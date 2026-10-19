"""Explicit chunk recovery preserves terminal history and downstream identity."""

import concurrent.futures
import json
import os
import subprocess
import sys

import psycopg
import pytest
from pydantic import ValidationError

from osint_workbench.contracts import DocumentInput
from osint_workbench.database import Database
from osint_workbench.errors import WorkbenchError
from osint_workbench.evidence import EvidenceStore
from osint_workbench.jobs import Jobs
from osint_workbench.worker import CHUNKER, AcceptedDocument, enqueue_chunk, run_once
from tests.test_lifecycle import change


def item(text="Synthetic chunk operation evidence."):
    return DocumentInput(source_id="fixture", external_id="chunk-item", title="Chunk", text=text)


@pytest.mark.parametrize("operation", [None, "", "../unsafe", "x" * 97, 1, True])
def test_chunk_request_validation_precedes_connection(monkeypatch, operation):
    def forbidden(*_):
        pytest.fail("invalid request opened a database connection")

    monkeypatch.setattr(Database, "connect", forbidden)
    with pytest.raises(ValidationError):
        enqueue_chunk(Database("unused"), "a" * 64, operation)


@pytest.mark.parametrize(
    "kind,key,payload",
    [(None, "k", {}), ("k", 4, {}), ("k", "", {}), ("k", "k", []), ("k", "k", {"n": float("nan")})],
)
def test_enqueue_validation_still_precedes_connection(monkeypatch, kind, key, payload):
    def forbidden(*_):
        pytest.fail("invalid enqueue opened a database connection")

    monkeypatch.setattr(Database, "connect", forbidden)
    with pytest.raises(WorkbenchError):
        Database("unused").enqueue_state(kind, key, payload)


@pytest.mark.parametrize(
    "extra",
    [
        {"operation_id": "repair"},
        {"chunker": CHUNKER},
        {"operation_id": "repair", "chunker": "characters/2"},
    ],
)
def test_explicit_payload_requires_supported_algorithm_pair(extra):
    with pytest.raises(ValidationError):
        AcceptedDocument(document_id="a" * 64, snapshot_id="b" * 64, **extra)


@pytest.mark.integration
@pytest.mark.parametrize("terminal", ["failed", "cancelled", "succeeded"])
def test_replay_preserves_terminal_and_new_operation_has_own_attempt(databases, tmp_path, terminal):
    writer, reader, _ = databases
    store = EvidenceStore(tmp_path / "objects")
    receipt = writer.ingest(item(), b"raw", store, describe=True)
    assert receipt["document_effect"] == "inserted"
    assert receipt["processing"]["enqueue_effect"] == "inserted"
    original = receipt["processing"]["job_id"]
    with writer.connect() as conn:
        conn.execute("UPDATE ow.jobs SET status=%s WHERE job_id=%s", (terminal, original))
    before = Jobs(writer).inspect(original)
    replay = writer.ingest(item(), b"raw", store, describe=True)
    assert replay["document_effect"] == "version_replayed"
    assert replay["processing"] == {
        "job_id": None,
        "job_status": None,
        "enqueue_effect": "not_enqueued",
        "requeued": False,
    }
    identifier = receipt["document_id"]
    operation = enqueue_chunk(writer, identifier, "repair-1")
    assert operation["job_id"] != original and not operation["requeued"]
    assert operation["job_status"] == "ready"
    assert enqueue_chunk(writer, identifier, "repair-1") == operation
    result = run_once(writer, store)
    assert result["status"] == "succeeded" and result["job_id"] == operation["job_id"]
    assert result["downstream_enqueue"]["job_status"] == "ready"
    assert enqueue_chunk(writer, identifier, "repair-1")["enqueue_effect"] == "terminal_preserved"
    assert run_once(writer, store)["status"] == "idle"
    assert Jobs(writer).inspect(original) == before
    with reader.connect() as conn:
        assert conn.execute("SELECT count(*) AS n FROM ow.visible_chunks").fetchone()["n"] == 1
    accepted = Jobs(writer).inspect(operation["job_id"])
    assert accepted["attempt"] == 1
    with writer.connect() as conn:
        stored = conn.execute(
            "SELECT result FROM ow.jobs WHERE job_id=%s", (operation["job_id"],)
        ).fetchone()
        assert stored["result"]["downstream_enqueue"] == result["downstream_enqueue"]


@pytest.mark.integration
def test_parallel_operation_identity_and_terminal_downstream_preserved(databases, tmp_path):
    writer, _, _ = databases
    store = EvidenceStore(tmp_path / "objects")
    identifier = writer.ingest(item(), b"raw", store)
    initial = run_once(writer, store)  # Historical two-field accepted payload still executes.
    downstream = initial["downstream_enqueue"]["job_id"]
    Jobs(writer).cancel(downstream)
    before = Jobs(writer).inspect(downstream)
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        receipts = list(pool.map(lambda _: enqueue_chunk(writer, identifier, "repair"), range(12)))
    assert len({r["job_id"] for r in receipts}) == 1
    result = run_once(writer, store)
    assert result["downstream_enqueue"] == {
        "job_id": downstream,
        "job_status": "cancelled",
        "enqueue_effect": "terminal_preserved",
        "requeued": False,
    }
    assert Jobs(writer).inspect(downstream) == before
    assert enqueue_chunk(writer, identifier, "repair-2")["job_id"] != result["job_id"]
    with writer.connect() as conn:
        assert conn.execute("SELECT count(*) AS n FROM ow.chunks").fetchone()["n"] == 1
        assert {r["kind"] for r in conn.execute("SELECT kind FROM ow.jobs")} == {
            "document.accepted",
            "document.chunked",
        }


@pytest.mark.integration
def test_historical_operation_does_not_rewind_head_and_retirement_denies(databases, tmp_path):
    writer, reader, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    old = writer.ingest(item("Previous evidence."), b"old", store)
    current = writer.ingest(item("Current evidence."), b"current", store)
    enqueue_chunk(writer, old, "repair-old")
    assert reader.search("Current")[0]["document_id"] == current
    change(Database(roles["lifecycle"]), old, "retire")
    with pytest.raises(WorkbenchError, match="DOCUMENT_RETIRED"):
        enqueue_chunk(writer, old, "retired-repair")
    with pytest.raises(WorkbenchError, match="DOCUMENT_RETIRED_OR_EXPIRED"):
        enqueue_chunk(writer, "f" * 64, "absent")


@pytest.mark.integration
def test_collector_receipts_do_not_require_downstream_access(databases, tmp_path):
    writer, _, roles = databases
    collector = Database(roles["collector"])
    collector.validate_collector()
    store = EvidenceStore(tmp_path / "objects")
    inserted = collector.ingest(item(), b"raw", store, describe=True)
    assert inserted["processing"]["job_status"] == "ready"
    Jobs(writer).cancel(inserted["processing"]["job_id"])
    replay = collector.ingest(item(), b"raw", store, describe=True)
    assert replay["processing"]["job_status"] is None
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        enqueue_chunk(collector, inserted["document_id"], "not-collector-authority")
    with collector.connect() as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("SELECT * FROM ow.jobs")
    collector.validate_collector()


@pytest.mark.integration
def test_installed_chunk_cli_requires_intent_and_reports_terminal_replay(databases, tmp_path):
    writer, _, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    identifier = writer.ingest(item(), b"raw", store)
    run_once(writer, store)
    command = [
        sys.executable,
        "-I",
        "-m",
        "osint_workbench.cli",
        "chunk",
        "enqueue",
        "--document-id",
        identifier,
    ]
    env = {
        **{k: v for k, v in os.environ.items() if not k.startswith("OW_")},
        "OW_WRITER_DSN": roles["writer"],
    }
    missing = subprocess.run(command, capture_output=True, text=True, timeout=15, env=env)
    assert missing.returncode == 2 and missing.stdout == ""
    command += ["--operation-id", "repair-cli"]
    first = subprocess.run(command, capture_output=True, text=True, timeout=15, env=env)
    assert first.returncode == 0 and first.stderr == ""
    receipt = json.loads(first.stdout)
    Jobs(writer).cancel(receipt["job_id"])
    second = subprocess.run(command, capture_output=True, text=True, timeout=15, env=env)
    assert second.returncode == 0 and second.stderr == ""
    assert json.loads(second.stdout) == {
        **receipt,
        "job_status": "cancelled",
        "enqueue_effect": "terminal_preserved",
    }


@pytest.mark.integration
@pytest.mark.parametrize("expired", [False, True])
def test_explicit_operation_rolls_back_chunks_outbox_and_success_on_final_refusal(
    databases, tmp_path, monkeypatch, expired
):
    writer, _, _ = databases
    store = EvidenceStore(tmp_path / "objects")
    identifier = writer.ingest(item(), b"raw", store)
    with writer.connect() as conn:
        original = conn.execute("SELECT job_id FROM ow.jobs").fetchone()["job_id"]
    Jobs(writer).cancel(original)
    operation = enqueue_chunk(writer, identifier, "repair-rollback")
    finish = Jobs.finish_locked

    def refuse(self, conn, row, result):
        if expired:
            conn.execute(
                "UPDATE ow.jobs SET lease_until=clock_timestamp()-interval '1 second' "
                "WHERE job_id=%s",
                (row["job_id"],),
            )
            return finish(self, conn, row, result)
        raise WorkbenchError("INJECTED_BEFORE_COMMIT")

    monkeypatch.setattr(Jobs, "finish_locked", refuse)
    result = run_once(writer, store)
    assert result["status"] == ("superseded" if expired else "failed")
    assert "downstream_enqueue" not in result
    with writer.connect() as conn:
        assert not conn.execute("SELECT 1 FROM ow.chunks").fetchone()
        assert not conn.execute("SELECT 1 FROM ow.jobs WHERE kind='document.chunked'").fetchone()
        row = conn.execute(
            "SELECT status,result FROM ow.jobs WHERE job_id=%s", (operation["job_id"],)
        ).fetchone()
        assert row["result"] is None and row["status"] != "succeeded"
        assert not conn.execute("SELECT 1 FROM ow.job_events WHERE event='succeeded'").fetchone()
