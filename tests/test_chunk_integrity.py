"""Retained immutable rows must match deterministic accepted chunk output."""

import concurrent.futures
import hashlib
import json
import threading

import pytest

from osint_workbench.evidence import EvidenceStore
from osint_workbench.jobs import Jobs
from osint_workbench.text import chunks
from osint_workbench.worker import CHUNKER, enqueue_chunk, run_once
from tests.test_chunk_operations import item

pytestmark = pytest.mark.integration


def expected_rows(document_id, text):
    return [
        {
            "chunk_id": hashlib.sha256(
                json.dumps([document_id, CHUNKER, ordinal, part["sha256"]]).encode()
            ).hexdigest(),
            "document_id": document_id,
            "chunker": CHUNKER,
            "ordinal": ordinal,
            "start_offset": part["start"],
            "end_offset": part["end"],
            "text_sha256": part["sha256"],
            "body": part["text"],
        }
        for ordinal, part in enumerate(chunks(text))
    ]


def insert(writer, row):
    # Ordinary writer INSERT authority, not an administrator-only corruption path.
    with writer.connect() as conn:
        conn.execute(
            """INSERT INTO ow.chunks(chunk_id,document_id,chunker,ordinal,
            start_offset,end_offset,text_sha256,body) VALUES
            (%(chunk_id)s,%(document_id)s,%(chunker)s,%(ordinal)s,
             %(start_offset)s,%(end_offset)s,%(text_sha256)s,%(body)s)""",
            row,
        )


def rows(writer):
    with writer.connect() as conn:
        return conn.execute(
            "SELECT * FROM ow.chunks ORDER BY document_id,chunker,ordinal"
        ).fetchall()


@pytest.mark.parametrize(
    "fault", ["body", "digest", "coordinates", "identity", "extra", "cross-document-id"]
)
def test_conflicting_set_refuses_completion_and_rolls_back_new_rows(databases, tmp_path, fault):
    writer, _, _ = databases
    store = EvidenceStore(tmp_path / "objects")
    text = "Original evidence. " * 250  # More than one chunk: partial inserts must roll back.
    ingested = writer.ingest(item(text), b"raw", store, describe=True)
    document_id = ingested["document_id"]
    expected = expected_rows(document_id, text)
    conflicting = dict(expected[0])
    if fault == "body":
        conflicting["body"] = "x" * len(conflicting["body"])
    elif fault == "digest":
        conflicting["text_sha256"] = "0" * 64
    elif fault == "coordinates":
        conflicting["start_offset"] += 1
        conflicting["end_offset"] += 1
    elif fault == "identity":
        conflicting["chunk_id"] = "0" * 64
    elif fault == "extra":
        conflicting.update(
            chunk_id="0" * 64,
            ordinal=99999,
            start_offset=0,
            end_offset=100000,
            body="private-canary" + "x" * (100000 - len("private-canary")),
        )
    else:
        other = writer.ingest(item("Other version."), b"other raw", store, describe=True)
        Jobs(writer).cancel(other["processing"]["job_id"])
        conflicting["document_id"] = other["document_id"]
    insert(writer, conflicting)
    before = rows(writer)
    previous = None
    if fault == "extra":
        downstream = writer.enqueue(
            "document.chunked", document_id + ":" + CHUNKER, {"previous": "retained"}
        )
        Jobs(writer).cancel(downstream)
        previous = Jobs(writer).inspect(downstream)
    result = run_once(writer, store)
    assert result == {
        "status": "failed",
        "job_id": ingested["processing"]["job_id"],
        "error": "CHUNK_INTEGRITY_MISMATCH",
    }
    assert rows(writer) == before
    with writer.connect() as conn:
        job = conn.execute(
            "SELECT status,result,last_error FROM ow.jobs WHERE job_id=%s", (result["job_id"],)
        ).fetchone()
        assert job == {"status": "failed", "result": None, "last_error": "CHUNK_INTEGRITY_MISMATCH"}
        assert not conn.execute(
            "SELECT 1 FROM ow.job_events WHERE job_id=%s AND event='succeeded'", (result["job_id"],)
        ).fetchone()
        downstream_rows = conn.execute(
            "SELECT job_id FROM ow.jobs WHERE kind='document.chunked'"
        ).fetchall()
        assert len(downstream_rows) == (1 if previous else 0)
    if previous:
        assert Jobs(writer).inspect(previous["job_id"]) == previous


def test_partial_compatible_set_completes_and_replay_preserves_other_chunkers(databases, tmp_path):
    writer, _, _ = databases
    store = EvidenceStore(tmp_path / "objects")
    text = "Compatible evidence. " * 250
    document_id = writer.ingest(item(text), b"raw", store)
    expected = expected_rows(document_id, text)
    insert(writer, expected[0])
    other = dict(expected[0], chunk_id="f" * 64, chunker="retained-other/1")
    insert(writer, other)
    assert run_once(writer, store)["status"] == "succeeded"
    assert rows(writer) == sorted(
        expected + [other], key=lambda r: (r["document_id"], r["chunker"], r["ordinal"])
    )
    before = rows(writer)
    enqueue_chunk(writer, document_id, "retry-compatible")
    assert run_once(writer, store)["status"] == "succeeded"
    assert rows(writer) == before


def test_concurrent_distinct_valid_operations_accept_identical_set(
    databases, tmp_path, monkeypatch
):
    writer, _, _ = databases
    store = EvidenceStore(tmp_path / "objects")
    text = "Concurrent evidence. " * 250
    ingested = writer.ingest(item(text), b"raw", store, describe=True)
    document_id = ingested["document_id"]
    Jobs(writer).cancel(ingested["processing"]["job_id"])
    operations = [enqueue_chunk(writer, document_id, name) for name in ("first", "second")]
    original = Jobs.locked
    rendezvous = threading.Barrier(2)

    def locked(conn, job_id, fence):
        row = original(conn, job_id, fence)
        # Distinct job locks acquired before either transaction inserts chunks.
        rendezvous.wait(timeout=10)
        return row

    monkeypatch.setattr(Jobs, "locked", staticmethod(locked))
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(run_once, writer, store) for _ in range(2)]
        results = [future.result(timeout=20) for future in futures]
    assert {r["job_id"] for r in results} == {r["job_id"] for r in operations}
    assert all(r["status"] == "succeeded" for r in results)
    assert rows(writer) == expected_rows(document_id, text)
    assert len({r["downstream_enqueue"]["job_id"] for r in results}) == 1


@pytest.mark.parametrize(
    "fault", ["document", "chunker", "count", "boolean", "float", "extra-field"]
)
def test_downstream_dedup_conflict_refuses_success_without_rewriting_history(
    databases, tmp_path, fault
):
    writer, _, _ = databases
    store = EvidenceStore(tmp_path / "objects")
    ingested = writer.ingest(item(), b"raw", store, describe=True)
    document_id = ingested["document_id"]
    payload = {"document_id": document_id, "chunker": CHUNKER, "chunks": 1}
    if fault == "document":
        other = writer.ingest(item("Other version."), b"other", store, describe=True)
        Jobs(writer).cancel(other["processing"]["job_id"])
        payload["document_id"] = other["document_id"]
    elif fault == "chunker":
        payload["chunker"] = "retained-other/1"
    elif fault == "extra-field":
        payload["unexpected"] = "private-canary"
    else:
        payload["chunks"] = {"count": 2, "boolean": True, "float": 1.0}[fault]
    downstream = writer.enqueue("document.chunked", document_id + ":" + CHUNKER, payload)
    Jobs(writer).cancel(downstream)
    before = Jobs(writer).inspect(downstream)
    result = run_once(writer, store)
    assert result == {
        "status": "failed",
        "job_id": ingested["processing"]["job_id"],
        "error": "CHUNK_DOWNSTREAM_MISMATCH",
    }
    assert rows(writer) == []
    assert Jobs(writer).inspect(downstream) == before
    with writer.connect() as conn:
        stored = conn.execute(
            "SELECT payload FROM ow.jobs WHERE job_id=%s", (downstream,)
        ).fetchone()["payload"]
        assert json.dumps(stored, sort_keys=True) == json.dumps(payload, sort_keys=True)
        assert not conn.execute("SELECT 1 FROM ow.job_events WHERE event='succeeded'").fetchone()
