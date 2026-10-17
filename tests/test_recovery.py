import asyncio
import base64
import json
import os
import stat
import subprocess
import sys
import uuid
from contextlib import contextmanager

import psycopg
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from psycopg import sql
from psycopg.conninfo import make_conninfo

from osint_workbench import intelligence, lifecycle, recovery
from osint_workbench.contracts import DocumentInput
from osint_workbench.database import Database, migrate
from osint_workbench.errors import WorkbenchError
from osint_workbench.evidence import EvidenceStore
from osint_workbench.jobs import Jobs
from osint_workbench.service import ReadService
from osint_workbench.text import digest
from osint_workbench.vector_index import VectorIndex, migrate_retrieval
from osint_workbench.worker import run_once


@contextmanager
def isolated(roles, *, retrieval):
    name = "ow_test_restore_" + uuid.uuid4().hex
    with psycopg.connect(roles["admin"], autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    target = {key: make_conninfo(dsn, dbname=name) for key, dsn in roles.items()}
    try:
        migrate(target["admin"])
        if retrieval:
            migrate_retrieval(target["admin"])
        yield target
    finally:
        with psycopg.connect(roles["admin"], autocommit=True) as conn:
            conn.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(name)))


@pytest.fixture
def destination(roles):
    with isolated(roles, retrieval=os.environ.get("OW_TEST_RETRIEVAL") == "1") as target:
        yield target


def policy_arguments(roles, path):
    policy_path = path.with_suffix(".owpolicy")
    receipt = lifecycle.export_policy(Database(roles["admin"]), policy_path)
    return {
        "policy_path": policy_path,
        "policy_sha": receipt["sha256"],
        "minimum_revision": receipt["revision"],
    }


def _input(text="Straße storage is unavailable.", external="one"):
    return DocumentInput(source_id="fixture", external_id=external, title="Synthetic", text=text)


class Generator:
    class Manifest:
        timeout_seconds = 2

        def identity(self):
            return "a" * 64

    manifest = Manifest()

    def generate(self, prompt, schema):
        return {
            "output": {
                "claims": [
                    {
                        "subject": "storage",
                        "predicate": "affects",
                        "object": "availability",
                        "statement": "The source reports an outage.",
                        "polarity": "asserted",
                        "quote": "Straße storage is unavailable.",
                    }
                ]
            },
            "prompt_sha256": digest(prompt.encode()),
            "response_sha256": "b" * 64,
        }


def _fixture(writer, store):
    doc = writer.ingest(_input(), b"synthetic raw feed", store)
    run_once(writer, store)
    generator = Generator()
    intelligence.enqueue(writer, generator, doc)
    intelligence.enrich_once(writer, store, generator)
    assertion = intelligence.assertions(writer)["results"][0]["assertion_id"]
    intelligence.review(writer, assertion, "accept", "fixture-reviewer", "Synthetic review")
    brief = intelligence.create_briefing(writer, [doc])["briefing_id"]
    pending = writer.enqueue("fixture", "pending", {})
    leased = writer.enqueue("fixture-running", "leased", {})
    claim = Jobs(writer).claim(kinds=["fixture-running"])
    return doc, assertion, brief, pending, leased, claim["fence"]


@pytest.mark.integration
def test_checkpoint_fresh_restore_citations_history_and_real_mcp(databases, destination, tmp_path):
    writer, _, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    doc, assertion, brief, pending, leased, old_fence = _fixture(writer, store)
    orphan = store.put(b"unreferenced private fixture must not be bundled")
    path = tmp_path / "checkpoint.owcp"
    receipt = recovery.checkpoint(Database(roles["admin"]), store, path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert orphan not in json.loads(path.read_bytes())["payload"]["objects"]
    target_store = tmp_path / "restored"
    policy_args = policy_arguments(roles, path)
    result = recovery.restore(
        Database(destination["admin"]), path, receipt["sha256"], target_store, **policy_args
    )
    assert result["status"] == "restored_requires_operator_reconciliation"
    restored_writer, reader = Database(destination["writer"]), Database(destination["reader"])
    service = ReadService(reader, EvidenceStore(target_store, read_only=True))
    assert service.document(doc)["integrity"] == "verified"
    assert service.briefing(brief)["items"][0]["assertion_id"] == assertion
    assert service.search("storage")["results"][0]["document_id"] == doc
    assert reader.sources()[0]["enabled"] is False
    for job in (pending, leased):
        inspected = Jobs(restored_writer).inspect(job)
        assert inspected["status"] == "failed"
        assert inspected["events"][-1]["code"] == "RECOVERY_RECONCILIATION_REQUIRED"
    with pytest.raises(WorkbenchError, match="STALE_JOB_LEASE"):
        Jobs(restored_writer).finish(leased, old_fence, {})
    # Restored identity sequences must advance beyond preserved review/event IDs.
    intelligence.review(restored_writer, assertion, "reject", "fixture-reviewer", "Withdrawal")
    with pytest.raises(WorkbenchError, match="BRIEFING_STALE"):
        service.briefing(brief)

    async def roundtrip():
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "osint_workbench.cli", "mcp"],
            env={
                **os.environ,
                "OW_READER_DSN": destination["reader"],
                "OW_EVIDENCE_ROOT": str(target_store),
            },
        )
        async with stdio_client(params) as (read, write), ClientSession(read, write) as client:
            await client.initialize()
            result = await client.call_tool("get_document", {"document_id": doc})
            assert (
                not result.isError and json.loads(result.content[0].text)["integrity"] == "verified"
            )
            found = await client.call_tool("search_documents", {"query": "storage"})
            assert json.loads(found.content[0].text)["results"][0]["document_id"] == doc

    asyncio.run(roundtrip())
    with pytest.raises(WorkbenchError, match="TARGET_NOT_EMPTY"):
        recovery.restore(
            Database(destination["admin"]),
            path,
            receipt["sha256"],
            tmp_path / "other",
            **policy_args,
        )
    assert not (tmp_path / "other").exists()


@pytest.mark.integration
def test_checkpoint_excludes_concurrent_acceptance(databases, destination, tmp_path, monkeypatch):
    writer, _, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    first = writer.ingest(_input(), b"first", store)
    original = store.get
    later = None

    def concurrent(sha):
        nonlocal later
        if later is None:
            later = writer.ingest(_input("Later accepted content.", "two"), b"later", store)
        return original(sha)

    monkeypatch.setattr(store, "get", concurrent)
    path = tmp_path / "snapshot.owcp"
    receipt = recovery.checkpoint(Database(roles["admin"]), store, path)
    policy_args = policy_arguments(roles, path)
    recovery.restore(
        Database(destination["admin"]),
        path,
        receipt["sha256"],
        tmp_path / "restored",
        **policy_args,
    )
    reader = Database(destination["reader"])
    assert reader.document(first)["document_id"] == first
    assert reader.search("Later") == []
    assert writer.document(later)["document_id"] == later


def _rewrite(path, change):
    bundle = json.loads(path.read_bytes())
    change(bundle["payload"])
    sha = digest(recovery._json(bundle["payload"]))
    bundle["sha256"] = sha
    path.write_bytes(recovery._json(bundle))
    return sha


@pytest.mark.integration
@pytest.mark.parametrize(
    "failure", ["digest", "object", "foreign-key", "schema", "columns", "version", "fsync"]
)
def test_restore_rejects_corruption_and_rolls_back(
    databases, destination, tmp_path, failure, monkeypatch
):
    writer, _, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    writer.ingest(_input(), b"raw", store)
    path = tmp_path / "checkpoint.owcp"
    sha = recovery.checkpoint(Database(roles["admin"]), store, path)["sha256"]
    policy_args = policy_arguments(roles, path)
    if failure == "digest":
        sha = "0" * 64
    elif failure == "object":
        sha = _rewrite(
            path,
            lambda p: p["objects"].update(
                {next(iter(p["objects"])): base64.b64encode(b"corrupted").decode()}
            ),
        )
    elif failure == "foreign-key":
        sha = _rewrite(
            path, lambda p: p["tables"]["document_heads"][0].update(document_id="0" * 64)
        )
    elif failure == "schema":
        sha = _rewrite(path, lambda p: p["migrations"].update({"999": "0" * 64}))
    elif failure == "version":
        sha = _rewrite(path, lambda p: p["database"].update(postgres_major=999))
    elif failure == "fsync":

        def unavailable(_fd):
            raise OSError("synthetic durability failure")

        monkeypatch.setattr(recovery.os, "fsync", unavailable)
    else:
        sha = _rewrite(path, lambda p: p["tables"]["sources"][0].update(unknown="rejected"))
    with pytest.raises((WorkbenchError, psycopg.IntegrityError, OSError)):
        recovery.restore(
            Database(destination["admin"]), path, sha, tmp_path / "restored", **policy_args
        )
    with Database(destination["admin"]).connect() as conn:
        assert conn.execute("SELECT count(*) AS n FROM ow.documents").fetchone()["n"] == 0
        assert conn.execute("SELECT count(*) AS n FROM ow.sources").fetchone()["n"] == 0


@pytest.mark.integration
def test_native_vector_generation_survives_restore(
    databases, destination, tmp_path, encoder_bundle
):
    if os.environ.get("OW_TEST_RETRIEVAL") != "1":
        pytest.skip("native optional retrieval profile unavailable")
    writer, _, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    doc = writer.ingest(_input("storage disk"), b"raw storage", store)
    index = VectorIndex(writer, encoder_bundle)
    generation = index.build(store)["generation_id"]
    index.activate(generation)
    path = tmp_path / "checkpoint.owcp"
    sha = recovery.checkpoint(Database(roles["admin"]), store, path)["sha256"]
    policy_args = policy_arguments(roles, path)
    recovery.restore(
        Database(destination["admin"]), path, sha, tmp_path / "restored", **policy_args
    )
    service = ReadService(
        Database(destination["reader"]),
        EvidenceStore(tmp_path / "restored", read_only=True),
        encoder=encoder_bundle,
    )
    found = service.search("storage")
    assert found["results"][0]["document_id"] == doc
    assert found["generation_id"] == generation


@pytest.mark.integration
def test_core_only_cli_checkpoint_and_restore(roles, tmp_path):
    with isolated(roles, retrieval=False) as source, isolated(roles, retrieval=False) as target:
        store = EvidenceStore(tmp_path / "objects")
        doc = Database(source["writer"]).ingest(_input(), b"raw", store)
        path = tmp_path / "core.owcp"
        result = subprocess.run(
            [sys.executable, "-m", "osint_workbench.cli", "checkpoint", "--file", str(path)],
            env={
                **os.environ,
                "OW_RECOVERY_DSN": source["admin"],
                "OW_EVIDENCE_ROOT": str(store.root),
            },
            check=True,
            capture_output=True,
            timeout=30,
        )
        receipt = json.loads(result.stdout)
        policy_args = policy_arguments(source, path)
        restored = subprocess.run(
            [
                sys.executable,
                "-m",
                "osint_workbench.cli",
                "restore",
                "--file",
                str(path),
                "--sha256",
                receipt["sha256"],
                "--policy-file",
                str(policy_args["policy_path"]),
                "--policy-sha256",
                policy_args["policy_sha"],
                "--minimum-policy-revision",
                str(policy_args["minimum_revision"]),
            ],
            env={
                **os.environ,
                "OW_RECOVERY_DSN": target["admin"],
                "OW_EVIDENCE_ROOT": str(tmp_path / "restored"),
            },
            check=True,
            capture_output=True,
            timeout=30,
        )
        assert json.loads(restored.stdout)["quarantined_jobs"] == 1
        assert Database(target["reader"]).search("storage")[0]["document_id"] == doc


@pytest.mark.integration
def test_checkpoint_limits_missing_evidence_and_unknown_tables(databases, tmp_path, monkeypatch):
    writer, _, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    writer.ingest(_input(), b"raw", store)
    path = tmp_path / "checkpoint.owcp"
    monkeypatch.setattr(recovery, "MAX_ROWS", 0)
    with pytest.raises(WorkbenchError, match="LIMIT_EXCEEDED"):
        recovery.checkpoint(Database(roles["admin"]), store, path)
    monkeypatch.undo()
    assert not path.exists()
    with Database(roles["admin"]).connect() as conn:
        conn.execute("CREATE TABLE ow.unclassified_fixture(value text)")
    try:
        with pytest.raises(WorkbenchError, match="SCHEMA_MISMATCH"):
            recovery.checkpoint(Database(roles["admin"]), store, path)
    finally:
        with Database(roles["admin"]).connect() as conn:
            conn.execute("DROP TABLE ow.unclassified_fixture")
    sha = digest(b"raw")
    (store.root / sha[:2] / sha).unlink()
    with pytest.raises(WorkbenchError, match="EVIDENCE_UNAVAILABLE"):
        recovery.checkpoint(Database(roles["admin"]), store, path)
    assert not path.exists()


def test_checkpoint_file_publication_is_atomic_private_and_no_overwrite(tmp_path):
    path = tmp_path / "checkpoint.owcp"
    recovery._write_new(path, b"first")
    with pytest.raises(FileExistsError):
        recovery._write_new(path, b"second")
    assert path.read_bytes() == b"first"
    assert not list(tmp_path.glob(".checkpoint-*"))
    path.unlink()
    target = tmp_path / "unrelated"
    target.write_bytes(b"do not overwrite")
    path.symlink_to(target)
    with pytest.raises(FileExistsError):
        recovery._write_new(path, b"replacement")
    assert target.read_bytes() == b"do not overwrite"
    with pytest.raises(OSError):
        recovery._read(path, "0" * 64)


def test_non_regular_objects_and_oversize_bundles_fail_without_blocking(tmp_path, monkeypatch):
    store = EvidenceStore(tmp_path / "objects")
    sha = store.put(b"fixture")
    path = store.root / sha[:2] / sha
    path.unlink()
    os.mkfifo(path, 0o600)
    with pytest.raises(WorkbenchError, match="INVALID_EVIDENCE_OBJECT"):
        store.get(sha)
    with pytest.raises(WorkbenchError, match="INVALID_RECOVERY_BUNDLE"):
        recovery._read(path, "0" * 64)
    large = tmp_path / "large.owcp"
    large.write_bytes(b"oversize")
    monkeypatch.setattr(recovery, "MAX_BUNDLE", 1)
    with pytest.raises(WorkbenchError, match="INVALID_RECOVERY_BUNDLE"):
        recovery._read(large, "0" * 64)
