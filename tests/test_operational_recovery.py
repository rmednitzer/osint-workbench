"""Collected/chunked evidence survives isolated restore and fresh CLI processes.

HTTP framing uses an authored in-memory h11 peer; feed parsing, PostgreSQL,
CAS bytes, scoped worker CLI execution, policy reconciliation and the recovered
MCP subprocess remain real. This does not qualify an independent assistant client,
backup scheduling, host recovery or operational RPO/RTO.
"""

import asyncio
import json
import os
import stat
import subprocess
import sys

import pytest
from mcp import Client, StdioServerParameters

from osint_workbench import lifecycle
from osint_workbench.collection import collect
from osint_workbench.contracts import Source
from osint_workbench.database import Database
from osint_workbench.errors import WorkbenchError
from osint_workbench.evidence import EvidenceStore
from osint_workbench.jobs import Jobs
from osint_workbench.service import ReadService
from osint_workbench.text import digest
from tests.test_recovery import destination as destination
from tests.test_scheduled_collection import ResponseWire, install
from tests.test_workflows import FEED

pytestmark = pytest.mark.integration


def cli(arguments, *, role, dsn, root, error=None):
    # Each process receives only its selected role and fixture store, never
    # inherited encoder/provider configuration or another role's credentials.
    result = subprocess.run(
        [sys.executable, "-I", "-m", "osint_workbench.cli", *arguments],
        env={"PATH": os.defpath, role: dsn, "OW_EVIDENCE_ROOT": str(root)},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if error is not None:
        assert result.returncode == 1 and result.stdout == ""
        assert json.loads(result.stderr) == {"error": error}
        return None
    assert result.returncode == 0 and result.stderr == ""
    return json.loads(result.stdout)


def restore_arguments(checkpoint, policy_path, policy, minimum_revision):
    return [
        "restore",
        "--file",
        str(checkpoint["path"]),
        "--sha256",
        checkpoint["sha256"],
        "--policy-file",
        str(policy_path),
        "--policy-sha256",
        policy["sha256"],
        "--minimum-policy-revision",
        str(minimum_revision),
    ]


@pytest.fixture
def collected_checkpoint(databases, tmp_path, monkeypatch):
    writer, _, roles = databases
    store = EvidenceStore(tmp_path / "source-evidence")
    collector = Database(roles["collector"])
    collector.validate_collector()
    source = Source(source_id="operational-fixture", url="http://example.invalid/feed")
    wire = ResponseWire(body=FEED, headers=[(b"etag", b'"operational-v1"')])
    install(monkeypatch, wire)
    accepted = collect(source, collector, store, due_only=True)
    assert accepted["status"] == "success" and accepted["documents"] == 2
    completed = [
        cli(["work-once"], role="OW_CHUNK_DSN", dsn=roles["chunk"], root=store.root)
        for _ in range(2)
    ]
    assert all(result["status"] == "succeeded" and result["chunks"] == 1 for result in completed)
    assert cli(["work-once"], role="OW_CHUNK_DSN", dsn=roles["chunk"], root=store.root) == {
        "status": "idle"
    }
    with writer.connect() as conn:
        chunks = conn.execute(
            "SELECT chunk_id,document_id,start_offset,end_offset,text_sha256,body "
            "FROM ow.chunks ORDER BY chunk_id"
        ).fetchall()
        pending = conn.execute(
            "SELECT job_id FROM ow.jobs WHERE kind='document.chunked' ORDER BY job_id"
        ).fetchall()
        snapshots = {
            row["document_id"]: row["snapshot_id"]
            for row in conn.execute("SELECT document_id,snapshot_id FROM ow.documents").fetchall()
        }
    assert len(chunks) == len(pending) == 2
    policy_path = tmp_path / "checkpoint-policy.owpolicy"
    old_policy = cli(
        ["lifecycle", "export-policy", "--file", str(policy_path)],
        role="OW_LIFECYCLE_DSN",
        dsn=roles["lifecycle"],
        root=store.root,
    )
    path = tmp_path / "collected.owcp"
    checkpoint = cli(
        ["checkpoint", "--file", str(path)],
        role="OW_RECOVERY_DSN",
        dsn=roles["admin"],
        root=store.root,
    )
    checkpoint["path"] = path
    assert stat.S_IMODE(path.stat().st_mode) == stat.S_IMODE(policy_path.stat().st_mode) == 0o600

    # The independently exported current policy is newer than the checkpoint.
    retired = accepted["document_ids"][1]
    lifecycle.apply(
        Database(roles["lifecycle"]),
        lifecycle.Change(
            action="retire",
            document_id=retired,
            operation_id="operational-retirement",
            actor="fixture-operator",
            rationale="Synthetic decision after checkpoint",
        ),
    )
    current_path = tmp_path / "current-policy.owpolicy"
    current_policy = cli(
        ["lifecycle", "export-policy", "--file", str(current_path)],
        role="OW_LIFECYCLE_DSN",
        dsn=roles["lifecycle"],
        root=store.root,
    )
    assert current_policy["revision"] == old_policy["revision"] + 1
    return {
        "roles": roles,
        "accepted": accepted,
        "checkpoint": checkpoint,
        "old_policy": old_policy,
        "old_policy_path": policy_path,
        "policy": current_policy,
        "policy_path": current_path,
        "completed": completed,
        "pending": pending,
        "chunks": chunks,
        "retired": retired,
        "snapshots": snapshots,
    }


def test_collected_chunked_checkpoint_restores_current_policy_and_restart_state(
    collected_checkpoint, destination, tmp_path
):
    fixture = collected_checkpoint
    root = tmp_path / "restored-evidence"
    result = cli(
        restore_arguments(
            fixture["checkpoint"],
            fixture["policy_path"],
            fixture["policy"],
            fixture["policy"]["revision"],
        ),
        role="OW_RECOVERY_DSN",
        dsn=destination["admin"],
        root=root,
    )
    assert result["status"] == "restored_requires_operator_reconciliation"
    assert result["policy_sha256"] == fixture["policy"]["sha256"]
    assert result["policy_revision"] == fixture["policy"]["revision"]
    assert result["quarantined_jobs"] == len(fixture["pending"])
    assert result["sources_enabled"] is False
    assert EvidenceStore(root, read_only=True).get(digest(FEED)) == FEED

    # New CLI processes cannot depend on the collector/worker's in-memory state.
    status = cli(["status"], role="OW_READER_DSN", dsn=destination["reader"], root=root)
    assert status["documents"] == status["chunks"] == status["failed_jobs"] == 2
    assert status["ready_jobs"] == status["running_jobs"] == 0
    assert status["lifecycle"]["visible_documents"] == status["lifecycle"]["retired_items"] == 1
    found = cli(["search", "evidence"], role="OW_READER_DSN", dsn=destination["reader"], root=root)
    assert [row["document_id"] for row in found["results"]] == [
        fixture["accepted"]["document_ids"][0]
    ]
    reader = Database(destination["reader"])
    service = ReadService(reader, EvidenceStore(root, read_only=True))
    assert service.document(found["results"][0]["document_id"])["text"] == "First evidence"
    assert service.document(found["results"][0]["document_id"])["integrity"] == "verified"
    with pytest.raises(WorkbenchError, match="^DOCUMENT_NOT_FOUND$"):
        service.document(fixture["retired"])
    assert reader.sources()[0]["enabled"] is False

    async def mcp_roundtrip():
        # Launch the actual installed CLI from outside the checkout with only
        # reader authority, no fixture Service or inherited OW_* configuration.
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-I", "-m", "osint_workbench.cli", "mcp"],
            cwd=tmp_path,
            env={
                "PATH": os.defpath,
                "OW_READER_DSN": destination["reader"],
                "OW_EVIDENCE_ROOT": str(root),
            },
        )
        async with (
            asyncio.timeout(30),
            Client(parameters, mode="2026-07-28", read_timeout_seconds=10) as client,
        ):
            assert len((await client.list_tools()).tools) == 7

            async def call(tool, arguments, *, error=None):
                result = await client.call_tool(tool, arguments)
                assert len(result.content) == 1 and result.content[0].type == "text"
                value = json.loads(result.content[0].text)
                assert result.is_error is (error is not None)
                if error is not None:
                    assert value == {"error": error}
                return value

            visible = fixture["accepted"]["document_ids"][0]
            found = await call("search_documents", {"query": "evidence"})
            assert [row["document_id"] for row in found["results"]] == [visible]
            document = await call("get_document", {"document_id": visible})
            assert document["text"] == "First evidence" and document["integrity"] == "verified"
            snapshot = fixture["snapshots"][visible]
            evidence = await call("get_evidence", {"snapshot_id": snapshot})
            assert evidence["integrity"] == "verified" and evidence["raw_sha256"] == digest(FEED)
            await call(
                "get_document", {"document_id": fixture["retired"]}, error="DOCUMENT_NOT_FOUND"
            )
            await call(
                "get_evidence",
                {"snapshot_id": fixture["snapshots"][fixture["retired"]]},
                error="SNAPSHOT_NOT_FOUND",
            )
            sources = await call("list_sources", {})
            assert len(sources["results"]) == 1 and sources["results"][0]["enabled"] is False

            # Corrupt only the disposable restored CAS. The MCP error must not
            # turn bad bytes into evidence or disclose the injected contents.
            raw_sha = evidence["raw_sha256"]
            raw_path = root / raw_sha[:2] / raw_sha
            original = raw_path.read_bytes()
            try:
                raw_path.write_bytes(b"synthetic-corruption-canary")
                await call(
                    "get_evidence", {"snapshot_id": snapshot}, error="EVIDENCE_INTEGRITY_MISMATCH"
                )
            finally:
                raw_path.write_bytes(original)
            assert (await call("get_evidence", {"snapshot_id": snapshot}))[
                "integrity"
            ] == "verified"
            # A refused read does not destroy the session or rewrite job state.
            status = await call("pipeline_status", {})
            assert status["failed_jobs"] == 2 and status["ready_jobs"] == 0

    asyncio.run(mcp_roundtrip())

    for completed in fixture["completed"]:
        job = cli(
            ["job", "inspect", completed["job_id"]],
            role="OW_WRITER_DSN",
            dsn=destination["writer"],
            root=root,
        )
        assert job["status"] == "succeeded" and job["events"][-1]["event"] == "succeeded"
    for pending in fixture["pending"]:
        job = Jobs(Database(destination["writer"])).inspect(pending["job_id"])
        assert job["status"] == "failed"
        assert job["events"][-1]["code"] == "RECOVERY_RECONCILIATION_REQUIRED"
    assert cli(["work-once"], role="OW_CHUNK_DSN", dsn=destination["chunk"], root=root) == {
        "status": "idle"
    }
    with Database(destination["writer"]).connect() as conn:
        assert (
            conn.execute(
                "SELECT chunk_id,document_id,start_offset,end_offset,text_sha256,body "
                "FROM ow.chunks ORDER BY chunk_id"
            ).fetchall()
            == fixture["chunks"]
        )


@pytest.mark.parametrize("fault", ["checkpoint-digest", "policy-digest", "policy-rollback"])
def test_recovery_input_denial_precedes_empty_target_or_cas_mutation(
    collected_checkpoint, destination, tmp_path, fault
):
    fixture = collected_checkpoint
    checkpoint = dict(fixture["checkpoint"])
    policy = dict(fixture["policy"])
    policy_path = fixture["policy_path"]
    if fault == "checkpoint-digest":
        checkpoint["sha256"] = "0" * 64
    elif fault == "policy-digest":
        policy["sha256"] = "0" * 64
    else:
        policy, policy_path = fixture["old_policy"], fixture["old_policy_path"]
    root = tmp_path / "must-remain-absent"
    cli(
        restore_arguments(checkpoint, policy_path, policy, fixture["policy"]["revision"]),
        role="OW_RECOVERY_DSN",
        dsn=destination["admin"],
        root=root,
        error="LIFECYCLE_POLICY_STALE_OR_WRONG_DATASET"
        if fault == "policy-rollback"
        else "RECOVERY_DIGEST_MISMATCH",
    )
    assert not root.exists()
    with Database(destination["admin"]).connect() as conn:
        assert conn.execute(
            "SELECT (SELECT count(*) FROM ow.sources) AS sources, "
            "(SELECT count(*) FROM ow.documents) AS documents, "
            "(SELECT count(*) FROM ow.chunks) AS chunks, "
            "(SELECT count(*) FROM ow.jobs) AS jobs, "
            "(SELECT revision FROM ow.lifecycle_control) AS revision"
        ).fetchone() == {"sources": 0, "documents": 0, "chunks": 0, "jobs": 0, "revision": 0}
