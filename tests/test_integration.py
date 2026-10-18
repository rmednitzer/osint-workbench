import asyncio
import json
import os
import sys
import uuid

import psycopg
import pytest
from mcp import Client, StdioServerParameters

from osint_workbench.contracts import DocumentInput
from osint_workbench.database import migrate
from osint_workbench.errors import WorkbenchError
from osint_workbench.evidence import EvidenceStore
from osint_workbench.intelligence import create_briefing
from osint_workbench.service import ReadService

pytestmark = pytest.mark.integration


def document(text="Persistent evidence for storage systems."):
    return DocumentInput(source_id="fixture", external_id="fixture-1", title="Storage", text=text)


def test_replay_versions_heads_outbox_and_reader(databases, tmp_path):
    writer, reader, _ = databases
    store = EvidenceStore(tmp_path / "objects")
    one = writer.ingest(document(), b"raw first", store)
    assert writer.ingest(document(), b"raw first", store) == one
    two = writer.ingest(document("Changed semantic content."), b"raw second", store)
    assert one != two
    writer.ingest(document(), b"raw first", store)  # replay must not rewind the head
    assert reader.search("Persistent") == []
    assert reader.search("Changed")[0]["document_id"] == two
    assert reader.document(one)["text"].startswith("Persistent")
    assert reader.status()["ready_jobs"] == 2
    with reader.connect() as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("DELETE FROM ow.documents")
    reader.validate_reader()


def test_real_reader_rejects_admin(databases):
    _, reader, roles = databases
    from osint_workbench.database import Database

    with pytest.raises(WorkbenchError, match="UNSAFE_READER"):
        Database(roles["admin"]).validate_reader()
    reader.validate_reader()


def test_integrity_and_rollback(databases, tmp_path):
    writer, reader, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    doc_id = writer.ingest(document(), b"raw first", store)
    service = ReadService(reader, EvidenceStore(store.root, read_only=True))
    row = service.document(doc_id)
    assert row["integrity"] == "verified" and "full_body" not in row
    snap = reader.snapshot(row["snapshot_id"])
    (store.root / snap["text_sha256"][:2] / snap["text_sha256"]).write_bytes(b"tampered")
    with pytest.raises(WorkbenchError, match="INTEGRITY"):
        service.document(doc_id)
    migrate(roles["admin"])  # exact packaged migration is idempotent


def test_job_lease_and_fencing(databases):
    writer, _, roles = databases
    job = writer.enqueue("fixture", "one", {"value": 1})
    assert writer.enqueue("fixture", "one", {"value": 2}) == job
    first = writer.claim()
    assert first["payload"] == {"value": 1}
    with pytest.raises(WorkbenchError, match="STALE"):
        writer.finish(job, str(uuid.uuid4()), {})
    with psycopg.connect(roles["admin"]) as conn:
        conn.execute("UPDATE ow.jobs SET lease_until=clock_timestamp()-interval '1 second'")
    second = writer.claim()
    assert first["fence"] != second["fence"] and second["attempt"] == 2
    with pytest.raises(WorkbenchError, match="STALE"):
        writer.finish(job, str(first["fence"]), {})
    writer.finish(job, str(second["fence"]), {"accepted": True})
    assert writer.claim() is None


def test_failure_does_not_commit_missing_metadata(databases, tmp_path, monkeypatch):
    writer, reader, _ = databases
    store = EvidenceStore(tmp_path / "objects")
    original = store.put
    calls = 0

    def failed(data):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise WorkbenchError("INJECTED_STORE_FAILURE")
        return original(data)

    monkeypatch.setattr(store, "put", failed)
    with pytest.raises(WorkbenchError):
        writer.ingest(document(), b"raw first", store)
    assert reader.status()["documents"] == 0


@pytest.mark.parametrize("mode", ["2026-07-28", "legacy"], ids=["modern", "legacy"])
def test_mcp_real_client_roundtrip(databases, tmp_path, mode):
    writer, _, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    doc_id = writer.ingest(document(), b"raw first", store)
    briefing_id = create_briefing(writer, [doc_id])["briefing_id"]

    async def run():
        env = {**os.environ, "OW_READER_DSN": roles["reader"], "OW_EVIDENCE_ROOT": str(store.root)}
        params = StdioServerParameters(
            command=sys.executable, args=["-m", "osint_workbench.cli", "mcp"], env=env
        )
        async with Client(params, mode=mode, read_timeout_seconds=10) as session:
            assert session.protocol_version == ("2026-07-28" if mode != "legacy" else "2025-11-25")
            tools = await session.list_tools()
            assert {t.name for t in tools.tools} == {
                "search_documents",
                "get_document",
                "get_evidence",
                "list_sources",
                "pipeline_status",
                "list_assertions",
                "get_briefing",
            }
            found = await session.call_tool("search_documents", {"query": "storage"})
            assert (
                not found.is_error
                and json.loads(found.content[0].text)["results"][0]["document_id"] == doc_id
            )
            doc = await session.call_tool("get_document", {"document_id": doc_id})
            snap = json.loads(doc.content[0].text)["snapshot_id"]
            evidence = await session.call_tool("get_evidence", {"snapshot_id": snap})
            assert json.loads(evidence.content[0].text)["integrity"] == "verified"
            invalid = await session.call_tool(
                "search_documents", {"query": "storage", "shell": "forbidden"}
            )
            assert invalid.is_error and "INVALID_ARGUMENTS" in invalid.content[0].text
            invalid = await session.call_tool("get_document", {"document_id": "../private"})
            assert invalid.is_error
            for name, arguments in [
                ("list_sources", {}),
                ("pipeline_status", {}),
                ("list_assertions", {"document_id": doc_id}),
                ("get_briefing", {"briefing_id": briefing_id}),
            ]:
                result = await session.call_tool(name, arguments)
                assert not result.is_error
            unknown = await session.call_tool("shell", {"command": "forbidden"})
            assert unknown.is_error and json.loads(unknown.content[0].text) == {
                "error": "UNKNOWN_TOOL"
            }

    asyncio.run(run())
