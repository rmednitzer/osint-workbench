import asyncio
import json
import os
import sys

import psycopg
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from osint_workbench.contracts import DocumentInput
from osint_workbench.database import Database
from osint_workbench.errors import WorkbenchError
from osint_workbench.evidence import EvidenceStore
from osint_workbench.local_encoder import LocalEncoder
from osint_workbench.service import ReadService
from osint_workbench.vector_index import VectorIndex, migrate_retrieval

pytestmark = pytest.mark.integration


@pytest.fixture
def retrieval(databases, encoder_bundle, tmp_path):
    if os.environ.get("OW_TEST_RETRIEVAL") != "1":
        pytest.skip("pgvector profile unavailable; not verified")
    writer, reader, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    for external, text in [("one", "storage disk"), ("two", "vulnerability patch")]:
        writer.ingest(
            DocumentInput(source_id="fixture", external_id=external, title=external, text=text),
            text.encode(),
            store,
        )
    return writer, reader, roles, store, encoder_bundle


def test_real_pgvector_ranking_generation_switch_and_rollback(retrieval):
    writer, reader, roles, store, encoder = retrieval
    index = VectorIndex(writer, encoder)
    first = index.build(store)
    assert first["status"] == "ready" and first["documents"] == 2
    index.activate(first["generation_id"])
    service = ReadService(reader, EvidenceStore(store.root, read_only=True), encoder=encoder)
    # 'disk' and 'storage' have equal fixture embeddings; this is a numerical oracle.
    found = service.search("disk")
    assert found["strategy"] == "hybrid-exact" and not found["degraded"]
    assert service.document(found["results"][0]["document_id"])["text"] == "storage disk"
    second = index.build(store)
    index.activate(second["generation_id"])
    index.activate(first["generation_id"])
    assert service.search("storage")["generation_id"] == first["generation_id"]
    migrate_retrieval(roles["admin"])
    wrong = LocalEncoder(encoder.manifest.model_copy(update={"max_tokens": 32}))
    with pytest.raises(WorkbenchError, match="INCOMPATIBLE_GENERATION"):
        VectorIndex(reader, wrong).search("storage")
    writer.ingest(
        DocumentInput(
            source_id="fixture", external_id="one", title="updated", text="patch vulnerability"
        ),
        b"changed raw",
        store,
    )
    assert service.search("patch")["degraded"]
    with pytest.raises(WorkbenchError, match="STALE_RETRIEVAL_GENERATION"):
        index.activate(second["generation_id"])


def test_failed_generation_does_not_replace_active_and_reader_cannot_write(retrieval):
    writer, reader, roles, store, encoder = retrieval
    index = VectorIndex(writer, encoder)
    first = index.build(store)
    index.activate(first["generation_id"])
    writer.ingest(
        DocumentInput(
            source_id="fixture", external_id="empty-vector", title="unknown", text="unrecognized"
        ),
        b"unknown raw",
        store,
    )
    with pytest.raises(WorkbenchError, match="EMBEDDING_NORM"):
        index.build(store)
    assert VectorIndex(reader, encoder).search("storage")["generation_id"] == first["generation_id"]
    with reader.connect() as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("DELETE FROM ow.retrieval_vectors")
    with psycopg.connect(roles["admin"]) as conn:
        conn.execute("GRANT UPDATE ON ow.retrieval_active TO ow_test_reader")
    try:
        with pytest.raises(WorkbenchError, match="UNSAFE_READER"):
            Database(roles["reader"]).validate_reader()
    finally:
        with psycopg.connect(roles["admin"]) as conn:
            conn.execute("REVOKE UPDATE ON ow.retrieval_active FROM ow_test_reader")


def test_hybrid_search_through_real_mcp_transport(retrieval, tmp_path):
    writer, _, roles, store, encoder = retrieval
    index = VectorIndex(writer, encoder)
    generation = index.build(store)
    index.activate(generation["generation_id"])
    manifest = tmp_path / "encoder.json"
    manifest.write_text(encoder.manifest.model_dump_json())

    async def run():
        env = {
            **os.environ,
            "OW_READER_DSN": roles["reader"],
            "OW_EVIDENCE_ROOT": str(store.root),
            "OW_ENCODER_MANIFEST": str(manifest),
        }
        params = StdioServerParameters(
            command=sys.executable, args=["-m", "osint_workbench.cli", "mcp"], env=env
        )
        async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("search_documents", {"query": "disk"})
            assert not result.is_error
            value = json.loads(result.content[0].text)
            assert value["strategy"] == "hybrid-exact"
            assert value["generation_id"] == generation["generation_id"]
            document = await session.call_tool(
                "get_document", {"document_id": value["results"][0]["document_id"]}
            )
            assert json.loads(document.content[0].text)["text"] == "storage disk"

    asyncio.run(run())


def test_actual_hybrid_rerank_integration(retrieval, reranker_bundle):
    writer, reader, _, store, encoder = retrieval
    index = VectorIndex(writer, encoder)
    built = index.build(store)
    index.activate(built["generation_id"])
    service = ReadService(
        reader, EvidenceStore(store.root, read_only=True), encoder=encoder, reranker=reranker_bundle
    )
    value = service.search("vulnerability")
    assert value["strategy"] == "hybrid-exact-reranked"
    assert value["results"][0]["rerank_score"] == 2.0
    assert value["results"][1]["rerank_score"] == -2.0
    with pytest.raises(WorkbenchError, match="INVALID_RERANK_PAGE"):
        service.search("patch", 33)
