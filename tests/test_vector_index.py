import asyncio
import json
import os
import sys
import uuid

import psycopg
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from osint_workbench import lifecycle
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


def test_unattended_growth_past_build_limit_degrades_search_instead_of_failing(retrieval):
    writer, reader, roles, store, encoder = retrieval
    index = VectorIndex(writer, encoder)
    generation = index.build(store)
    index.activate(generation["generation_id"])
    service = ReadService(reader, EvidenceStore(store.root, read_only=True), encoder=encoder)
    assert not service.search("disk")["degraded"]
    # Two large later observations push the head corpus past the 2M character
    # build bound; this is ordinary collector growth, not a reader fault.
    for external in ("large-a", "large-b"):
        text = "storage " * 125_000
        writer.ingest(
            DocumentInput(source_id="fixture", external_id=external, title=external, text=text),
            text.encode(),
            store,
        )
    found = service.search("disk")
    assert found["degraded"] and found["degradation_reason"] == "CORPUS_CHANGED"
    assert found["generation_id"] == generation["generation_id"]
    assert found["results"]
    # The bound still governs builds and activation explicitly.
    with pytest.raises(WorkbenchError, match="REFERENCE_CORPUS_LIMIT"):
        index.build(store)
    with pytest.raises(WorkbenchError, match="REFERENCE_CORPUS_LIMIT"):
        index.activate(generation["generation_id"])


def test_failed_generation_does_not_replace_active_and_reader_cannot_write(retrieval):
    writer, reader, roles, store, encoder = retrieval
    index = VectorIndex(writer, encoder)
    first = index.build(store)
    index.activate(first["generation_id"])
    # One all-unknown document is now an explicit exclusion (ADR-0041); a
    # majority of them still fails the build without replacing the active one.
    for name in ("empty-vector", "empty-vector-2", "empty-vector-3"):
        _ingest(writer, store, name, "unrecognized")
    with pytest.raises(WorkbenchError, match="RETRIEVAL_EXCLUSION_LIMIT"):
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


def test_hybrid_search_through_real_mcp_transport(retrieval, reranker_bundle, tmp_path):
    writer, _, roles, store, encoder = retrieval
    index = VectorIndex(writer, encoder)
    generation = index.build(store)
    index.activate(generation["generation_id"])
    manifest = tmp_path / "encoder.json"
    manifest.write_text(encoder.manifest.model_dump_json())
    reranker_manifest = tmp_path / "reranker.json"
    reranker_manifest.write_text(reranker_bundle.manifest.model_dump_json())

    async def run():
        env = {
            **os.environ,
            "OW_READER_DSN": roles["reader"],
            "OW_EVIDENCE_ROOT": str(store.root),
            "OW_ENCODER_MANIFEST": str(manifest),
            "OW_RERANKER_MANIFEST": str(reranker_manifest),
        }
        params = StdioServerParameters(
            command=sys.executable, args=["-m", "osint_workbench.cli", "mcp"], env=env
        )
        async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("search_documents", {"query": "disk"})
            assert not result.is_error
            value = json.loads(result.content[0].text)
            assert value["strategy"] == "hybrid-exact-reranked"
            assert value["reranker_id"] == reranker_bundle.manifest.identity()
            assert [row["rerank_score"] for row in value["results"]] == [2.0, -2.0]
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
    original = reranker_bundle.manifest.identity()
    reranker_bundle.manifest.output_name = "caller_changed_output"
    reranker_bundle.manifest.threads = 0
    value = service.search("vulnerability")
    assert value["reranker_id"] == original
    assert reranker_bundle.manifest.identity() != original
    with pytest.raises(WorkbenchError, match="^RERANK_CONFIGURATION_INVALID$"):
        ReadService(reader, EvidenceStore(store.root, read_only=True), reranker=reranker_bundle)
    assert value["strategy"] == "hybrid-exact-reranked"
    assert value["results"][0]["rerank_score"] == 2.0
    assert value["results"][1]["rerank_score"] == -2.0
    with pytest.raises(WorkbenchError, match="INVALID_RERANK_PAGE"):
        service.search("patch", 33)


def _ingest(writer, store, external, text):
    return writer.ingest(
        DocumentInput(source_id="fixture", external_id=external, title=external, text=text),
        text.encode(),
        store,
    )


def test_content_refusals_become_explicit_exclusions_not_build_failures(retrieval):
    writer, reader, roles, store, encoder = retrieval
    # Zero-width-only text passes extraction and the blank check but pools to a
    # zero vector; a valid long document exceeds the encoder input bound.
    hidden = _ingest(writer, store, "zero-width", "\u200b\u200c")
    long = _ingest(writer, store, "long", "patch " * 40_000)
    index = VectorIndex(writer, encoder)
    built = index.build(store)
    assert built["status"] == "ready" and built["documents"] == 4
    assert built["excluded_documents"] == 2
    assert built["exclusion_reasons"] == {"INVALID_EMBEDDING_NORM": 1, "INVALID_ENCODER_INPUT": 1}
    index.activate(built["generation_id"])
    with Database(roles["admin"]).connect() as conn:
        rows = conn.execute(
            "SELECT document_id,reason FROM ow.retrieval_exclusions WHERE generation_id=%s "
            "ORDER BY reason",
            (built["generation_id"],),
        ).fetchall()
        assert rows == [
            {"document_id": hidden, "reason": "INVALID_EMBEDDING_NORM"},
            {"document_id": long, "reason": "INVALID_ENCODER_INPUT"},
        ]
        assert not conn.execute(
            "SELECT 1 FROM ow.retrieval_vectors WHERE document_id=ANY(%s)", ([hidden, long],)
        ).fetchone()
    service = ReadService(reader, EvidenceStore(store.root, read_only=True), encoder=encoder)
    found = service.search("patch")
    assert not found["degraded"] and found["excluded_documents"] == 2
    # Excluded documents stay reachable lexically and as evidence.
    assert long in {r["document_id"] for r in found["results"]}
    assert service.document(long)["integrity"] == "verified"
    assert service.status()["excluded_documents"] == 2
    # The reader sees exclusions only through the lifecycle-filtered view.
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with psycopg.connect(roles["reader"]) as conn:
            conn.execute("SELECT 1 FROM ow.retrieval_exclusions")


def test_majority_exclusion_and_runtime_failures_still_fail_the_build(retrieval, monkeypatch):
    writer, reader, roles, store, encoder = retrieval
    good = VectorIndex(writer, encoder).build(store)
    VectorIndex(writer, encoder).activate(good["generation_id"])
    hidden = [_ingest(writer, store, name, "\u2060") for name in ("zw-a", "zw-b", "zw-c")]

    def failed(index, code):
        with pytest.raises(WorkbenchError, match=f"^{code}$"):
            index.build(store)
        with Database(roles["admin"]).connect() as conn:
            row = conn.execute(
                "SELECT status,error_code FROM ow.retrieval_generations "
                "ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
            active = conn.execute("SELECT generation_id FROM ow.retrieval_active").fetchone()
        assert row == {"status": "failed", "error_code": code}
        assert str(active["generation_id"]) == good["generation_id"]

    # Three of five members unencodable: an incompatible encoder must not
    # silently produce an almost empty generation.
    failed(VectorIndex(writer, encoder), "RETRIEVAL_EXCLUSION_LIMIT")

    # Retire the unencodable documents through the real operator path.
    for document in hidden:
        lifecycle.apply(
            Database(roles["lifecycle"]),
            lifecycle.Change(
                action="retire",
                document_id=document,
                operation_id=uuid.uuid4().hex,
                actor="synthetic-index-operator",
                rationale="Remove unencodable synthetic entries",
            ),
        )
    invoke = LocalEncoder._invoke_packet
    for code in (
        "ENCODER_TIMEOUT",
        "ENCODER_UNAVAILABLE",
        "MODEL_INTEGRITY_MISMATCH",
        "ENCODER_INCOMPATIBLE",
        "ENCODER_INVALID_RESULT",
        "INVALID_EMBEDDING_VECTOR",
        "INVALID_ENCODER_PACKET",
    ):

        def unavailable(self, manifest, packet, error=code):
            if json.loads(packet)["text"] == "storage disk":
                raise WorkbenchError(error)
            return invoke(self, manifest, packet)

        with monkeypatch.context() as patch:
            patch.setattr(LocalEncoder, "_invoke_packet", unavailable)
            failed(VectorIndex(writer, encoder), code)


def test_member_with_both_dispositions_cannot_activate(retrieval):
    writer, reader, roles, store, encoder = retrieval
    index = VectorIndex(writer, encoder)
    built = index.build(store)
    # A writer-authority row must not give an encoded member a second disposition.
    with Database(roles["admin"]).connect() as conn:
        conn.execute(
            "INSERT INTO ow.retrieval_exclusions SELECT generation_id,document_id,"
            "'INVALID_ENCODER_INPUT' FROM ow.retrieval_members WHERE generation_id=%s LIMIT 1",
            (built["generation_id"],),
        )
    with pytest.raises(WorkbenchError, match="^INCOMPLETE_RETRIEVAL_GENERATION$"):
        index.activate(built["generation_id"])


def test_unmigrated_profile_is_reported_typed_not_as_raw_sql(retrieval):
    writer, reader, roles, store, encoder = retrieval
    index = VectorIndex(writer, encoder)
    index.activate(index.build(store)["generation_id"])
    service = ReadService(reader, EvidenceStore(store.root, read_only=True), encoder=encoder)
    # Fault injection: hide the profile-4 view as an older profile would lack it.
    with psycopg.connect(roles["admin"]) as conn:
        conn.execute("ALTER VIEW ow.visible_retrieval_exclusions RENAME TO hidden_exclusions")
    try:
        assert service.status()["retrieval_state"] == "migration_required"
        with pytest.raises(WorkbenchError, match="^RETRIEVAL_MIGRATION_REQUIRED$"):
            service.search("storage")
    finally:
        with psycopg.connect(roles["admin"]) as conn:
            conn.execute("ALTER VIEW ow.hidden_exclusions RENAME TO visible_retrieval_exclusions")
    assert service.search("storage")["excluded_documents"] == 0


def test_caller_mutation_cannot_mislabel_persisted_generation(retrieval):
    writer, reader, roles, store, encoder = retrieval
    expected_id = encoder.manifest.identity()
    expected_manifest = encoder.manifest.model_dump(
        exclude={"model_path", "tokenizer_path", "threads"}
    )
    index = VectorIndex(writer, encoder)
    encoder.manifest.space.document_template = "patch {text}"
    built = index.build(store)
    index.activate(built["generation_id"])
    with writer.connect() as conn:
        space = conn.execute(
            "SELECT manifest,dimensions FROM ow.embedding_spaces WHERE space_id=%s",
            (expected_id,),
        ).fetchone()
        rows = conn.execute(
            "SELECT v.space_id,v.embedding::text AS embedding,d.body "
            "FROM ow.retrieval_vectors v JOIN ow.active_documents d USING(document_id) "
            "WHERE generation_id=%s",
            (built["generation_id"],),
        ).fetchall()
    assert space == {"manifest": expected_manifest, "dimensions": 3}
    assert built["space_id"] == expected_id and len(rows) == 2
    expected_vectors = {"storage disk": [1, 0, 0], "vulnerability patch": [0, 1, 0]}
    for row in rows:
        assert row["space_id"] == expected_id
        assert json.loads(row["embedding"]) == expected_vectors[row["body"]]


def test_caller_query_template_mutation_cannot_rebind_hybrid_search(retrieval):
    writer, reader, roles, store, encoder = retrieval
    index = VectorIndex(writer, encoder)
    built = index.build(store)
    index.activate(built["generation_id"])
    service = ReadService(reader, EvidenceStore(store.root, read_only=True), encoder=encoder)
    encoder.manifest.space.query_template = "patch patch {text}"
    found = service.search("disk")
    assert found["space_id"] == built["space_id"] and not found["degraded"]
    assert found["results"][0]["excerpt"] == "storage disk"
    # Both exact native and lexical rankings put storage first under the captured
    # contract; the changed template would put security first semantically.
    assert found["results"][0]["rrf_score"] == pytest.approx(2 / 61)


@pytest.mark.parametrize("field", ["manifest", "dimensions"])
def test_conflicting_registered_space_refuses_build_without_relabelling(retrieval, field):
    from psycopg.types.json import Jsonb

    writer, reader, roles, store, encoder = retrieval
    index = VectorIndex(writer, encoder)
    manifest = encoder.manifest.model_dump(exclude={"model_path", "tokenizer_path", "threads"})
    dimensions = 3
    if field == "manifest":
        manifest["space"]["document_template"] = "patch {text}"
    else:
        dimensions = 4
    with writer.connect() as conn:
        conn.execute(
            "INSERT INTO ow.embedding_spaces(space_id,manifest,dimensions) VALUES (%s,%s,%s)",
            (index.space_id, Jsonb(manifest), dimensions),
        )
    with pytest.raises(WorkbenchError, match="^INCOMPATIBLE_EMBEDDING_SPACE$"):
        index.build(store)
    with writer.connect() as conn:
        assert conn.execute(
            "SELECT manifest,dimensions FROM ow.embedding_spaces WHERE space_id=%s",
            (index.space_id,),
        ).fetchone() == {"manifest": manifest, "dimensions": dimensions}
        assert (
            conn.execute("SELECT count(*) AS n FROM ow.retrieval_generations").fetchone()["n"] == 0
        )
        assert conn.execute("SELECT count(*) AS n FROM ow.retrieval_active").fetchone()["n"] == 0


@pytest.mark.parametrize("conflict", ["template", "normalized_type"])
def test_active_registry_conflict_refuses_reads_and_activation_without_repair(
    retrieval, monkeypatch, conflict
):
    from psycopg.types.json import Jsonb

    writer, reader, roles, store, encoder = retrieval
    index = VectorIndex(writer, encoder)
    built = index.build(store)
    index.activate(built["generation_id"])
    service = ReadService(reader, EvidenceStore(store.root, read_only=True), encoder=encoder)
    assert service.search("disk")["results"][0]["excerpt"] == "storage disk"
    with writer.connect() as conn:
        before = conn.execute(
            "SELECT document_id,embedding::text AS embedding FROM ow.retrieval_vectors "
            "WHERE generation_id=%s ORDER BY document_id,ordinal",
            (built["generation_id"],),
        ).fetchall()
    # Reproduce a historical registry mismatch using fixture-admin authority.
    # The application writer cannot update registered manifests.
    manifest = encoder.manifest.model_dump(exclude={"model_path", "tokenizer_path", "threads"})
    if conflict == "template":
        manifest["space"]["query_template"] = "patch {text}"
    else:
        # Python dict equality accepts 1 == True; canonical model identity must not.
        manifest["space"]["normalized"] = 1
    with Database(roles["admin"]).connect() as conn:
        conn.execute(
            "UPDATE ow.embedding_spaces SET manifest=%s WHERE space_id=%s",
            (Jsonb(manifest), index.space_id),
        )

    def unexpected_inference(self, query):
        pytest.fail("conflicting registry reached query inference")

    monkeypatch.setattr(LocalEncoder, "query", unexpected_inference)
    assert service.status()["retrieval_state"] == "incompatible"
    with pytest.raises(WorkbenchError, match="^INCOMPATIBLE_EMBEDDING_SPACE$"):
        service.search("disk")
    with pytest.raises(WorkbenchError, match="^INCOMPATIBLE_EMBEDDING_SPACE$"):
        index.activate(built["generation_id"])
    # Explicit lexical/evidence reads remain available with reader authority.
    lexical = ReadService(reader, EvidenceStore(store.root, read_only=True))
    assert lexical.search("disk")["results"][0]["excerpt"] == "storage disk"
    with writer.connect() as conn:
        assert conn.execute(
            "SELECT manifest FROM ow.embedding_spaces WHERE space_id=%s", (index.space_id,)
        ).fetchone() == {"manifest": manifest}
        assert conn.execute(
            "SELECT status FROM ow.retrieval_generations WHERE generation_id=%s",
            (built["generation_id"],),
        ).fetchone() == {"status": "ready"}
        assert (
            str(
                conn.execute("SELECT generation_id FROM ow.retrieval_active").fetchone()[
                    "generation_id"
                ]
            )
            == built["generation_id"]
        )
        assert (
            conn.execute(
                "SELECT document_id,embedding::text AS embedding FROM ow.retrieval_vectors "
                "WHERE generation_id=%s ORDER BY document_id,ordinal",
                (built["generation_id"],),
            ).fetchall()
            == before
        )
