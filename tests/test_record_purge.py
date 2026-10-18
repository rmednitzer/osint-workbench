"""Transactional retired-record purge against disposable native PostgreSQL only."""

import asyncio
import copy
import json
import os
import secrets
import stat
import sys
import uuid
from datetime import UTC, datetime, timedelta

import psycopg
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from psycopg import sql
from psycopg.conninfo import make_conninfo
from psycopg.types.json import Jsonb
from pydantic import ValidationError

from osint_workbench import intelligence, lifecycle, record_purge, recovery
from osint_workbench.database import Database
from osint_workbench.errors import WorkbenchError
from osint_workbench.evidence import EvidenceStore
from osint_workbench.jobs import Jobs
from osint_workbench.service import ReadService
from osint_workbench.text import digest
from osint_workbench.vector_index import VectorIndex
from tests.test_recovery import _fixture, _input, policy_arguments, published_pair
from tests.test_recovery import destination as destination

pytestmark = pytest.mark.integration


@pytest.fixture
def context(databases, tmp_path):
    writer, reader, roles = databases
    name = "ow_test_purger_" + uuid.uuid4().hex
    password = secrets.token_urlsafe(32)
    with psycopg.connect(roles["admin"], autocommit=True) as conn:
        conn.execute(
            sql.SQL(
                "CREATE ROLE {} LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "NOREPLICATION NOBYPASSRLS PASSWORD {}"
            ).format(sql.Identifier(name), sql.Literal(password))
        )
        conn.execute(sql.SQL("GRANT ow_purger TO {}").format(sql.Identifier(name)))
    try:
        yield {
            "writer": writer,
            "reader": reader,
            "roles": roles,
            "admin": Database(roles["admin"]),
            "operator": Database(roles["lifecycle"]),
            "purger": Database(make_conninfo(roles["admin"], user=name, password=password)),
            "login": name,
            "store": EvidenceStore(tmp_path / "objects"),
            "tmp": tmp_path,
        }
    finally:
        with psycopg.connect(roles["admin"], autocommit=True) as conn:
            conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(name)))


def change(context, document, action, **kwargs):
    return lifecycle.apply(
        context["operator"],
        lifecycle.Change(
            action=action,
            document_id=document,
            operation_id=uuid.uuid4().hex,
            actor="synthetic-purge-reviewer",
            rationale="Synthetic retention decision",
            **kwargs,
        ),
    )


def plan(context, document, *, name="review.owpurge", operation=None, rationale=None):
    path = context["tmp"] / name
    receipt = record_purge.plan(
        context["purger"],
        path,
        document_id=document,
        operation_id=operation or uuid.uuid4().hex,
        actor="synthetic-purge-reviewer",
        rationale=rationale or "Remove retired synthetic SQL records after review",
    )
    return path, receipt


def apply(context, document, **kwargs):
    path, receipt = plan(context, document, **kwargs)
    return record_purge.apply(context["purger"], path, receipt["sha256"])


def state(context):
    names = (
        "sources",
        "snapshots",
        "documents",
        "document_heads",
        "jobs",
        "job_events",
        "chunks",
        "collection_runs",
        "collection_state",
        "enrichments",
        "assertions",
        "assertion_reviews",
        "briefings",
        "lifecycle_control",
        "lifecycle_items",
        "lifecycle_holds",
        "lifecycle_tombstones",
        "lifecycle_events",
        "retrieval_generations",
        "retrieval_members",
        "retrieval_vectors",
        "retrieval_active",
    )
    result = {}
    with context["admin"].connect() as conn:
        for name in names:
            if conn.execute("SELECT to_regclass(%s) AS relation", ("ow." + name,)).fetchone()[
                "relation"
            ]:
                result[name] = conn.execute(
                    sql.SQL(
                        "SELECT to_jsonb(t) AS value FROM ow.{} t ORDER BY to_jsonb(t)::text"
                    ).format(sql.Identifier(name))
                ).fetchall()
    return result


def retired_document(context):
    document = context["writer"].ingest(_input(), b"synthetic purge raw", context["store"])
    change(context, document, "retire")
    return document


def assert_absent(context, identifiers):
    with context["admin"].connect() as conn:
        for table in ("documents", "chunks", "enrichments", "assertions"):
            assert not conn.execute(
                sql.SQL("SELECT 1 FROM ow.{} WHERE document_id=ANY(%s)").format(
                    sql.Identifier(table)
                ),
                (identifiers,),
            ).fetchone()


def test_all_versions_and_sql_derivatives_purged_with_permanent_policy_and_real_mcp(context):
    writer, reader, store = context["writer"], context["reader"], context["store"]
    previous = writer.ingest(_input("Previous synthetic storage evidence."), b"previous", store)
    document, assertion, brief, unrelated_pending, unrelated_running, _ = _fixture(writer, store)
    neighbour = writer.ingest(
        _input("Independent policy evidence.", "neighbour"), b"neighbour", store
    )
    with context["admin"].connect() as conn:
        snapshots = conn.execute(
            "SELECT DISTINCT snapshot_id FROM ow.documents WHERE document_id=ANY(%s)",
            ([previous, document],),
        ).fetchall()
        source_key = conn.execute(
            "SELECT source_id,external_key FROM ow.documents WHERE document_id=%s", (document,)
        ).fetchone()
    change(context, document, "retire")
    before = state(context)
    object_names = sorted(str(p.relative_to(store.root)) for p in store.root.rglob("*"))
    path, planned = plan(context, document)
    assert planned["classification"] == "private_purge_plan"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert state(context) == before
    result = record_purge.apply(context["purger"], path, planned["sha256"])
    assert result["kind"] == "retired_record_purge" and result["sql_deleted"]
    assert not result["physical_erasure"] and not result["backup_erasure"]
    assert result["cas_objects_deleted"] == 0 and not result["replayed"]
    assert result["revision"] == result["policy_revision_before"] + 1
    assert result["counts"]["documents"] == 2
    assert_absent(context, [previous, document])
    with context["admin"].connect() as conn:
        assert not conn.execute(
            "SELECT 1 FROM ow.assertion_reviews WHERE assertion_id=%s", (assertion,)
        ).fetchone()
        assert not conn.execute(
            "SELECT 1 FROM ow.briefings WHERE briefing_id=%s", (brief,)
        ).fetchone()
        assert not conn.execute(
            "SELECT 1 FROM ow.snapshots WHERE snapshot_id=ANY(%s)",
            ([r["snapshot_id"] for r in snapshots],),
        ).fetchone()
        assert conn.execute(
            "SELECT 1 FROM ow.lifecycle_tombstones WHERE source_id=%s AND external_key=%s",
            (source_key["source_id"], source_key["external_key"]),
        ).fetchone()
        event = conn.execute(
            "SELECT action,result FROM ow.lifecycle_events WHERE operation_id=%s",
            (result["operation_id"],),
        ).fetchone()
        assert event["action"] == "purge" and event["result"]["sql_deleted"]
    assert Jobs(writer).inspect(unrelated_pending)["status"] == "ready"
    assert Jobs(writer).inspect(unrelated_running)["status"] == "running"
    assert reader.document(neighbour)["document_id"] == neighbour
    assert sorted(str(p.relative_to(store.root)) for p in store.root.rglob("*")) == object_names
    service = ReadService(reader, EvidenceStore(store.root, read_only=True))
    for identifier in (previous, document):
        with pytest.raises(WorkbenchError, match="DOCUMENT_NOT_FOUND"):
            service.document(identifier)
    with pytest.raises(WorkbenchError, match="BRIEFING_NOT_FOUND"):
        service.briefing(brief)
    with pytest.raises(WorkbenchError, match="RETIRED_OR_EXPIRED"):
        writer.ingest(_input("Attempted resurrection."), b"new raw", store)

    async def roundtrip():
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "osint_workbench.cli", "mcp"],
            env={
                **os.environ,
                "OW_READER_DSN": context["roles"]["reader"],
                "OW_EVIDENCE_ROOT": str(store.root),
            },
        )
        async with stdio_client(params) as (read, write), ClientSession(read, write) as client:
            await client.initialize()
            response = await client.call_tool("get_document", {"document_id": document})
            assert response.is_error and "Straße storage" not in response.content[0].text
            inventory = await client.list_tools()
            assert len(inventory.tools) == 7 and not any(
                "purge" in tool.name for tool in inventory.tools
            )

    asyncio.run(roundtrip())


@pytest.mark.parametrize("role", ["writer", "reader", "lifecycle", "collector", "admin"])
def test_other_principals_cannot_plan_or_apply_purge(context, role):
    document = retired_document(context)
    path, receipt = plan(context, document)
    before = state(context)
    db = Database(context["roles"][role])
    with pytest.raises(WorkbenchError):
        record_purge.plan(
            db,
            context["tmp"] / "forbidden.owpurge",
            document_id=document,
            operation_id=uuid.uuid4().hex,
            actor="synthetic-reviewer",
            rationale="Synthetic unauthorized attempt",
        )
    with pytest.raises(WorkbenchError):
        record_purge.apply(db, path, receipt["sha256"])
    assert state(context) == before and not (context["tmp"] / "forbidden.owpurge").exists()


def test_purger_with_extra_writer_authority_is_refused(context):
    document = retired_document(context)
    with context["admin"].connect() as conn:
        conn.execute(sql.SQL("GRANT ow_writer TO {}").format(sql.Identifier(context["login"])))
    try:
        before = state(context)
        with pytest.raises(WorkbenchError):
            plan(context, document)
        assert state(context) == before
    finally:
        with context["admin"].connect() as conn:
            conn.execute(
                sql.SQL("REVOKE ow_writer FROM {}").format(sql.Identifier(context["login"]))
            )


@pytest.mark.parametrize("condition", ["active", "expired", "held"])
def test_visibility_loss_or_hold_is_not_retirement_authority(context, condition):
    document = context["writer"].ingest(_input(), b"raw", context["store"])
    if condition == "expired":
        change(
            context,
            document,
            "retention",
            retention_class="short",
            retain_until=datetime.now(UTC) - timedelta(seconds=1),
        )
    elif condition == "held":
        change(context, document, "hold", hold_id="target-hold")
    before = state(context)
    with pytest.raises(WorkbenchError):
        plan(context, document)
    assert state(context) == before


def test_held_neighbour_in_shared_immutable_briefing_vetoes_purge(context):
    document, *_ = _fixture(context["writer"], context["store"])
    neighbour = context["writer"].ingest(
        _input("Independent held evidence.", "held-neighbour"), b"held", context["store"]
    )
    intelligence.create_briefing(context["writer"], [document, neighbour])
    change(context, neighbour, "hold", hold_id="neighbour-hold")
    change(context, document, "retire")
    before = state(context)
    with pytest.raises(WorkbenchError):
        plan(context, document)
    assert state(context) == before


def test_shared_snapshot_and_source_feed_receipts_survive_sql_purge(context):
    writer, store = context["writer"], context["store"]
    document = writer.ingest(_input(), b"shared raw feed", store)
    neighbour = writer.ingest(_input(external="neighbour"), b"shared raw feed", store)
    snapshot = context["reader"].document(document)["snapshot_id"]
    raw_sha = digest(b"shared raw feed")
    with context["admin"].connect() as conn:
        conn.execute(
            "INSERT INTO ow.collection_runs(run_id,source_id,status,raw_sha256) "
            "VALUES (%s,'fixture','succeeded',%s)",
            (uuid.uuid4(), raw_sha),
        )
        conn.execute(
            "INSERT INTO ow.collection_state(source_id,resource_sha256,etag,raw_sha256) "
            "VALUES ('fixture',%s,'\"shared\"',%s)",
            (digest(b"synthetic shared resource"), raw_sha),
        )
    change(context, document, "retire")
    apply(context, document)
    assert context["reader"].document(neighbour)["snapshot_id"] == snapshot
    with context["admin"].connect() as conn:
        assert conn.execute(
            "SELECT 1 FROM ow.snapshots WHERE snapshot_id=%s", (snapshot,)
        ).fetchone()
        assert (
            conn.execute("SELECT raw_sha256 FROM ow.collection_runs").fetchone()["raw_sha256"]
            == raw_sha
        )
        assert (
            conn.execute("SELECT raw_sha256 FROM ow.collection_state").fetchone()["raw_sha256"]
            == raw_sha
        )
    assert store.get(raw_sha) == b"shared raw feed"


@pytest.mark.parametrize("mutation", ["inventory", "policy", "dataset"])
def test_exact_reviewed_plan_is_refused_after_inventory_or_policy_drift(context, mutation):
    document = retired_document(context)
    path, receipt = plan(context, document)
    if mutation == "policy":
        neighbour = context["writer"].ingest(
            _input("Other evidence.", "neighbour"), b"other", context["store"]
        )
        change(context, neighbour, "hold", hold_id="later-hold")
    else:
        with context["admin"].connect() as conn:
            if mutation == "inventory":
                conn.execute(
                    "UPDATE ow.jobs SET last_error='synthetic-inventory-drift' "
                    "WHERE payload->>'document_id'=%s",
                    (document,),
                )
            else:
                conn.execute("UPDATE ow.lifecycle_control SET dataset_id=gen_random_uuid()")
    before = state(context)
    with pytest.raises(WorkbenchError):
        record_purge.apply(context["purger"], path, receipt["sha256"])
    assert state(context) == before


@pytest.mark.parametrize("fault", ["wrong-hash", "corrupt-file"])
def test_corrupt_or_unreviewed_plan_never_deletes_records(context, fault):
    document = retired_document(context)
    path, receipt = plan(context, document)
    expected = receipt["sha256"]
    if fault == "wrong-hash":
        expected = "0" * 64
    else:
        path.write_bytes(b'{"synthetic-corrupt-plan":')
    before = state(context)
    with pytest.raises(WorkbenchError):
        record_purge.apply(context["purger"], path, expected)
    assert state(context) == before


@pytest.mark.parametrize("field", ["actor", "rationale"])
def test_endorsed_plan_with_blank_decision_metadata_is_rejected_before_mutation(context, field):
    document = retired_document(context)
    path, _ = plan(context, document)
    bundle = json.loads(path.read_bytes())
    bundle["payload"]["request"][field] = "   "
    bundle["sha256"] = digest(recovery._json(bundle["payload"]))
    path.write_bytes(recovery._json(bundle))
    before = state(context)
    with pytest.raises((WorkbenchError, ValidationError)):
        record_purge.apply(context["purger"], path, bundle["sha256"])
    assert state(context) == before


@pytest.mark.parametrize("schema_fault", ["row-security", "unknown-table", "migration-digest"])
def test_purge_refuses_incomplete_visibility_or_unknown_schema_before_deletion(
    context, schema_fault
):
    document = retired_document(context)
    path, receipt = plan(context, document)
    with context["admin"].connect() as conn:
        original_sha = conn.execute("SELECT sha256 FROM ow.migrations WHERE version=1").fetchone()[
            "sha256"
        ]
        if schema_fault == "row-security":
            conn.execute("ALTER TABLE ow.documents ENABLE ROW LEVEL SECURITY")
        elif schema_fault == "unknown-table":
            conn.execute("CREATE TABLE ow.synthetic_purge_unknown(value integer)")
        else:
            conn.execute("UPDATE ow.migrations SET sha256=%s WHERE version=1", ("0" * 64,))
    try:
        before = state(context)
        with pytest.raises(WorkbenchError):
            plan(context, document, name="rejected.owpurge")
        with pytest.raises(WorkbenchError):
            record_purge.apply(context["purger"], path, receipt["sha256"])
        assert state(context) == before and not (context["tmp"] / "rejected.owpurge").exists()
    finally:
        with context["admin"].connect() as conn:
            if schema_fault == "row-security":
                conn.execute("ALTER TABLE ow.documents DISABLE ROW LEVEL SECURITY")
            elif schema_fault == "unknown-table":
                conn.execute("DROP TABLE ow.synthetic_purge_unknown")
            else:
                conn.execute("UPDATE ow.migrations SET sha256=%s WHERE version=1", (original_sha,))


@pytest.mark.parametrize("extra_authority", ["inherited-owner", "delete-policy", "delegation"])
def test_purger_rejects_reachable_ownership_extra_delete_or_delegation(context, extra_authority):
    document = retired_document(context)
    path, receipt = plan(context, document)
    owner_role = "ow_purge_owner_" + uuid.uuid4().hex
    with context["admin"].connect() as conn:
        original_owner = conn.execute(
            "SELECT pg_get_userbyid(relowner) AS owner FROM pg_class "
            "WHERE oid='ow.documents'::regclass"
        ).fetchone()["owner"]
        if extra_authority == "inherited-owner":
            conn.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(owner_role)))
            conn.execute(
                sql.SQL("ALTER TABLE ow.documents OWNER TO {}").format(sql.Identifier(owner_role))
            )
            conn.execute(
                sql.SQL("GRANT {} TO {}").format(
                    sql.Identifier(owner_role), sql.Identifier(context["login"])
                )
            )
        elif extra_authority == "delete-policy":
            conn.execute(
                sql.SQL("GRANT DELETE ON ow.lifecycle_tombstones TO {}").format(
                    sql.Identifier(context["login"])
                )
            )
        else:
            conn.execute(
                sql.SQL("GRANT ow_purger TO {} WITH ADMIN OPTION").format(
                    sql.Identifier(context["login"])
                )
            )
    try:
        before = state(context)
        with pytest.raises(WorkbenchError):
            plan(context, document, name="rejected.owpurge")
        with pytest.raises(WorkbenchError):
            record_purge.apply(context["purger"], path, receipt["sha256"])
        assert state(context) == before
    finally:
        with context["admin"].connect() as conn:
            if extra_authority == "inherited-owner":
                conn.execute(
                    sql.SQL("ALTER TABLE ow.documents OWNER TO {}").format(
                        sql.Identifier(original_owner)
                    )
                )
                conn.execute(
                    sql.SQL("REVOKE {} FROM {}").format(
                        sql.Identifier(owner_role), sql.Identifier(context["login"])
                    )
                )
                conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(owner_role)))
            elif extra_authority == "delete-policy":
                conn.execute(
                    sql.SQL("REVOKE DELETE ON ow.lifecycle_tombstones FROM {}").format(
                        sql.Identifier(context["login"])
                    )
                )
            else:
                conn.execute(
                    sql.SQL("REVOKE ADMIN OPTION FOR ow_purger FROM {}").format(
                        sql.Identifier(context["login"])
                    )
                )


def test_mid_delete_failure_rolls_back_actual_rows_and_policy_then_retry_succeeds(
    context, monkeypatch
):
    document, *_ = _fixture(context["writer"], context["store"])
    change(context, document, "retire")
    path, receipt = plan(context, document)
    before = state(context)
    deleted = []
    original = record_purge._delete_rows

    def fail_after_real_delete(conn, table, keys):
        result = original(conn, table, keys)
        if keys:
            deleted.append(table)
            raise WorkbenchError("SYNTHETIC_PURGE_DELETE_FAILURE")
        return result

    with monkeypatch.context() as patch:
        patch.setattr(record_purge, "_delete_rows", fail_after_real_delete)
        with pytest.raises(WorkbenchError, match="^SYNTHETIC_PURGE_DELETE_FAILURE$"):
            record_purge.apply(context["purger"], path, receipt["sha256"])
    assert deleted and state(context) == before
    result = record_purge.apply(context["purger"], path, receipt["sha256"])
    assert result["sql_deleted"] and not result["replayed"]
    assert_absent(context, [document])


def test_same_plan_replays_durable_receipt_but_conflicting_plan_cannot_reuse_operation(context):
    document = retired_document(context)
    operation = uuid.uuid4().hex
    path, receipt = plan(context, document, operation=operation)
    conflict_path, conflict = plan(
        context,
        document,
        name="conflict.owpurge",
        operation=operation,
        rationale="A distinct reviewed rationale",
    )
    first = record_purge.apply(context["purger"], path, receipt["sha256"])
    before = state(context)
    replay = record_purge.apply(context["purger"], path, receipt["sha256"])
    assert replay["replayed"] and {**replay, "replayed": False} == first
    with pytest.raises(WorkbenchError):
        record_purge.apply(context["purger"], conflict_path, conflict["sha256"])
    assert state(context) == before


@pytest.mark.parametrize("malformed", ["unknown-kind", "invalid-selection"])
def test_unknown_or_malformed_products_fail_closed_without_partial_purge(context, malformed):
    document = retired_document(context)
    content = {
        "schema_version": 1,
        "kind": "unknown",
        "selected_documents": [document],
        "items": [],
    }
    if malformed == "invalid-selection":
        content.update(kind="reviewed_assertion_digest", selected_documents="not-an-array")
    with context["admin"].connect() as conn:
        conn.execute(
            "INSERT INTO ow.briefings(briefing_id,content) VALUES (%s,%s)",
            (digest(json.dumps(content, sort_keys=True).encode()), Jsonb(content)),
        )
    before = state(context)
    with pytest.raises(WorkbenchError):
        plan(context, document)
    assert state(context) == before


def test_cross_item_enrichment_job_reference_is_not_deleted_by_inference(context):
    document, *_ = _fixture(context["writer"], context["store"])
    neighbour = context["writer"].ingest(
        _input("Independent evidence.", "neighbour"), b"other", context["store"]
    )
    with context["admin"].connect() as conn:
        conn.execute(
            "UPDATE ow.jobs SET payload=jsonb_build_object('document_id',%s::text) "
            "WHERE job_id IN (SELECT job_id FROM ow.enrichments WHERE document_id=%s)",
            (neighbour, document),
        )
    change(context, document, "retire")
    before = state(context)
    with pytest.raises(WorkbenchError):
        plan(context, document)
    assert state(context) == before


def test_native_profile_purge_invalidates_alias_and_preserves_other_vectors(
    context, encoder_bundle
):
    if os.environ.get("OW_TEST_RETRIEVAL") != "1":
        pytest.skip("native optional retrieval profile unavailable")
    writer, store = context["writer"], context["store"]
    document = writer.ingest(_input("storage disk"), b"raw", store)
    neighbour = writer.ingest(_input("vulnerability patch", "neighbour"), b"other", store)
    index = VectorIndex(writer, encoder_bundle)
    generation = index.build(store)["generation_id"]
    index.activate(generation)
    change(context, document, "retire")
    apply(context, document)
    with context["admin"].connect() as conn:
        assert not conn.execute("SELECT 1 FROM ow.retrieval_active").fetchone()
        assert (
            conn.execute(
                "SELECT status FROM ow.retrieval_generations WHERE generation_id=%s", (generation,)
            ).fetchone()["status"]
            == "failed"
        )
        for table in ("retrieval_members", "retrieval_vectors"):
            assert not conn.execute(
                sql.SQL("SELECT 1 FROM ow.{} WHERE document_id=%s").format(sql.Identifier(table)),
                (document,),
            ).fetchone()
            assert conn.execute(
                sql.SQL("SELECT 1 FROM ow.{} WHERE document_id=%s").format(sql.Identifier(table)),
                (neighbour,),
            ).fetchone()
    with pytest.raises(WorkbenchError):
        index.activate(generation)


def test_purge_between_builder_transactions_revokes_late_encoder_admission(
    context, encoder_bundle, monkeypatch
):
    if os.environ.get("OW_TEST_RETRIEVAL") != "1":
        pytest.skip("native optional retrieval profile unavailable")
    writer, store = context["writer"], context["store"]
    documents = [
        writer.ingest(_input(text, external), raw, store)
        for text, external, raw in (
            ("storage disk", "one", b"one"),
            ("vulnerability patch", "two", b"two"),
        )
    ]
    target = min(documents)
    original_get, original_chunks = store.get, encoder_bundle.chunks
    reads, dispatched, invalidated = [], [], []

    def observe_chunks(text):
        dispatched.append(text)
        return original_chunks(text)

    def interleave(sha):
        reads.append(sha)
        if len(reads) == 3:
            change(context, target, "retire")
            apply(context, target)
            with context["admin"].connect() as conn:
                invalidated.extend(
                    conn.execute(
                        "SELECT generation_id,status,error_code FROM ow.retrieval_generations"
                    ).fetchall()
                )
        return original_get(sha)

    monkeypatch.setattr(store, "get", interleave)
    monkeypatch.setattr(encoder_bundle, "chunks", observe_chunks)
    with pytest.raises(WorkbenchError, match="^RETRIEVAL_GENERATION_INVALIDATED$"):
        VectorIndex(writer, encoder_bundle).build(store)
    assert len(dispatched) == 1 and len(invalidated) == 1 and invalidated[0]["status"] == "failed"
    with context["admin"].connect() as conn:
        assert (
            conn.execute(
                "SELECT generation_id,status,error_code FROM ow.retrieval_generations"
            ).fetchall()
            == invalidated
        )
        assert not conn.execute("SELECT 1 FROM ow.retrieval_members").fetchone()
        assert not conn.execute("SELECT 1 FROM ow.retrieval_vectors").fetchone()
    assert_absent(context, [target])


def test_post_purge_checkpoint_restores_but_older_data_cannot_be_reintroduced(context, destination):
    document, *_ = _fixture(context["writer"], context["store"])
    old_path = context["tmp"] / "before.owcp"
    old_receipt = recovery.checkpoint(context["admin"], context["store"], old_path)
    change(context, document, "retire")
    result = apply(context, document)
    old_policy = policy_arguments(context["roles"], old_path)
    restored_root = context["tmp"] / "forbidden-old"
    with pytest.raises(WorkbenchError, match="^RECOVERY_PURGED_CONTENT_PRESENT$"):
        recovery.restore(
            Database(destination["admin"]),
            old_path,
            old_receipt["sha256"],
            restored_root,
            **old_policy,
        )
    assert not restored_root.exists()
    path = context["tmp"] / "after.owcp"
    receipt = recovery.checkpoint(context["admin"], context["store"], path)
    policy = policy_arguments(context["roles"], path)
    recovery.restore(
        Database(destination["admin"]),
        path,
        receipt["sha256"],
        context["tmp"] / "restored",
        **policy,
    )
    with Database(destination["admin"]).connect() as conn:
        assert not conn.execute(
            "SELECT 1 FROM ow.documents WHERE document_id=%s", (document,)
        ).fetchone()
        assert conn.execute(
            "SELECT result FROM ow.lifecycle_events WHERE operation_id=%s",
            (result["operation_id"],),
        ).fetchone()["result"]["sql_deleted"]
    with pytest.raises(WorkbenchError, match="RETIRED_OR_EXPIRED"):
        Database(destination["writer"]).ingest(
            _input(), b"resurrection", EvidenceStore(context["tmp"] / "restored")
        )


@pytest.mark.parametrize("version,profile", [(6, 2), (7, 3), (8, 3), (8, 4)])
def test_known_core_checkpoint_adopts_into_current_schema(
    context, destination, encoder_bundle, version, profile
):
    if os.environ.get("OW_TEST_RETRIEVAL") != "1":
        pytest.skip("native optional retrieval profile unavailable")
    document, assertion, _, _, _, _ = _fixture(context["writer"], context["store"])
    neighbour = context["writer"].ingest(
        _input("vulnerability patch", "neighbour"), b"other", context["store"]
    )
    index = VectorIndex(context["writer"], encoder_bundle)
    generation = index.build(context["store"])["generation_id"]
    index.activate(generation)
    path = context["tmp"] / f"known-core-{version}-{profile}.owcp"
    recovery.checkpoint(context["admin"], context["store"], path)
    # Core7/profile3 add operator authority and event vocabulary; core8 adds
    # collector grants only. No purge event exists in this captured dataset.
    # Preserve real document/vector rows and change only the exact known
    # published migration pair for adoption.
    bundle = json.loads(path.read_bytes())
    published_pair(bundle["payload"], version, profile)
    bundle["sha256"] = digest(recovery._json(bundle["payload"]))
    path.write_bytes(recovery._json(bundle))
    change(context, document, "retire")
    policy = policy_arguments(context["roles"], path)
    restored = context["tmp"] / f"adopted-core-{version}-{profile}"
    result = recovery.restore(
        Database(destination["admin"]), path, bundle["sha256"], restored, **policy
    )
    assert result[f"adopted_core_v{version}"] is True
    assert sum(result[f"adopted_core_v{v}"] for v in recovery.PUBLISHED_PAIRS) == 1
    service = ReadService(Database(destination["reader"]), EvidenceStore(restored, read_only=True))
    assert service.document(neighbour)["integrity"] == "verified"
    with pytest.raises(WorkbenchError, match="DOCUMENT_NOT_FOUND"):
        service.document(document)
    with Database(destination["admin"]).connect() as conn:
        assert conn.execute("SELECT max(version) AS v FROM ow.migrations").fetchone()["v"] == 9
        assert conn.execute("SELECT count(*) AS n FROM ow.remote_operations").fetchone()["n"] == 0
        assert (
            conn.execute("SELECT max(version) AS v FROM ow.retrieval_migrations").fetchone()["v"]
            == 4
        )
        # No profile before 4 recorded exclusions; adoption must not invent any.
        assert (
            conn.execute("SELECT count(*) AS n FROM ow.retrieval_exclusions").fetchone()["n"] == 0
        )
        assert conn.execute(
            "SELECT assertion_id FROM ow.assertions WHERE assertion_id=%s", (assertion,)
        ).fetchone()
        assert conn.execute(
            "SELECT document_id FROM ow.retrieval_members WHERE generation_id=%s "
            "ORDER BY document_id",
            (generation,),
        ).fetchall() == [{"document_id": d} for d in sorted([document, neighbour])]


@pytest.mark.parametrize("tamper", ["changed-plan-digest", "replayed-purge-event"])
def test_exported_purge_history_rejects_tampering_and_duplicate_logical_purge(context, tamper):
    document = retired_document(context)
    result = apply(context, document)
    path = context["tmp"] / "valid-purged-policy.owpolicy"
    lifecycle.export_policy(context["operator"], path)
    payload = json.loads(path.read_bytes())["payload"]
    lifecycle.validate_policy(payload)
    event = next(e for e in payload["tables"]["lifecycle_events"] if e["action"] == "purge")
    if tamper == "changed-plan-digest":
        event["result"]["plan_sha256"] = "f" * 64
    else:
        replay = copy.deepcopy(event)
        replay["operation_id"] = uuid.uuid4().hex
        replay["revision"] += 1
        replay["result"].update(
            operation_id=replay["operation_id"],
            policy_revision_before=result["revision"],
            revision=replay["revision"],
        )
        replay["request_sha256"] = lifecycle.purge_request_sha(
            replay["operation_id"],
            replay["source_id"],
            replay["external_key"],
            replay["actor"],
            replay["rationale"],
            replay["result"]["plan_sha256"],
        )
        payload["tables"]["lifecycle_events"].append(replay)
        payload["control"]["revision"] = replay["revision"]
    before = state(context)
    with pytest.raises(WorkbenchError, match="HISTORY_MISMATCH"):
        lifecycle.validate_policy(payload)
    assert state(context) == before


def test_purge_removes_an_excluded_member_and_records_its_count(context, encoder_bundle):
    if os.environ.get("OW_TEST_RETRIEVAL") != "1":
        pytest.skip("native optional retrieval profile unavailable")
    writer, store = context["writer"], context["store"]
    excluded = writer.ingest(_input("\u2060"), b"zero width", store)
    writer.ingest(_input("vulnerability patch", "neighbour"), b"other", store)
    writer.ingest(_input("storage disk", "third"), b"third", store)
    built = VectorIndex(writer, encoder_bundle).build(store)
    assert built["excluded_documents"] == 1
    change(context, excluded, "retire")
    result = apply(context, excluded)
    assert result["counts"]["retrieval_exclusions"] == 1
    assert result["counts"]["retrieval_members"] == 1
    with context["admin"].connect() as conn:
        assert not conn.execute(
            "SELECT 1 FROM ow.retrieval_exclusions WHERE document_id=%s", (excluded,)
        ).fetchone()


def test_profile3_purge_event_counts_remain_valid():
    """Historical events recorded before retrieval profile 4 have no exclusion count."""
    base = {
        "format": 1,
        "kind": "retired_record_purge",
        "operation_id": "historical",
        "plan_sha256": "a" * 64,
        "dataset_id": str(uuid.uuid4()),
        "source_id": "fixture",
        "external_key": "b" * 64,
        "policy_revision_before": 1,
        "revision": 2,
        "sql_deleted": True,
        "physical_erasure": False,
        "cas_objects_deleted": 0,
        "backup_erasure": False,
    }
    current = {key: 0 for key in lifecycle.PURGE_COUNT_KEYS} | {"documents": 1}
    historical = {k: v for k, v in current.items() if k != "retrieval_exclusions"}
    for counts in (current, historical):
        lifecycle.PurgeResult.model_validate_json(recovery._json({**base, "counts": counts}))
    for counts in ({**current, "unknown": 0}, {k: v for k, v in historical.items() if k != "jobs"}):
        with pytest.raises(ValueError):
            lifecycle.PurgeResult.model_validate_json(recovery._json({**base, "counts": counts}))
