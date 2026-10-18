import asyncio
import concurrent.futures
import copy
import json
import os
import sys
import threading
import uuid
from datetime import UTC, datetime, timedelta, timezone

import psycopg
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from psycopg import sql

from osint_workbench import intelligence, lifecycle, recovery
from osint_workbench.collection import collect
from osint_workbench.contracts import Source
from osint_workbench.database import Database
from osint_workbench.errors import WorkbenchError
from osint_workbench.evidence import EvidenceStore
from osint_workbench.jobs import Jobs
from osint_workbench.service import ReadService
from osint_workbench.vector_index import VectorIndex
from tests.test_recovery import (
    Generator,
    _fixture,
    _input,
    policy_arguments,
)
from tests.test_recovery import (
    destination as destination,
)
from tests.test_workflows import FEED


def change(db, document, action, *, operation=None, **kwargs):
    request = lifecycle.Change(
        action=action,
        document_id=document,
        operation_id=operation or uuid.uuid4().hex,
        actor="fixture-reviewer",
        rationale="Synthetic lifecycle decision",
        **kwargs,
    )
    return lifecycle.apply(db, request)


@pytest.mark.integration
def test_holds_expiry_idempotency_and_permanent_logical_key(databases, tmp_path):
    writer, reader, roles = databases
    operator = Database(roles["lifecycle"])
    store = EvidenceStore(tmp_path / "objects")
    doc = writer.ingest(_input(), b"raw", store)
    first = change(operator, doc, "hold", operation="hold-once", hold_id="hold-one")
    assert first["revision"] == 1 and not first["replayed"]
    assert change(operator, doc, "hold", operation="hold-once", hold_id="hold-one")["replayed"]
    with pytest.raises(WorkbenchError, match="OPERATION_CONFLICT"):
        change(operator, doc, "hold", operation="hold-once", hold_id="other")
    change(operator, doc, "hold", hold_id="hold-two")
    with pytest.raises(WorkbenchError, match="DOCUMENT_HELD"):
        change(operator, doc, "retire")
    change(
        operator,
        doc,
        "retention",
        retention_class="short-lived",
        retain_until=datetime.now(UTC) - timedelta(seconds=1),
    )
    assert reader.search("storage") == []
    with pytest.raises(WorkbenchError, match="NOT_FOUND"):
        reader.document(doc)
    assert len(lifecycle.inspect(operator, doc)["holds"]) == 2
    change(operator, doc, "release", hold_id="hold-one")
    with pytest.raises(WorkbenchError, match="DOCUMENT_HELD"):
        change(operator, doc, "retire")
    # A hold preserves records and never extends serving authorization.
    with operator.connect() as conn:
        assert conn.execute("SELECT body FROM ow.documents WHERE document_id=%s", (doc,)).fetchone()
    change(operator, doc, "release", hold_id="hold-two")
    assert reader.search("storage") == []
    change(operator, doc, "retire")
    with pytest.raises(WorkbenchError, match="DOCUMENT_RETIRED"):
        change(operator, doc, "retention", retention_class="manual")
    with pytest.raises(WorkbenchError, match="RETIRED_OR_EXPIRED"):
        writer.ingest(_input("New content for retired logical identity."), b"new", store)
    with pytest.raises(WorkbenchError, match="RETIRED_OR_EXPIRED"):
        writer.enqueue("document.accepted", "new-operation", {"document_id": doc})
    receipt = lifecycle.export_policy(operator, tmp_path / "policy.owpolicy")
    assert receipt["revision"] == 6
    assert reader.status()["schema_version"] == 8
    assert reader.status()["lifecycle"]["retired_items"] == 1


@pytest.mark.integration
def test_retirement_revokes_reader_and_fences_all_versions(databases, tmp_path):
    writer, reader, roles = databases
    operator = Database(roles["lifecycle"])
    store = EvidenceStore(tmp_path / "objects")
    old = writer.ingest(_input("Previous storage evidence."), b"old", store)
    doc, assertion, brief, unrelated_pending, unrelated_running, _ = _fixture(writer, store)
    pending = writer.enqueue("fixture-document", "pending", {"document_id": doc})
    leased = writer.enqueue("fixture-doc-running", "leased", {"document_id": old})
    fence = Jobs(writer).claim(kinds=["fixture-doc-running"])["fence"]
    snapshot = reader.document(doc)["snapshot_id"]
    other = writer.ingest(_input("vulnerability patch", external="other"), b"other", store)
    service = ReadService(reader, EvidenceStore(store.root, read_only=True))
    change(operator, doc, "retire")
    assert reader.search("storage") == []
    assert reader.document(other)["document_id"] == other
    for identifier in (doc, old):
        with pytest.raises(WorkbenchError, match="DOCUMENT_NOT_FOUND"):
            service.document(identifier)
    with pytest.raises(WorkbenchError, match="SNAPSHOT_NOT_FOUND"):
        service.evidence(snapshot)
    with pytest.raises(WorkbenchError, match="BRIEFING_NOT_FOUND"):
        service.briefing(brief)
    assert service.assertions()["results"] == []
    with pytest.raises(WorkbenchError, match="ASSERTION_NOT_CURRENT"):
        intelligence.review(writer, assertion, "accept", "fixture-reviewer", "Retired")
    for job in (pending, leased):
        assert Jobs(writer).inspect(job)["status"] == "cancelled"
    assert Jobs(writer).inspect(unrelated_pending)["status"] == "ready"
    assert Jobs(writer).inspect(unrelated_running)["status"] == "running"
    with writer.connect() as conn:
        assert (
            conn.execute(
                "SELECT fence FROM ow.job_events WHERE job_id=%s AND event='cancelled'", (leased,)
            ).fetchone()["fence"]
            == fence
        )
    with pytest.raises(WorkbenchError, match="STALE_JOB_LEASE"):
        Jobs(writer).finish(leased, fence, {})
    for table in (
        "documents",
        "snapshots",
        "chunks",
        "assertions",
        "briefings",
        "lifecycle_events",
        "lifecycle_holds",
        "lifecycle_tombstones",
    ):
        with reader.connect() as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(sql.SQL("SELECT * FROM ow.{}").format(sql.Identifier(table)))
    for table in ("visible_documents", "visible_chunks", "visible_assertions", "visible_briefings"):
        with reader.connect() as conn:
            rows = conn.execute(
                sql.SQL("SELECT * FROM ow.{}").format(sql.Identifier(table))
            ).fetchall()
            assert doc not in json.dumps(rows, default=str)
            assert "Straße storage" not in json.dumps(rows, default=str)
    reader.validate_reader()
    with pytest.raises(WorkbenchError, match="OPERATOR_REQUIRED"):
        change(writer, other, "retire")
    with writer.connect() as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute("DELETE FROM ow.lifecycle_tombstones")

    async def roundtrip():
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "osint_workbench.cli", "mcp"],
            env={
                **os.environ,
                "OW_READER_DSN": roles["reader"],
                "OW_EVIDENCE_ROOT": str(store.root),
            },
        )
        async with stdio_client(params) as (read, write), ClientSession(read, write) as client:
            await client.initialize()
            for tool, args in (
                ("get_document", {"document_id": doc}),
                ("get_evidence", {"snapshot_id": snapshot}),
                ("get_briefing", {"briefing_id": brief}),
            ):
                result = await client.call_tool(tool, args)
                assert result.is_error and "Straße storage" not in result.content[0].text
            tools = await client.list_tools()
            assert len(tools.tools) == 7 and not any("retire" in t.name for t in tools.tools)

    asyncio.run(roundtrip())


@pytest.mark.integration
def test_native_vectors_and_rerank_cannot_resurrect_retired_records(
    databases, tmp_path, encoder_bundle, reranker_bundle
):
    if os.environ.get("OW_TEST_RETRIEVAL") != "1":
        pytest.skip("native optional retrieval profile unavailable")
    writer, reader, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    doc = writer.ingest(_input("storage disk"), b"raw", store)
    other = writer.ingest(_input("vulnerability patch", external="other"), b"other", store)
    index = VectorIndex(writer, encoder_bundle)
    generation = index.build(store)["generation_id"]
    index.activate(generation)
    service = ReadService(
        reader,
        EvidenceStore(store.root, read_only=True),
        encoder=encoder_bundle,
        reranker=reranker_bundle,
    )
    change(Database(roles["lifecycle"]), doc, "retire")
    found = service.search("storage")
    assert found["degraded"] and {r["document_id"] for r in found["results"]} == {other}
    with pytest.raises(WorkbenchError, match="STALE_RETRIEVAL_GENERATION"):
        index.activate(generation)
    for table in ("retrieval_vectors", "retrieval_members"):
        with reader.connect() as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(sql.SQL("SELECT * FROM ow.{}").format(sql.Identifier(table)))
    with reader.connect() as conn:
        assert not conn.execute(
            "SELECT 1 FROM ow.visible_retrieval_vectors WHERE document_id=%s", (doc,)
        ).fetchone()


@pytest.mark.integration
def test_old_checkpoint_reconciles_new_tombstones_before_reads(databases, destination, tmp_path):
    writer, reader, roles = databases
    operator = Database(roles["lifecycle"])
    store = EvidenceStore(tmp_path / "objects")
    doc, _, brief, _, _, _ = _fixture(writer, store)
    held = writer.ingest(_input("vulnerability patch", external="held"), b"held", store)
    path = tmp_path / "old.owcp"
    receipt = recovery.checkpoint(Database(roles["admin"]), store, path)
    change(operator, held, "hold", hold_id="preserved-hold")
    change(operator, doc, "retire")
    policy = policy_arguments(roles, path)
    result = recovery.restore(
        Database(destination["admin"]), path, receipt["sha256"], tmp_path / "restored", **policy
    )
    assert result["policy_revision"] == 2
    recovered = ReadService(
        Database(destination["reader"]), EvidenceStore(tmp_path / "restored", read_only=True)
    )
    assert recovered.search("storage")["results"] == []
    with pytest.raises(WorkbenchError, match="NOT_FOUND"):
        recovered.document(doc)
    with pytest.raises(WorkbenchError, match="NOT_FOUND"):
        recovered.briefing(brief)
    assert recovered.document(held)["integrity"] == "verified"
    with pytest.raises(WorkbenchError, match="DOCUMENT_HELD"):
        change(Database(destination["lifecycle"]), held, "retire")
    with pytest.raises(WorkbenchError, match="RETIRED_OR_EXPIRED"):
        Database(destination["writer"]).ingest(
            _input(), b"raw", EvidenceStore(tmp_path / "restored")
        )
    assert reader.search("storage") == []


@pytest.mark.integration
@pytest.mark.parametrize("failure", ["stale", "wrong-dataset", "missing-tombstone", "corrupt"])
def test_restore_refuses_untrusted_or_incomplete_policy(databases, destination, tmp_path, failure):
    writer, _, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    doc = writer.ingest(_input(), b"raw", store)
    path = tmp_path / "checkpoint.owcp"
    receipt = recovery.checkpoint(Database(roles["admin"]), store, path)
    change(Database(roles["lifecycle"]), doc, "retire")
    policy = policy_arguments(roles, path)
    bundle = json.loads(policy["policy_path"].read_bytes())
    if failure == "stale":
        policy["minimum_revision"] = 2
    elif failure == "wrong-dataset":
        bundle["payload"]["control"]["dataset_id"] = str(uuid.uuid4())
    elif failure == "missing-tombstone":
        bundle["payload"]["tables"]["lifecycle_tombstones"] = []
    else:
        policy["policy_sha"] = "0" * 64
    if failure in {"wrong-dataset", "missing-tombstone"}:
        bundle["sha256"] = recovery.digest(recovery._json(bundle["payload"]))
        policy["policy_sha"] = bundle["sha256"]
        policy["policy_path"].write_bytes(recovery._json(bundle))
    with pytest.raises(WorkbenchError):
        recovery.restore(
            Database(destination["admin"]), path, receipt["sha256"], tmp_path / "restored", **policy
        )
    assert not (tmp_path / "restored").exists()
    with Database(destination["admin"]).connect() as conn:
        assert conn.execute("SELECT count(*) AS n FROM ow.documents").fetchone()["n"] == 0


@pytest.mark.integration
def test_collector_reports_suppression_and_accepts_other_entries(databases, tmp_path, monkeypatch):
    writer, reader, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    source = Source(source_id="fixture", url="https://example.invalid/feed")
    monkeypatch.setattr("osint_workbench.collection.fetch", lambda url: FEED)
    first = collect(source, writer, store)
    doc = first["document_ids"][0]
    change(Database(roles["lifecycle"]), doc, "retire")
    next_run = collect(source, writer, store)
    assert next_run["status"] == "success" and next_run["suppressed_documents"] == 1
    assert next_run["documents"] == 1 and doc not in next_run["document_ids"]
    with Database(roles["admin"]).connect() as conn:
        row = conn.execute(
            "SELECT accepted_documents,suppressed_documents FROM ow.collection_runs "
            "WHERE run_id=%s",
            (next_run["run_id"],),
        ).fetchone()
        assert row == {"accepted_documents": 1, "suppressed_documents": 1}
    assert not reader.search("First") and reader.search("Second")


@pytest.mark.integration
def test_retirement_waits_for_admitted_work_and_late_repeatable_read_is_fresh(
    databases, tmp_path, monkeypatch
):
    writer, reader, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    doc = writer.ingest(_input(), b"raw", store)
    entered, release = threading.Event(), threading.Event()
    original = lifecycle._cancel

    def blocked(conn, source, external):
        result = original(conn, source, external)
        entered.set()
        assert release.wait(10)
        return result

    monkeypatch.setattr(lifecycle, "_cancel", blocked)

    def fresh_read():
        with writer.connect() as conn:
            conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            return bool(
                conn.execute(
                    "SELECT 1 FROM ow.visible_documents WHERE document_id=%s", (doc,)
                ).fetchone()
            )

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        retirement = pool.submit(change, Database(roles["lifecycle"]), doc, "retire")
        assert entered.wait(10)
        late = pool.submit(fresh_read)
        try:
            with pytest.raises(concurrent.futures.TimeoutError):
                late.result(timeout=0.2)
        finally:
            release.set()
        assert retirement.result(timeout=10)["action"] == "retire"
        assert late.result(timeout=10) is False
    assert reader.search("storage") == []


@pytest.mark.integration
def test_security_barrier_excludes_hidden_rows_before_user_predicates(databases, tmp_path):
    writer, reader, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    doc = writer.ingest(_input(), b"raw", store)
    change(Database(roles["lifecycle"]), doc, "retire")
    with psycopg.connect(roles["admin"]) as conn:
        conn.execute("""CREATE FUNCTION public.ow_fixture_leak(value text) RETURNS boolean
            LANGUAGE plpgsql VOLATILE COST 0.0001 AS $$ BEGIN
            RAISE EXCEPTION 'hidden row reached predicate'; END $$""")
    try:
        with reader.connect() as conn:
            assert (
                conn.execute(
                    "SELECT document_id FROM ow.visible_documents "
                    "WHERE public.ow_fixture_leak(body)"
                ).fetchall()
                == []
            )
    finally:
        with psycopg.connect(roles["admin"]) as conn:
            conn.execute("DROP FUNCTION public.ow_fixture_leak(text)")


def test_policy_revision_is_bounded_before_allocating_history():
    policy = {
        "format": 1,
        "kind": "lifecycle_policy",
        "control": {"singleton": True, "dataset_id": str(uuid.uuid4()), "revision": 10**18},
        "tables": {n: [] for n in lifecycle.POLICY_TABLES},
    }
    with pytest.raises(WorkbenchError, match="^INVALID_LIFECYCLE_POLICY$"):
        lifecycle.validate_policy(policy)
    bad = copy.deepcopy(policy)
    bad["control"]["revision"] = 0
    bad["tables"]["lifecycle_items"] = [
        {
            "source_id": "fixture",
            "external_key": "a" * 64,
            "retention_class": "unlogged",
            "retain_until": None,
        }
    ]
    with pytest.raises(WorkbenchError, match="HISTORY_MISMATCH"):
        lifecycle.validate_policy(bad)


def test_policy_history_compares_timestamp_instants_not_rendered_offsets():
    request = lifecycle.Change(
        action="hold",
        document_id="b" * 64,
        operation_id="hold-op",
        actor="fixture-reviewer",
        rationale="Synthetic hold",
        hold_id="hold-one",
    )
    instant = datetime(2026, 1, 1, tzinfo=UTC)
    key = {"source_id": "fixture", "external_key": "a" * 64}
    control = {"singleton": True, "dataset_id": str(uuid.uuid4()), "revision": 1}
    result = {
        "operation_id": "hold-op",
        "document_id": "b" * 64,
        "action": "hold",
        "revision": 1,
        "cancelled_jobs": 0,
        "physical_erasure": False,
        "retention_class": None,
        "retain_until": None,
        "hold_id": "hold-one",
    }
    tables = {
        "lifecycle_items": [{**key, "retention_class": "manual", "retain_until": None}],
        "lifecycle_holds": [
            {**key, "hold_id": "hold-one", "placed_at": instant.isoformat(), "released_at": None}
        ],
        "lifecycle_tombstones": [],
        "lifecycle_events": [
            {
                **key,
                "operation_id": "hold-op",
                "request_sha256": recovery.digest(request.model_dump_json().encode()),
                "revision": 1,
                "action": "hold",
                "actor": "fixture-reviewer",
                "rationale": "Synthetic hold",
                "result": result,
                "recorded_at": instant.isoformat(),
            }
        ],
    }
    payload = {
        "format": 1,
        "kind": "lifecycle_policy",
        "control": control,
        "tables": copy.deepcopy(tables),
    }
    for name, field in (("lifecycle_holds", "placed_at"), ("lifecycle_events", "recorded_at")):
        payload["tables"][name][0][field] = instant.astimezone(
            timezone(timedelta(hours=2))
        ).isoformat()
    baseline = {"lifecycle_control": [control], **tables}
    lifecycle.reconcile_policy(baseline, payload, 1)
    payload["tables"]["lifecycle_holds"][0]["placed_at"] = (
        instant + timedelta(seconds=1)
    ).isoformat()
    with pytest.raises(WorkbenchError, match="HISTORY_MISMATCH"):
        lifecycle.reconcile_policy(baseline, payload, 1)


@pytest.mark.integration
def test_clock_expiry_blocks_new_model_dispatch_without_a_sweeper(databases, tmp_path):
    writer, reader, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    doc = writer.ingest(_input(), b"raw", store)

    class Recording(Generator):
        calls = 0

        def generate(self, prompt, schema):
            self.calls += 1
            return super().generate(prompt, schema)

    generator = Recording()
    job = intelligence.enqueue(writer, generator, doc)
    with writer.connect() as conn:
        until = conn.execute("SELECT clock_timestamp()+interval '2 seconds' AS t").fetchone()["t"]
    change(
        Database(roles["lifecycle"]),
        doc,
        "retention",
        retention_class="short-lived",
        retain_until=until,
    )
    assert reader.document(doc)["document_id"] == doc
    with writer.connect() as conn:
        conn.execute(
            "SELECT pg_sleep(greatest(0,extract(epoch FROM %s-clock_timestamp()))+0.05)", (until,)
        )
    assert reader.search("storage") == []
    assert intelligence.enrich_once(writer, store, generator)["status"] == "failed"
    assert generator.calls == 0 and Jobs(writer).inspect(job)["status"] == "failed"


@pytest.mark.integration
@pytest.mark.parametrize("privilege", ["SELECT", "SELECT(body)", "UPDATE(title)"])
def test_reader_rejects_accidental_raw_select_grants(databases, privilege):
    _, reader, roles = databases
    with psycopg.connect(roles["admin"]) as conn:
        conn.execute(
            sql.SQL("GRANT {} ON ow.documents TO ow_test_reader").format(sql.SQL(privilege))
        )
    try:
        with pytest.raises(WorkbenchError, match="UNSAFE_READER_IDENTITY"):
            reader.validate_reader()
    finally:
        with psycopg.connect(roles["admin"]) as conn:
            conn.execute(
                sql.SQL("REVOKE {} ON ow.documents FROM ow_test_reader").format(sql.SQL(privilege))
            )
    reader.validate_reader()


@pytest.mark.integration
def test_retirement_waits_for_already_admitted_transaction(databases, tmp_path):
    writer, _, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    doc = writer.ingest(_input(), b"raw", store)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        with writer.connect() as conn:
            assert conn.execute(
                "SELECT 1 FROM ow.visible_documents WHERE document_id=%s", (doc,)
            ).fetchone()
            future = pool.submit(change, Database(roles["lifecycle"]), doc, "retire")
            with pytest.raises(concurrent.futures.TimeoutError):
                future.result(timeout=0.2)
            assert conn.execute(
                "SELECT 1 FROM ow.visible_documents WHERE document_id=%s", (doc,)
            ).fetchone()
        assert future.result(timeout=10)["action"] == "retire"


@pytest.mark.integration
def test_policy_roundtrip_ignores_role_timezone_defaults(databases, destination, tmp_path):
    writer, _, roles = databases
    operator = Database(roles["lifecycle"])
    store = EvidenceStore(tmp_path / "objects")
    doc = writer.ingest(_input(), b"raw", store)
    with psycopg.connect(roles["admin"]) as conn:
        conn.execute("ALTER ROLE ow_test_lifecycle SET timezone='Europe/Vienna'")
    try:
        with operator.connect() as conn:
            assert (
                conn.execute("SELECT current_setting('TimeZone') AS zone").fetchone()["zone"]
                == "UTC"
            )
        change(operator, doc, "hold", hold_id="timezone-hold")
        path = tmp_path / "checkpoint.owcp"
        receipt = recovery.checkpoint(Database(roles["admin"]), store, path)
        policy = policy_arguments({"admin": roles["lifecycle"]}, path)
        # An older valid producer may render the same instants with an offset.
        # Preserve the original request/result encoding; only row timestamps vary.
        bundle = json.loads(policy["policy_path"].read_bytes())
        for name, field in (("lifecycle_holds", "placed_at"), ("lifecycle_events", "recorded_at")):
            for row in bundle["payload"]["tables"][name]:
                row[field] = (
                    datetime.fromisoformat(row[field])
                    .astimezone(timezone(timedelta(hours=2)))
                    .isoformat()
                )
        bundle["sha256"] = recovery.digest(recovery._json(bundle["payload"]))
        policy["policy_sha"] = bundle["sha256"]
        policy["policy_path"].write_bytes(recovery._json(bundle))
        result = recovery.restore(
            Database(destination["admin"]), path, receipt["sha256"], tmp_path / "restored", **policy
        )
        assert result["policy_revision"] == 1
    finally:
        with psycopg.connect(roles["admin"]) as conn:
            conn.execute("ALTER ROLE ow_test_lifecycle RESET timezone")
