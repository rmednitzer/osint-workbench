"""Actual runtime principals must not acquire sibling mutation authority."""

from decimal import Decimal

import psycopg
import pytest

from osint_workbench import cloud
from osint_workbench.database import Database
from osint_workbench.errors import WorkbenchError
from osint_workbench.jobs import Jobs
from osint_workbench.worker import run_once
from tests.test_cloud import policy, route
from tests.test_intelligence import setup

pytestmark = pytest.mark.integration


def test_chunk_login_executes_but_cannot_mutate_sibling_or_terminal_jobs(databases, tmp_path):
    writer, _, roles, store, _ = setup(databases, tmp_path)
    chunk = Database(roles["chunk"])
    chunk.validate_worker("ow_chunk_worker")
    sibling = writer.enqueue("document.enrich/" + "a" * 64, "sibling", {"fixture": True})
    with chunk.connect() as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("UPDATE ow.jobs SET status='cancelled' WHERE job_id=%s", (sibling,))
    with chunk.connect() as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("UPDATE ow.remote_operations SET status='released'")
    assert run_once(chunk, store)["status"] == "succeeded"
    with chunk.connect() as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("UPDATE ow.jobs SET status='ready' WHERE kind='document.accepted'")
    with pytest.raises(WorkbenchError, match="^UNSAFE_WORKER_IDENTITY$"):
        writer.validate_worker("ow_chunk_worker")


def test_enrichment_kind_registration_separates_local_and_remote_jobs(databases, tmp_path):
    writer, _, roles, _, _ = setup(databases, tmp_path)
    local_kind, remote_kind = "document.enrich/" + "a" * 64, "document.enrich/" + "b" * 64
    with psycopg.connect(roles["admin"]) as conn:
        conn.execute(
            "INSERT INTO ow.worker_kinds VALUES ('ow_test_local_enricher',%s,'local') "
            "ON CONFLICT (database_principal) DO UPDATE SET kind=excluded.kind",
            (local_kind,),
        )
    local = Database(roles["local_enricher"])
    local.validate_worker("ow_local_enricher")
    writer.enqueue(local_kind, "local", {})
    remote = writer.enqueue(remote_kind, "remote", {})
    claimed = Jobs(local).claim(kinds=[local_kind])
    assert claimed["kind"] == local_kind
    with local.connect() as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("UPDATE ow.jobs SET status='failed' WHERE job_id=%s", (remote,))
    with local.connect() as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("UPDATE ow.worker_kinds SET kind=%s", (remote_kind,))
    with local.connect() as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("UPDATE ow.remote_operations SET status='released'")


def test_dispatcher_cannot_release_another_principals_attempt(databases, tmp_path):
    writer, _, roles, _, _ = setup(databases, tmp_path)
    parsed, sha = policy(route())
    led = cloud.Ledger(writer)
    attempt, _, _ = led.record(
        operation_id="owner-test",
        route=parsed.routes[0],
        policy_sha=sha,
        task="structured_extraction",
        data_class="public",
        decision="conforming",
        reason=None,
        packet_sha="d" * 64,
        reserve=Decimal("0.01"),
    )
    led.transition(attempt, "reserved", "dispatched")
    dispatcher = Database(roles["dispatcher"])
    dispatcher.validate_worker("ow_dispatcher")
    with dispatcher.connect() as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(
                "UPDATE ow.remote_operations SET status='released' WHERE attempt_id=%s", (attempt,)
            )
    assert cloud.exposure(dispatcher, "fixture-eu", "EUR") == Decimal("0.01")


def test_reported_usage_cannot_reopen_capacity_before_settlement(databases, tmp_path):
    writer, _, _, _, _ = setup(databases, tmp_path)
    parsed, sha = policy(route(cap="0.01"))
    led = cloud.Ledger(writer)
    args = dict(
        route=parsed.routes[0],
        policy_sha=sha,
        task="structured_extraction",
        data_class="public",
        decision="conforming",
        reason=None,
        packet_sha="d" * 64,
        reserve=Decimal("0.01"),
    )
    attempt, decision, _ = led.record(operation_id="first", **args)
    assert decision == "conforming"
    led.transition(attempt, "reserved", "dispatched")
    led.transition(
        attempt,
        "dispatched",
        "completed",
        usage="reported",
        input_tokens=1,
        output_tokens=0,
        estimated_cost=Decimal("0.000000001"),
    )
    _, decision, reason = led.record(operation_id="next", **args)
    assert (decision, reason) == ("denied", "BUDGET_EXHAUSTED")
