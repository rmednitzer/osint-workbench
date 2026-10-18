"""Operator settlement of remote attempts: authority, evidence, finality and races.

Settlements are operator assertions bound to private provider evidence by
digest. These tests use synthetic evidence files; they are not invoice evidence.
"""

import hashlib
import json
import os
import threading
import time
from decimal import Decimal

import psycopg
import pytest

from osint_workbench import cli, cloud, recovery
from osint_workbench import intelligence as intel
from osint_workbench.database import Database
from osint_workbench.errors import WorkbenchError
from tests.test_cloud import NoEgress, completion, governed, ledger, policy, proposals, route
from tests.test_cloud import certificates as certificates
from tests.test_intelligence import claim, setup
from tests.test_recovery import destination as destination
from tests.test_recovery import policy_arguments, published_pair
from tests.tls_fixture import tls_peer

SCHEMA = intel.Proposals.model_json_schema()


def settlement(attempt, **changes):
    value = {
        "attempt_id": str(attempt),
        "basis": "invoice",
        "cost": "0.000500000",
        "currency": "EUR",
        "evidence_sha256": "e" * 64,
        "actor": "synthetic-operator",
        "rationale": "Synthetic provider invoice line for the attempt.",
    }
    return cloud.Settlement.model_validate_json(json.dumps({**value, **changes}))


def attempt(writer, status="outcome_unknown", *, operation="op-settle", parsed=None):
    parsed, sha = parsed or policy(route())
    led = cloud.Ledger(writer)
    identifier, decision, _ = led.record(
        operation_id=operation,
        route=parsed.routes[0],
        policy_sha=sha,
        task="structured_extraction",
        data_class="public",
        decision="conforming",
        reason=None,
        packet_sha="d" * 64,
        reserve=Decimal("0.002000000"),
    )
    assert decision == "conforming"
    if status != "reserved":
        led.transition(identifier, "reserved", "dispatched")
    if status not in ("reserved", "dispatched"):
        led.transition(identifier, "dispatched", status, error_code="SYNTHETIC")
    return identifier


def age(roles, identifier, minutes=11):
    # Fixture-only clock movement: replica mode skips the transition trigger.
    with psycopg.connect(roles["admin"]) as conn:
        conn.execute("SET session_replication_role = replica")
        conn.execute(
            "UPDATE ow.remote_operations SET updated_at=updated_at-%s*interval '1 minute',"
            "created_at=created_at-%s*interval '1 minute' WHERE attempt_id=%s",
            (minutes, minutes, identifier),
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"basis": "not_dispatched", "cost": "0", "evidence_sha256": "e" * 64},
        {"basis": "not_dispatched", "cost": "0.1", "evidence_sha256": None},
        {"basis": "invoice", "evidence_sha256": None},
        {"cost": 0.5},
        {"cost": "1e-3"},
        {"cost": "-1"},
        {"cost": "1000000"},
        {"currency": "eur"},
        {"actor": ""},
        {"rationale": "x" * 2001},
        {"basis": "estimate"},
    ],
)
def test_settlement_requires_exact_money_and_bound_evidence(changes):
    with pytest.raises(ValueError):
        settlement("00000000-0000-4000-8000-000000000001", **changes)
    assert settlement(
        "00000000-0000-4000-8000-000000000001",
        basis="not_dispatched",
        cost="0",
        evidence_sha256=None,
    ).cost == Decimal(0)


def test_evidence_is_a_bounded_regular_file_never_a_link(tmp_path, monkeypatch):
    evidence = tmp_path / "invoice.synthetic"
    evidence.write_bytes(b"synthetic invoice line")
    assert cloud.evidence_digest(evidence) == hashlib.sha256(b"synthetic invoice line").hexdigest()
    link = tmp_path / "link"
    link.symlink_to(evidence)
    with pytest.raises(WorkbenchError, match="^SETTLEMENT_EVIDENCE_UNAVAILABLE$"):
        cloud.evidence_digest(link)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(WorkbenchError, match="^SETTLEMENT_EVIDENCE_INVALID$"):
        cloud.evidence_digest(fifo)
    empty = tmp_path / "empty"
    empty.write_bytes(b"")
    with pytest.raises(WorkbenchError, match="^SETTLEMENT_EVIDENCE_INVALID$"):
        cloud.evidence_digest(empty)
    monkeypatch.setattr(cloud, "MAX_EVIDENCE_BYTES", 4)
    with pytest.raises(WorkbenchError, match="^SETTLEMENT_EVIDENCE_INVALID$"):
        cloud.evidence_digest(evidence)
    with pytest.raises(WorkbenchError, match="^SETTLEMENT_EVIDENCE_UNAVAILABLE$"):
        cloud.evidence_digest(tmp_path / "missing")


@pytest.mark.integration
def test_unknown_outcome_settles_once_and_releases_replay(
    databases, tmp_path, monkeypatch, certificates
):
    writer, reader, roles, store, doc = setup(databases, tmp_path)
    accounting = Database(roles["accounting"])
    generator = governed(writer)
    operation = {"operation_id": "op-u", "task": "structured_extraction", "data_class": "public"}
    with tls_peer(monkeypatch, certificates, wire=b""):
        with pytest.raises(WorkbenchError, match="^REMOTE_OUTCOME_UNKNOWN$"):
            generator.generate("Synthetic prompt", SCHEMA, operation=operation)
    (row,) = ledger(roles)
    listed = cloud.unsettled(accounting)
    assert [a["attempt_id"] for a in listed["attempts"]] == [str(row["attempt_id"])]
    assert listed["attempts"][0]["in_flight"] is False and listed["truncated"] is False
    # Outcome-unknown is terminal, so it can be settled immediately.
    request = settlement(row["attempt_id"])
    receipt = cloud.settle(accounting, request)
    assert receipt["replayed"] is False and receipt["settled_cost"] == "0.000500000"
    assert receipt["status"] == "outcome_unknown" and receipt["settled_at"]
    assert cloud.exposure(writer, "fixture-eu", "EUR") == Decimal("0.000500000")
    assert cloud.unsettled(accounting)["attempts"] == []
    # Exact retry returns the receipt; any change is a conflict, never an overwrite.
    assert cloud.settle(accounting, request) == {**receipt, "replayed": True}
    for change in ({"cost": "0.000400000"}, {"evidence_sha256": "f" * 64}, {"actor": "other"}):
        with pytest.raises(WorkbenchError, match="^SETTLEMENT_CONFLICT$"):
            cloud.settle(accounting, settlement(row["attempt_id"], **change))
    # The resolved operation may be attempted again under a new reservation.
    with tls_peer(monkeypatch, certificates, wire=completion(proposals(claim()))) as peer:
        assert generator.generate("Synthetic prompt", SCHEMA, operation=operation)["output"]
    assert peer.connections == 1
    rows = ledger(roles)
    assert [r["status"] for r in rows] == ["outcome_unknown", "completed"]
    assert rows[0]["settled_cost"] == Decimal("0.000500000") and rows[1]["settled_cost"] is None


@pytest.mark.integration
def test_settlement_above_the_reservation_counts_and_exhausts_the_cap(databases, tmp_path):
    writer, reader, roles, store, doc = setup(databases, tmp_path)
    accounting = Database(roles["accounting"])
    parsed = policy(route(cap="1.00"))
    identifier = attempt(writer, "failed", parsed=parsed)
    # An invoice can exceed the declared-price estimate; the ledger records it.
    cloud.settle(accounting, settlement(identifier, cost="1.250000000"))
    assert cloud.exposure(writer, "fixture-eu", "EUR") == Decimal("1.250000000")
    assert cloud.Ledger(writer).record(
        operation_id="after-overrun",
        route=parsed[0].routes[0],
        policy_sha=parsed[1],
        task="structured_extraction",
        data_class="public",
        decision="conforming",
        reason=None,
        packet_sha="d" * 64,
        reserve=Decimal("0.000000001"),
    )[1:] == ("denied", "BUDGET_EXHAUSTED")


@pytest.mark.integration
def test_settlement_refuses_wrong_scope_currency_and_basis(databases, tmp_path):
    writer, reader, roles, store, doc = setup(databases, tmp_path)
    accounting = Database(roles["accounting"])
    unknown = attempt(writer, "outcome_unknown", operation="a")
    released = attempt(writer, "released", operation="b")
    with pytest.raises(WorkbenchError, match="^SETTLEMENT_NOT_REQUIRED$"):
        cloud.settle(accounting, settlement(released))
    with pytest.raises(WorkbenchError, match="^SETTLEMENT_CURRENCY_MISMATCH$"):
        cloud.settle(accounting, settlement(unknown, currency="USD"))
    # A dispatched attempt may have been billed; it needs provider evidence.
    with pytest.raises(WorkbenchError, match="^SETTLEMENT_BASIS_INVALID$"):
        cloud.settle(
            accounting, settlement(unknown, basis="not_dispatched", cost="0", evidence_sha256=None)
        )
    with pytest.raises(WorkbenchError, match="^ATTEMPT_NOT_FOUND$"):
        cloud.settle(accounting, settlement("00000000-0000-4000-8000-000000000009"))
    assert all(r["settlement_basis"] is None for r in ledger(roles))


@pytest.mark.integration
@pytest.mark.parametrize("status", ["reserved", "dispatched"])
def test_live_attempts_are_refused_until_stale_in_code_and_database(databases, tmp_path, status):
    writer, reader, roles, store, doc = setup(databases, tmp_path)
    accounting = Database(roles["accounting"])
    identifier = attempt(writer, status)
    assert cloud.unsettled(accounting)["attempts"][0]["in_flight"] is True
    with pytest.raises(WorkbenchError, match="^SETTLEMENT_IN_FLIGHT$"):
        cloud.settle(accounting, settlement(identifier))
    # The database refuses the same settlement without the application check.
    with psycopg.connect(roles["accounting"]) as conn:
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(
                "UPDATE ow.remote_operations SET settlement_basis='invoice',settled_cost=0,"
                "settlement_evidence_sha256=%s,settled_by='x',settlement_rationale='y' "
                "WHERE attempt_id=%s",
                ("e" * 64, identifier),
            )
    age(roles, identifier)
    assert cloud.settle(accounting, settlement(identifier))["status"] == status


@pytest.mark.integration
def test_stale_reservation_settles_at_zero_and_can_never_dispatch(databases, tmp_path):
    writer, reader, roles, store, doc = setup(databases, tmp_path)
    accounting = Database(roles["accounting"])
    identifier = attempt(writer, "reserved")
    age(roles, identifier)
    assert cloud.exposure(writer, "fixture-eu", "EUR") == Decimal("0.002000000")
    receipt = cloud.settle(
        accounting, settlement(identifier, basis="not_dispatched", cost="0", evidence_sha256=None)
    )
    assert receipt["settlement_basis"] == "not_dispatched"
    assert cloud.exposure(writer, "fixture-eu", "EUR") == 0
    # A worker that resumes after settlement cannot move the attempt to dispatch.
    with pytest.raises(WorkbenchError, match="^INVALID_LEDGER_TRANSITION$"):
        cloud.Ledger(writer).transition(identifier, "reserved", "dispatched")
    (row,) = ledger(roles)
    assert row["status"] == "reserved" and row["settlement_basis"] == "not_dispatched"


@pytest.mark.integration
@pytest.mark.parametrize("isolation", ["read committed", "repeatable read"])
def test_settlement_and_late_outcome_serialize_on_the_attempt_row(databases, tmp_path, isolation):
    writer, reader, roles, store, doc = setup(databases, tmp_path)
    identifier = attempt(writer, "dispatched")
    age(roles, identifier)
    outcome = []
    settling = psycopg.connect(roles["accounting"])
    try:
        settling.execute(
            "UPDATE ow.remote_operations SET settlement_basis='provider_statement',"
            "settled_cost=0,settlement_evidence_sha256=%s,settled_by='synthetic',"
            "settlement_rationale='Synthetic statement' WHERE attempt_id=%s",
            ("e" * 64, identifier),
        )

        def late_worker():
            with psycopg.connect(roles["writer"]) as conn:
                conn.execute("SET TRANSACTION ISOLATION LEVEL " + isolation.upper())
                try:
                    conn.execute(
                        "UPDATE ow.remote_operations SET status='completed',usage='missing',"
                        "response_sha256=%s WHERE attempt_id=%s AND status='dispatched'",
                        ("a" * 64, identifier),
                    )
                    outcome.append("updated")
                except (psycopg.errors.CheckViolation, psycopg.errors.SerializationFailure) as exc:
                    outcome.append(type(exc).__name__)

        thread = threading.Thread(target=late_worker)
        thread.start()
        time.sleep(0.5)
        assert thread.is_alive()  # Blocked on the settlement's row lock.
        settling.commit()
        thread.join(timeout=10)
    finally:
        settling.close()
    expected = "CheckViolation" if isolation == "read committed" else "SerializationFailure"
    assert outcome == [expected]
    (row,) = ledger(roles)
    assert row["status"] == "dispatched" and row["settlement_basis"] == "provider_statement"


@pytest.mark.integration
def test_settlement_authority_is_separate_from_the_writer(databases, tmp_path):
    writer, reader, roles, store, doc = setup(databases, tmp_path)
    identifier = attempt(writer, "outcome_unknown")
    for name in ("writer", "reader", "collector", "lifecycle"):
        with pytest.raises(WorkbenchError, match="^ACCOUNTING_OPERATOR_REQUIRED$"):
            cloud.settle(Database(roles[name]), settlement(identifier))
        with pytest.raises(WorkbenchError, match="^ACCOUNTING_OPERATOR_REQUIRED$"):
            cloud.unsettled(Database(roles[name]))
    with psycopg.connect(roles["writer"]) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(
                "UPDATE ow.remote_operations SET settlement_basis='invoice' WHERE attempt_id=%s",
                (identifier,),
            )
    # The writer can no longer insert a pre-settled or back-dated attempt.
    for column, value in (("settled_cost", 0), ("created_at", "2020-01-01T00:00:00Z")):
        with psycopg.connect(roles["writer"]) as conn:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(
                    "INSERT INTO ow.remote_operations(attempt_id,operation_id,route_id,"
                    "policy_sha256,task,decision,packet_sha256,currency,reserved,status,"
                    + column
                    + ") VALUES (gen_random_uuid(),'x','fixture-eu',%s,'structured_extraction',"
                    "'denied',%s,'EUR',0,'denied',%s)",
                    ("a" * 64, "a" * 64, value),
                )
    # Accounting may settle only; it cannot rewrite outcomes, reservations or delete.
    for statement in (
        "UPDATE ow.remote_operations SET status='released' WHERE attempt_id=%s",
        "UPDATE ow.remote_operations SET reserved=0 WHERE attempt_id=%s",
        "UPDATE ow.remote_operations SET settled_at=now() WHERE attempt_id=%s",
        "DELETE FROM ow.remote_operations WHERE attempt_id=%s",
    ):
        with psycopg.connect(roles["accounting"]) as conn:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(statement, (identifier,))
    # A login holding both spending and settlement authority is refused.
    with psycopg.connect(roles["admin"], autocommit=True) as conn:
        conn.execute("GRANT ow_writer TO ow_test_accounting")
    try:
        with pytest.raises(WorkbenchError, match="^ACCOUNTING_OPERATOR_REQUIRED$"):
            cloud.settle(Database(roles["accounting"]), settlement(identifier))
        # The database refuses it too, without the application check.
        with psycopg.connect(roles["accounting"]) as conn:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(
                    "UPDATE ow.remote_operations SET settlement_basis='invoice',settled_cost=0,"
                    "settlement_evidence_sha256=%s,settled_by='x',settlement_rationale='y' "
                    "WHERE attempt_id=%s",
                    ("e" * 64, identifier),
                )
    finally:
        with psycopg.connect(roles["admin"], autocommit=True) as conn:
            conn.execute("REVOKE ow_writer FROM ow_test_accounting")
    # The reader identity check rejects settlement authority.
    with psycopg.connect(roles["admin"], autocommit=True) as conn:
        conn.execute("GRANT ow_accounting TO ow_test_reader")
    try:
        with pytest.raises(WorkbenchError, match="^UNSAFE_READER_IDENTITY$"):
            Database(roles["reader"]).validate_reader()
    finally:
        with psycopg.connect(roles["admin"], autocommit=True) as conn:
            conn.execute("REVOKE ow_accounting FROM ow_test_reader")
    assert ledger(roles)[0]["settlement_basis"] is None


@pytest.mark.integration
def test_settled_rows_are_immutable_even_to_accounting(databases, tmp_path):
    writer, reader, roles, store, doc = setup(databases, tmp_path)
    identifier = attempt(writer, "refused")
    cloud.settle(Database(roles["accounting"]), settlement(identifier))
    with psycopg.connect(roles["accounting"]) as conn:
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(
                "UPDATE ow.remote_operations SET settled_cost=0 WHERE attempt_id=%s",
                (identifier,),
            )
    with psycopg.connect(roles["writer"]) as conn:
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(
                "UPDATE ow.remote_operations SET error_code='X' WHERE attempt_id=%s",
                (identifier,),
            )


@pytest.mark.integration
def test_unsettled_listing_is_bounded_and_filtered(databases, tmp_path):
    writer, reader, roles, store, doc = setup(databases, tmp_path)
    accounting = Database(roles["accounting"])
    unknown = attempt(writer, "outcome_unknown", operation="l1")
    estimated = attempt(writer, "dispatched", operation="l2")
    cloud.Ledger(writer).transition(
        estimated,
        "dispatched",
        "completed",
        usage="reported",
        input_tokens=1,
        output_tokens=1,
        estimated_cost=Decimal("0.000001600"),
    )
    other, other_sha = policy(route(route_id="fixture-two"))
    attempt(writer, "failed", operation="l3", parsed=(other, other_sha))
    attempt(writer, "released", operation="l4")
    listed = [a["attempt_id"] for a in cloud.unsettled(accounting)["attempts"]]
    assert str(unknown) in listed and str(estimated) not in listed and len(listed) == 2
    everything = cloud.unsettled(accounting, include_estimated=True)["attempts"]
    assert len(everything) == 3
    assert [
        a["route_id"] for a in cloud.unsettled(accounting, route_id="fixture-two")["attempts"]
    ] == ["fixture-two"]
    page = cloud.unsettled(accounting, include_estimated=True, limit=2)
    assert len(page["attempts"]) == 2 and page["truncated"] is True
    with pytest.raises(WorkbenchError, match="^INVALID_LIST_LIMIT$"):
        cloud.unsettled(accounting, limit=cloud.MAX_LISTED + 1)
    assert "synthetic-credential-canary" not in json.dumps(everything)


@pytest.mark.integration
def test_cli_settles_with_a_hashed_evidence_file(databases, tmp_path, monkeypatch, capsys):
    writer, reader, roles, store, doc = setup(databases, tmp_path)
    identifier = attempt(writer, "outcome_unknown")
    evidence = tmp_path / "statement.synthetic"
    evidence.write_bytes(b"synthetic provider statement")
    monkeypatch.setenv("OW_ACCOUNTING_DSN", roles["accounting"])

    def run(*arguments):
        monkeypatch.setattr("sys.argv", ["osint-workbench", "cloud-ledger", *arguments])
        try:
            cli.main()
            code = 0
        except SystemExit as exc:
            code = exc.code
        captured = capsys.readouterr()
        return code, json.loads(captured.out if code == 0 else captured.err)

    code, listed = run("unsettled")
    assert code == 0 and listed["attempts"][0]["attempt_id"] == str(identifier)
    arguments = [
        "settle",
        "--attempt-id",
        str(identifier),
        "--basis",
        "provider_statement",
        "--cost",
        "0",
        "--currency",
        "EUR",
        "--evidence",
        str(evidence),
        "--actor",
        "synthetic-operator",
        "--rationale",
        "Provider statement shows no processing.",
    ]
    code, receipt = run(*arguments)
    assert code == 0 and receipt["settlement_basis"] == "provider_statement"
    assert receipt["settlement_evidence_sha256"] == cloud.evidence_digest(evidence)
    assert cloud.exposure(writer, "fixture-eu", "EUR") == 0
    code, error = run(*arguments[:-2])
    assert code != 0 and error["error"] == "INVALID_SETTLEMENT"
    monkeypatch.setenv("OW_ACCOUNTING_DSN", roles["writer"])
    code, error = run("unsettled")
    assert code != 0 and error["error"] == "ACCOUNTING_OPERATOR_REQUIRED"


def checkpoint(roles, store, tmp_path, name):
    path = tmp_path / name
    return path, recovery.checkpoint(Database(roles["admin"]), store, path)["sha256"]


@pytest.mark.integration
def test_settlements_survive_checkpoint_and_restore_exactly(databases, destination, tmp_path):
    writer, reader, roles, store, doc = setup(databases, tmp_path)
    settled = attempt(writer, "outcome_unknown", operation="r1")
    attempt(writer, "failed", operation="r2")
    cloud.settle(Database(roles["accounting"]), settlement(settled, cost="999999.123456789"))
    before = ledger(roles)
    path, sha = checkpoint(roles, store, tmp_path, "settled.owcp")
    recovery.restore(
        Database(destination["admin"]),
        path,
        sha,
        tmp_path / "restored",
        **policy_arguments(roles, path),
    )
    # Settlement, its database timestamp and exact amount are retained.
    assert ledger({"admin": destination["admin"]}) == before
    assert cloud.exposure(Database(destination["writer"]), "fixture-eu", "EUR") == cloud.exposure(
        writer, "fixture-eu", "EUR"
    )


@pytest.mark.integration
def test_core9_checkpoint_attempts_adopt_unsettled(databases, destination, tmp_path):
    writer, reader, roles, store, doc = setup(databases, tmp_path)
    attempt(writer, "outcome_unknown", operation="r3")
    before = ledger(roles)
    path, _ = checkpoint(roles, store, tmp_path, "core9.owcp")
    bundle = json.loads(path.read_bytes())
    published_pair(bundle["payload"], 9)
    assert all("settled_at" not in r for r in bundle["payload"]["tables"]["remote_operations"])
    bundle["sha256"] = recovery.digest(recovery._json(bundle["payload"]))
    path.write_bytes(recovery._json(bundle))
    result = recovery.restore(
        Database(destination["admin"]),
        path,
        bundle["sha256"],
        tmp_path / "restored",
        **policy_arguments(roles, path),
    )
    assert result["adopted_core_v9"] is True
    assert ledger({"admin": destination["admin"]}) == before


@pytest.mark.integration
def test_core9_adoption_refuses_partial_settlement_columns(databases, destination, tmp_path):
    writer, reader, roles, store, doc = setup(databases, tmp_path)
    attempt(writer, "outcome_unknown", operation="r4")
    path, _ = checkpoint(roles, store, tmp_path, "mixed.owcp")
    bundle = json.loads(path.read_bytes())
    published_pair(bundle["payload"], 9)
    bundle["payload"]["tables"]["remote_operations"][0]["settled_cost"] = "0"
    bundle["sha256"] = recovery.digest(recovery._json(bundle["payload"]))
    path.write_bytes(recovery._json(bundle))
    with pytest.raises(WorkbenchError, match="^RECOVERY_COLUMNS_MISMATCH$"):
        recovery.restore(
            Database(destination["admin"]),
            path,
            bundle["sha256"],
            tmp_path / "restored",
            **policy_arguments(roles, path),
        )


@pytest.mark.integration
def test_a_worker_stalled_after_dispatch_commit_never_sends(databases, tmp_path, monkeypatch):
    writer, reader, roles, store, doc = setup(databases, tmp_path)
    generator = governed(writer, route(timeout_seconds=1))
    commit = cloud.Ledger.transition

    def stalled(self, attempt, expected, status, **fields):
        commit(self, attempt, expected, status, **fields)
        if status == "dispatched":
            time.sleep(1.2)  # Synthetic pause between the commit and the request.

    monkeypatch.setattr(cloud.Ledger, "transition", stalled)
    monkeypatch.setattr(cloud.fetch, "_PublicBackend", NoEgress)
    operation = {"operation_id": "stall", "task": "structured_extraction", "data_class": "public"}
    with pytest.raises(WorkbenchError, match="^REMOTE_UNAVAILABLE$"):
        generator.generate("Synthetic prompt", SCHEMA, operation=operation)
    (row,) = ledger(roles)
    assert row["status"] == "released" and row["error_code"] == "REMOTE_DEADLINE_BEFORE_SEND"


@pytest.mark.integration
def test_in_flight_window_uses_database_time_the_writer_cannot_set(databases, tmp_path):
    writer, reader, roles, store, doc = setup(databases, tmp_path)
    accounting = Database(roles["accounting"])
    identifier = attempt(writer, "reserved")
    with psycopg.connect(roles["writer"]) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(
                "UPDATE ow.remote_operations SET status='dispatched',"
                "updated_at='2000-01-01T00:00:00Z' WHERE attempt_id=%s",
                (identifier,),
            )
    age(roles, identifier)
    assert cloud.unsettled(accounting)["attempts"][0]["in_flight"] is False
    # Dispatch restarts the window from the database clock.
    cloud.Ledger(writer).transition(identifier, "reserved", "dispatched")
    assert cloud.unsettled(accounting)["attempts"][0]["in_flight"] is True
    with pytest.raises(WorkbenchError, match="^SETTLEMENT_IN_FLIGHT$"):
        cloud.settle(accounting, settlement(identifier))


@pytest.mark.integration
def test_settlement_waiting_on_a_live_worker_is_busy(databases, tmp_path):
    writer, reader, roles, store, doc = setup(databases, tmp_path)
    identifier = attempt(writer, "dispatched")
    age(roles, identifier)
    worker = psycopg.connect(roles["writer"])
    try:
        worker.execute(
            "UPDATE ow.remote_operations SET status='outcome_unknown' WHERE attempt_id=%s",
            (identifier,),
        )
        with pytest.raises(WorkbenchError, match="^SETTLEMENT_BUSY$"):
            cloud.settle(Database(roles["accounting"]), settlement(identifier))
    finally:
        worker.rollback()
        worker.close()
    assert ledger(roles)[0]["settlement_basis"] is None
