"""Governed compatible route: policy denial, ledger and real-transport contracts.

The synthetic provider runs behind configured fixture trust with the original
HTTPS origin, SNI and certificate checks. This is contract evidence, not a
live-provider, sovereignty or invoice claim.
"""

import json
import threading
from decimal import Decimal

import httpcore
import psycopg
import pytest

from osint_workbench import cloud, fetch
from osint_workbench import intelligence as intel
from osint_workbench.errors import WorkbenchError
from tests.test_intelligence import claim, setup
from tests.test_recovery import destination as destination
from tests.tls_fixture import generate_certificates, tls_peer

ENDPOINT = "https://feed.fixture.invalid/v1/chat/completions"
KEY = {"OW_ROUTE_FIXTURE_KEY": "synthetic-credential-canary"}


def route(**changes):
    value = {
        "route_id": "fixture-eu",
        "adapter": "openai-compatible-chat",
        "endpoint": ENDPOINT,
        "model": "synthetic-model",
        "credential_env": "OW_ROUTE_FIXTURE_KEY",
        "tasks": ["structured_extraction"],
        "data_classes": ["public"],
        "provider": {
            "controlling_jurisdiction": "AT",
            "processing_regions": ["AT", "DE"],
            "foreign_legal_exposure": "none",
            "retention_training": "none",
            "evidence_date": "2026-10-01",
        },
        "pricebook": {
            "currency": "EUR",
            "input_per_million": "0.400000000",
            "output_per_million": "1.200000000",
            "effective_date": "2026-10-01",
        },
        "cap": "1.00",
        "max_input_chars": 20000,
        "max_output_tokens": 1000,
        "timeout_seconds": 5,
    }
    for key, item in changes.items():
        if isinstance(item, dict) and isinstance(value.get(key), dict):
            value[key] = {**value[key], **item}
        else:
            value[key] = item
    return value


def policy(*routes):
    data = json.dumps({"schema_version": 1, "routes": list(routes) or [route()]}).encode()
    return cloud.load_policy(data)


# Unit contracts --------------------------------------------------------------


@pytest.mark.parametrize(
    "changes,data_class,reason",
    [
        ({}, None, "DATA_CLASS_UNKNOWN"),
        ({}, "personal", "DATA_CLASS_NOT_ALLOWED"),
        ({"enabled": False}, "public", "ROUTE_DISABLED"),
        ({"provider": {"controlling_jurisdiction": "unknown"}}, "public", "SOVEREIGNTY_UNKNOWN"),
        ({"provider": {"processing_regions": ["AT", "unknown"]}}, "public", "SOVEREIGNTY_UNKNOWN"),
        ({"provider": {"foreign_legal_exposure": "unknown"}}, "public", "SOVEREIGNTY_UNKNOWN"),
        ({"provider": {"controlling_jurisdiction": "US"}}, "public", "SOVEREIGNTY_NONCONFORMING"),
        ({"provider": {"processing_regions": ["AT", "US"]}}, "public", "SOVEREIGNTY_NONCONFORMING"),
        (
            {"provider": {"foreign_legal_exposure": "material"}},
            "public",
            "SOVEREIGNTY_NONCONFORMING",
        ),
        ({"provider": {"retention_training": "retained"}}, "public", "SOVEREIGNTY_NONCONFORMING"),
    ],
)
def test_route_decision_denies_unknown_or_unapproved_facts(changes, data_class, reason):
    parsed, _ = policy(route(**changes))
    assert cloud.decide(parsed.routes[0], "structured_extraction", data_class, environ=KEY) == (
        "denied",
        reason,
    )


def test_exception_is_explicit_task_scoped_and_never_relabelled():
    nonconforming = {"provider": {"controlling_jurisdiction": "US"}}
    exempt = route(
        **nonconforming,
        exception={"rationale": "Synthetic test", "tasks": ["structured_extraction"]},
    )
    parsed, _ = policy(exempt)
    assert cloud.decide(parsed.routes[0], "structured_extraction", "public", environ=KEY) == (
        "exception",
        None,
    )
    # Unknown facts deny even with an exception.
    unknown = route(
        provider={"retention_training": "unknown"},
        exception={"rationale": "Synthetic test", "tasks": ["structured_extraction"]},
    )
    parsed, _ = policy(unknown)
    assert cloud.decide(parsed.routes[0], "structured_extraction", "public", environ=KEY)[1] == (
        "SOVEREIGNTY_UNKNOWN"
    )
    parsed, _ = policy(route())
    assert cloud.decide(parsed.routes[0], "structured_extraction", "public", environ={}) == (
        "denied",
        "CREDENTIAL_MISSING",
    )
    assert cloud.decide(None, "structured_extraction", "public", environ=KEY) == (
        "denied",
        "ROUTE_UNKNOWN",
    )
    for bad in ("two words", "line\r\nInjected: header", "nön-ascii"):
        assert cloud.decide(
            parsed.routes[0],
            "structured_extraction",
            "public",
            environ={**KEY, "OW_ROUTE_FIXTURE_KEY": bad},
        ) == ("denied", "CREDENTIAL_INVALID")


@pytest.mark.parametrize(
    "changes",
    [
        {"endpoint": "http://feed.fixture.invalid/v1/chat/completions"},
        {"endpoint": "https://feed.fixture.invalid:8443/v1"},
        {"endpoint": "https://user:pass@feed.fixture.invalid/v1"},
        {"cap": 1.0},
        {"cap": "0"},
        {"pricebook": {"input_per_million": 0.4}},
        {"credential_env": "AWS_SECRET_ACCESS_KEY"},
        {"unexpected": True},
        {"endpoint": "https://feed.fixture.invalid/v1?key=secret"},
        {"endpoint": "https:" + "//203.0.113.7/v1"},
        {"endpoint": "https:" + "//[2001:db8::1]/v1"},
        {"endpoint": "https:" + "//localhost/v1"},
        {"endpoint": "https:" + "//feed.fixture.invalid./v1"},
        {"pricebook": {"input_per_million": "0", "output_per_million": "0"}},
        {"pricebook": {"input_per_million": "1_0"}},
        {"cap": "1000000"},
        {"cap": "1e3"},
    ],
)
def test_policy_rejects_unsafe_or_ambiguous_configuration(changes):
    with pytest.raises(WorkbenchError, match="^CLOUD_POLICY_INVALID$"):
        policy(route(**changes))


def test_policy_digest_bounds_and_duplicate_routes():
    parsed, sha = policy(route())
    assert len(sha) == 64 and parsed.routes[0].cap == Decimal("1.00")
    with pytest.raises(WorkbenchError, match="^CLOUD_POLICY_INVALID$"):
        policy(route(), route())
    with pytest.raises(WorkbenchError, match="^CLOUD_POLICY_TOO_LARGE$"):
        cloud.load_policy(b" " * (cloud.MAX_POLICY_BYTES + 1))


def test_reservation_is_a_ceiling_of_the_worst_case():
    parsed, _ = policy(route())
    # 1000 input characters at 0.40/M plus 1000 output tokens at 1.20/M.
    assert cloud.worst_case_cost(parsed.routes[0], 1000) == Decimal("0.001600000")
    assert cloud.observed_cost(parsed.routes[0], 3, 1) == Decimal("0.000002400")


# Native contracts ------------------------------------------------------------


@pytest.fixture(scope="module")
def certificates(tmp_path_factory):
    return generate_certificates(tmp_path_factory.mktemp("cloud-pki") / "pki")


def completion(content=None, *, finish="stop", usage=True, refusal=None, status=200):
    message = {"role": "assistant", "content": content}
    if refusal is not None:
        message["refusal"] = refusal
    body = {
        "id": "synthetic",
        "choices": [{"index": 0, "message": message, "finish_reason": finish}],
    }
    if usage is True:
        body["usage"] = {"prompt_tokens": 120, "completion_tokens": 30, "total_tokens": 150}
    elif usage is not None:
        body["usage"] = usage
    data = json.dumps(body).encode()
    reason = {200: b"OK", 429: b"Too Many Requests", 500: b"Internal Server Error"}[status]
    return (
        b"HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n"
        b"Connection: close\r\n\r\n" % (status, reason, len(data))
    ) + data


def proposals(*claims):
    return json.dumps({"claims": list(claims)})


class NoEgress(fetch._PublicBackend):
    def connect_tcp(self, *args, **kwargs):
        raise AssertionError("provider connection attempted")


def governed(writer, *routes, environ=KEY):
    parsed, sha = policy(*(routes or [route()]))
    return cloud.GovernedGenerator(writer, parsed, sha, parsed.routes[0].route_id, environ=environ)


def ledger(roles):
    with psycopg.connect(roles["admin"]) as conn:
        conn.row_factory = psycopg.rows.dict_row
        return conn.execute("SELECT * FROM ow.remote_operations ORDER BY created_at").fetchall()


@pytest.mark.integration
def test_routed_enrichment_reaches_proposals_and_settles_reported_usage(
    databases, tmp_path, monkeypatch, certificates
):
    writer, reader, roles, store, doc = setup(databases, tmp_path)
    generator = governed(writer)
    intel.enqueue(writer, generator, doc, data_class="public")
    with tls_peer(monkeypatch, certificates, wire=completion(proposals(claim()))) as peer:
        result = intel.enrich_once(writer, store, generator)
    assert result["status"] == "proposed" and result["proposals"] == 1
    assert intel.assertions(reader)["results"][0]["review_state"] == "pending"
    assert peer.sni == ["feed.fixture.invalid"] and peer.connections == 1
    head, body = peer.requests[0], json.loads(peer.bodies[0])
    assert head.startswith(b"POST /v1/chat/completions HTTP/1.1\r\n")
    assert b"Authorization: Bearer synthetic-credential-canary\r\n" in head
    assert body["model"] == "synthetic-model" and body["temperature"] == 0
    assert body["response_format"]["json_schema"]["strict"] is True
    (row,) = ledger(roles)
    # The reservation covers every request byte, not just prompt characters.
    assert row["reserved"] == cloud.worst_case_cost(generator.route, len(peer.bodies[0]))
    assert row["status"] == "completed" and row["decision"] == "conforming"
    assert row["usage"] == "reported" and (row["input_tokens"], row["output_tokens"]) == (120, 30)
    assert row["estimated_cost"] == Decimal("0.000084000")
    assert row["data_class"] == "public" and row["currency"] == "EUR"
    # Digests and accounting only: no credential, prompt or response text.
    assert "synthetic-credential-canary" not in json.dumps(row, default=str)
    assert "Straße" not in json.dumps(row, default=str)
    assert cloud.exposure(writer, "fixture-eu", "EUR") == Decimal("0.000084000")


@pytest.mark.integration
@pytest.mark.parametrize(
    "changes,data_class,code",
    [
        ({}, None, "REMOTE_DATA_CLASS_UNKNOWN"),
        (
            {"provider": {"controlling_jurisdiction": "unknown"}},
            "public",
            "REMOTE_SOVEREIGNTY_UNKNOWN",
        ),
        (
            {"provider": {"controlling_jurisdiction": "US"}},
            "public",
            "REMOTE_SOVEREIGNTY_NONCONFORMING",
        ),
        ({"data_classes": ["internal"]}, "public", "REMOTE_DATA_CLASS_NOT_ALLOWED"),
        ({"cap": "0.000000001"}, "public", "REMOTE_BUDGET_EXHAUSTED"),
    ],
)
def test_denials_are_recorded_with_zero_provider_egress(
    databases, tmp_path, monkeypatch, changes, data_class, code
):
    writer, reader, roles, store, doc = setup(databases, tmp_path)
    generator = governed(writer, route(**changes))
    intel.enqueue(writer, generator, doc, data_class=data_class)
    monkeypatch.setattr(fetch, "_PublicBackend", NoEgress)
    result = intel.enrich_once(writer, store, generator)
    assert result == {"status": "failed", "error": code}
    (row,) = ledger(roles)
    assert row["status"] == "denied" and row["reason"] == code.removeprefix("REMOTE_")
    assert row["reserved"] == 0
    # Denied work is terminal: nothing is retried into a remote call.
    assert intel.enrich_once(writer, store, generator)["status"] == "idle"


@pytest.mark.integration
def test_missing_credential_denies_without_egress(databases, tmp_path, monkeypatch):
    writer, reader, roles, store, doc = setup(databases, tmp_path)
    generator = governed(writer, environ={})
    intel.enqueue(writer, generator, doc, data_class="public")
    monkeypatch.setattr(fetch, "_PublicBackend", NoEgress)
    assert intel.enrich_once(writer, store, generator)["error"] == "REMOTE_CREDENTIAL_MISSING"


@pytest.mark.integration
@pytest.mark.parametrize(
    "wire,status,code,usage",
    [
        (completion(proposals(claim()), usage=None), "completed", None, "missing"),
        (completion(proposals(claim()), usage={"prompt_tokens": -1}), "completed", None, "missing"),
        # Zero or impossible usage cannot shrink exposure below the reservation.
        (
            completion(proposals(claim()), usage={"prompt_tokens": 0, "completion_tokens": 0}),
            "completed",
            None,
            "missing",
        ),
        (
            completion(proposals(claim()), usage={"prompt_tokens": 10**12, "completion_tokens": 1}),
            "completed",
            None,
            "missing",
        ),
        (
            completion(proposals(claim()), usage={"prompt_tokens": 10, "completion_tokens": 10**6}),
            "completed",
            None,
            "missing",
        ),
        # Adversarial nesting and unstorable text settle instead of sticking.
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 200000\r\nConnection: close\r\n\r\n"
            + b"[" * 200000,
            "failed",
            "REMOTE_PROTOCOL_ERROR",
            "missing",
        ),
        # Schema-valid output whose text holds a lone surrogate cannot be stored.
        (
            completion(json.dumps({"claims": [{**claim(), "subject": "\ud800"}]})),
            "completed",
            "INVALID_MODEL_RESULT",
            "reported",
        ),
        (completion(None, refusal="Synthetic refusal"), "refused", "REMOTE_REFUSED", "reported"),
        (completion(None, finish="content_filter"), "refused", "REMOTE_REFUSED", "reported"),
        (
            completion('{"claims": [', finish="length"),
            "incomplete",
            "GENERATION_INCOMPLETE",
            "reported",
        ),
        (completion("not json"), "completed", "INVALID_MODEL_RESULT", "reported"),
        (
            completion(proposals(), finish="tool_calls"),
            "failed",
            "REMOTE_PROTOCOL_ERROR",
            "reported",
        ),
        (completion(proposals(), status=500), "failed", "REMOTE_HTTP_FAILURE", None),
        (completion(proposals(), status=429), "failed", "REMOTE_HTTP_FAILURE", None),
    ],
)
def test_provider_outcomes_are_explicit_and_never_free(
    databases, tmp_path, monkeypatch, certificates, wire, status, code, usage
):
    writer, reader, roles, store, doc = setup(databases, tmp_path)
    generator = governed(writer)
    intel.enqueue(writer, generator, doc, data_class="public")
    with tls_peer(monkeypatch, certificates, wire=wire) as peer:
        result = intel.enrich_once(writer, store, generator)
    assert peer.connections == 1
    if code is None:
        assert result["status"] == "proposed"
    else:
        assert result == {"status": "failed", "error": code}
    (row,) = ledger(roles)
    assert row["status"] == status and row["usage"] == usage
    assert row["status"] != "dispatched"
    expected = row["estimated_cost"] if usage == "reported" else row["reserved"]
    # Unreported usage keeps the full reservation as exposure; it is never zero.
    assert cloud.exposure(writer, "fixture-eu", "EUR") == expected > 0
    # Failed work is terminal and is not replayed by the worker.
    assert intel.enrich_once(writer, store, generator)["status"] == "idle"


@pytest.mark.integration
def test_dropped_response_is_outcome_unknown_and_blocks_replay(
    databases, tmp_path, monkeypatch, certificates
):
    writer, reader, roles, store, doc = setup(databases, tmp_path)
    generator = governed(writer)
    operation = {"operation_id": "op-1", "task": "structured_extraction", "data_class": "public"}
    schema = intel.Proposals.model_json_schema()
    # The peer reads the full request, then closes without any response.
    with tls_peer(monkeypatch, certificates, wire=b"") as peer:
        with pytest.raises(WorkbenchError, match="^REMOTE_OUTCOME_UNKNOWN$"):
            generator.generate("Synthetic prompt", schema, operation=operation)
    assert peer.connections == 1 and len(peer.bodies) == 1
    (row,) = ledger(roles)
    assert row["status"] == "outcome_unknown" and row["usage"] is None
    assert cloud.exposure(writer, "fixture-eu", "EUR") == row["reserved"] > 0
    monkeypatch.setattr(fetch, "_PublicBackend", NoEgress)
    with pytest.raises(WorkbenchError, match="^REMOTE_PRIOR_ATTEMPT_UNRESOLVED$"):
        generator.generate("Synthetic prompt", schema, operation=operation)
    assert [r["status"] for r in ledger(roles)] == ["outcome_unknown", "denied"]


@pytest.mark.integration
def test_connection_failure_before_sending_releases_the_reservation(
    databases, tmp_path, monkeypatch
):
    writer, reader, roles, store, doc = setup(databases, tmp_path)
    generator = governed(writer)

    class Refused(fetch._PublicBackend):
        def connect_tcp(self, *args, **kwargs):
            raise httpcore.ConnectError("synthetic refusal")

    monkeypatch.setattr(fetch, "_PublicBackend", Refused)
    operation = {"operation_id": "op-2", "task": "structured_extraction", "data_class": "public"}
    with pytest.raises(WorkbenchError, match="^REMOTE_UNAVAILABLE$"):
        generator.generate(
            "Synthetic prompt", intel.Proposals.model_json_schema(), operation=operation
        )
    (row,) = ledger(roles)
    assert row["status"] == "released" and row["error_code"] == "REMOTE_CONNECT_FAILED"
    assert cloud.exposure(writer, "fixture-eu", "EUR") == 0


@pytest.mark.integration
def test_concurrent_reservations_never_exceed_the_cap(databases, tmp_path):
    writer, reader, roles, store, doc = setup(databases, tmp_path)
    parsed, sha = policy(
        route(cap="0.010000000"),
        route(route_id="fixture-usd", pricebook={"currency": "USD"}, cap="0.010000000"),
    )
    eur, usd = parsed.routes
    led = cloud.Ledger(writer)
    barrier, results = threading.Barrier(12), []

    def reserve(index, target):
        barrier.wait()
        results.append(
            led.record(
                operation_id=f"concurrent-{index}",
                route=target,
                policy_sha=sha,
                task="structured_extraction",
                data_class="public",
                decision="conforming",
                reason=None,
                packet_sha="a" * 64,
                reserve=Decimal("0.003000000"),
            )[1]
        )

    threads = [threading.Thread(target=reserve, args=(i, eur if i < 8 else usd)) for i in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    # 0.003 fits three times under 0.010 per route and currency, never more.
    assert cloud.exposure(writer, "fixture-eu", "EUR") == Decimal("0.009000000")
    assert cloud.exposure(writer, "fixture-usd", "USD") == Decimal("0.009000000")
    assert results.count("conforming") == 6 and results.count("denied") == 6
    reasons = {r["reason"] for r in ledger(roles) if r["status"] == "denied"}
    assert reasons == {"BUDGET_EXHAUSTED"}


@pytest.mark.integration
def test_reader_and_collector_cannot_see_the_ledger(databases):
    writer, reader, roles, *_ = databases
    for role in ("reader", "collector"):
        with psycopg.connect(roles[role]) as conn:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute("SELECT 1 FROM ow.remote_operations")
    # The writer may record outcomes but never rewrite the decision or reservation.
    with psycopg.connect(roles["writer"]) as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("UPDATE ow.remote_operations SET reserved=0")


@pytest.mark.integration
def test_writer_cannot_skip_or_rewind_the_attempt_state_machine(databases, tmp_path):
    writer, reader, roles, store, doc = setup(databases, tmp_path)
    parsed, sha = policy(route())
    led = cloud.Ledger(writer)
    attempt, decision, _ = led.record(
        operation_id="machine",
        route=parsed.routes[0],
        policy_sha=sha,
        task="structured_extraction",
        data_class="public",
        decision="conforming",
        reason=None,
        packet_sha="b" * 64,
        reserve=Decimal("0.010000000"),
    )
    assert decision == "conforming"

    def update(sql, *params):
        with psycopg.connect(roles["writer"]) as conn:
            conn.execute(sql, (*params, attempt))

    # Skipping dispatch, settling usage on a reserved row, or exceeding the reservation fail.
    for sql in (
        "UPDATE ow.remote_operations SET status='completed' WHERE attempt_id=%s",
        "UPDATE ow.remote_operations SET status='released' WHERE attempt_id=%s",
        "UPDATE ow.remote_operations SET usage='missing' WHERE attempt_id=%s",
    ):
        with pytest.raises(psycopg.errors.CheckViolation):
            update(sql)
    led.transition(attempt, "reserved", "dispatched")
    with pytest.raises(psycopg.errors.CheckViolation):
        update(
            "UPDATE ow.remote_operations SET status='completed',usage='reported',"
            "estimated_cost=1 WHERE attempt_id=%s"
        )
    led.transition(attempt, "dispatched", "outcome_unknown", error_code="REMOTE_OUTCOME_UNKNOWN")
    # A terminal attempt cannot be released to clear its exposure.
    for target in ("released", "dispatched", "completed"):
        with pytest.raises(psycopg.errors.CheckViolation):
            update("UPDATE ow.remote_operations SET status=%s WHERE attempt_id=%s", target)
    assert cloud.exposure(writer, "fixture-eu", "EUR") == Decimal("0.010000000")


@pytest.mark.integration
def test_ledger_survives_checkpoint_and_restore_exactly(
    databases, destination, tmp_path, monkeypatch, certificates
):
    from osint_workbench import recovery
    from osint_workbench.database import Database
    from tests.test_recovery import policy_arguments

    writer, reader, roles, store, doc = setup(databases, tmp_path)
    generator = governed(writer)
    intel.enqueue(writer, generator, doc, data_class="public")
    with tls_peer(monkeypatch, certificates, wire=completion(proposals(claim()))):
        assert intel.enrich_once(writer, store, generator)["status"] == "proposed"
    with tls_peer(monkeypatch, certificates, wire=b""):
        with pytest.raises(WorkbenchError, match="^REMOTE_OUTCOME_UNKNOWN$"):
            generator.generate(
                "Synthetic prompt",
                intel.Proposals.model_json_schema(),
                operation={
                    "operation_id": "op-3",
                    "task": "structured_extraction",
                    "data_class": "public",
                },
            )
    # The largest storable amount must survive checkpoint JSON exactly.
    large, large_sha = policy(route(route_id="fixture-large", cap="999999.999999999"))
    cloud.Ledger(writer).record(
        operation_id="large",
        route=large.routes[0],
        policy_sha=large_sha,
        task="structured_extraction",
        data_class="public",
        decision="conforming",
        reason=None,
        packet_sha="c" * 64,
        reserve=Decimal("999999.123456789"),
    )
    before = ledger(roles)
    assert Decimal("999999.123456789") in {row["reserved"] for row in before}
    path = tmp_path / "ledger.owcp"
    receipt = recovery.checkpoint(Database(roles["admin"]), store, path)
    recovery.restore(
        Database(destination["admin"]),
        path,
        receipt["sha256"],
        tmp_path / "restored",
        **policy_arguments(roles, path),
    )
    # Unknown outcomes and Decimal amounts are retained, never reset on recovery.
    restored = ledger({"admin": destination["admin"]})
    assert restored == before
    assert cloud.exposure(Database(destination["writer"]), "fixture-eu", "EUR") == cloud.exposure(
        writer, "fixture-eu", "EUR"
    )
