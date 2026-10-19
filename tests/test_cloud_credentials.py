"""Managed cloud credentials preserve governed dispatch and legacy route identity."""

import json

import pytest

from osint_workbench import cloud
from osint_workbench import intelligence as intel
from osint_workbench.credentials import SecretStr
from osint_workbench.errors import WorkbenchError
from tests.test_cloud import (
    KEY,
    completion,
    governed,
    ledger,
    policy,
    proposals,
    route,
)
from tests.test_cloud import (
    certificates as certificates,
)
from tests.test_intelligence import claim, setup
from tests.tls_fixture import tls_peer

CANARY = "managed-cloud-credential-canary"


def _file_route(tmp_path):
    path = tmp_path / "cloud-token"
    path.write_text(CANARY)
    path.chmod(0o600)
    return path, route(credential_env=None, credential={"kind": "file", "path": str(path)})


def test_managed_file_credential_policy_decision(tmp_path):
    path, configured = _file_route(tmp_path)
    parsed, _ = policy(configured)
    assert cloud.decide(parsed.routes[0], "structured_extraction", "public", environ={}) == (
        "conforming",
        None,
    )
    assert str(path) not in repr(parsed.routes[0])
    assert CANARY not in repr(parsed.routes[0])


@pytest.mark.parametrize("channel", ["both", "neither"])
def test_exactly_one_credential_channel_required(tmp_path, channel):
    _, configured = _file_route(tmp_path)
    if channel == "both":
        configured["credential_env"] = next(iter(KEY))
    else:
        configured["credential"] = None
    with pytest.raises(WorkbenchError, match="^CLOUD_POLICY_INVALID$"):
        policy(configured)


def test_managed_credential_refusal_never_falls_back_to_environment(tmp_path):
    path, configured = _file_route(tmp_path)
    path.chmod(0o644)
    parsed, _ = policy(configured)
    assert cloud.decide(parsed.routes[0], "structured_extraction", "public", environ=KEY) == (
        "denied",
        "CREDENTIAL_UNSAFE",
    )


def test_systemd_uses_selected_service_environment_only(tmp_path, monkeypatch):
    path, configured = _file_route(tmp_path)
    configured["credential"] = {"kind": "systemd", "name": path.name}
    parsed, _ = policy(configured)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
    assert cloud.decide(parsed.routes[0], "structured_extraction", "public", environ={}) == (
        "denied",
        "CREDENTIAL_UNAVAILABLE",
    )
    selected = {"CREDENTIALS_DIRECTORY": str(tmp_path)}
    assert cloud.decide(parsed.routes[0], "structured_extraction", "public", environ=selected) == (
        "conforming",
        None,
    )


def test_policy_denial_precedes_secret_resolution(tmp_path, monkeypatch):
    _, configured = _file_route(tmp_path)
    configured["enabled"] = False
    parsed, _ = policy(configured)

    def forbidden(*args, **kwargs):
        raise AssertionError("credential read before policy approval")

    monkeypatch.setattr(cloud, "resolve_credential", forbidden)
    assert cloud.decide(parsed.routes[0], "structured_extraction", "public") == (
        "denied",
        "ROUTE_DISABLED",
    )


def test_legacy_route_keeps_published_generator_identity():
    # Obtained from the installed predecessor wheel, not reconstructed from the
    # new serialization implementation. Adding credential=None must not change it.
    parsed, sha = policy()
    manifest = cloud.GovernedGenerator.Manifest(parsed.routes[0], sha)
    assert manifest.identity() == "aaa9d8681e8e533abe17fa2ea1916dd33881aaf7a353cd67dd3c5c3b869399c5"


class _RecordingLedger:
    def __init__(self):
        self.records = []
        self.transitions = []

    def record(self, **fields):
        self.records.append(fields)
        return "fixture-attempt", fields["decision"], fields["reason"]

    def transition(self, *args, **kwargs):
        self.transitions.append((args, kwargs))


def test_generate_resolves_once_and_uses_same_token_after_rotation(tmp_path, monkeypatch):
    path, configured = _file_route(tmp_path)
    parsed, sha = policy(configured)
    generator = cloud.GovernedGenerator(None, parsed, sha, parsed.routes[0].route_id, environ=KEY)
    recorder = _RecordingLedger()
    generator.ledger = recorder
    actual_resolver = cloud.resolve_credential
    resolutions = []

    def once(reference, **kwargs):
        token = actual_resolver(reference, **kwargs)
        assert isinstance(token, SecretStr)
        resolutions.append(token)
        path.write_text("rotated-after-decision")
        return token

    def post(url, body, headers, deadline):
        assert headers == [("Authorization", "Bearer " + CANARY)]
        return 200, json.dumps(
            {"choices": [{"message": {"content": "{}"}, "finish_reason": "stop"}]}
        ).encode()

    monkeypatch.setattr(cloud, "resolve_credential", once)
    monkeypatch.setattr(cloud, "post_json", post)
    result = generator.generate(
        "Synthetic prompt",
        {"type": "object"},
        operation={
            "operation_id": "fixture",
            "task": "structured_extraction",
            "data_class": "public",
        },
    )
    assert result["output"] == {}
    assert len(resolutions) == 1
    assert CANARY not in repr(recorder.records)
    assert CANARY not in repr(recorder.transitions)


def test_generate_missing_reference_records_denial_without_dispatch(tmp_path, monkeypatch):
    path, configured = _file_route(tmp_path)
    path.unlink()
    parsed, sha = policy(configured)
    generator = cloud.GovernedGenerator(None, parsed, sha, parsed.routes[0].route_id, environ=KEY)
    recorder = _RecordingLedger()
    generator.ledger = recorder

    def forbidden(*args, **kwargs):
        raise AssertionError("dispatch with missing managed credential")

    monkeypatch.setattr(cloud, "post_json", forbidden)
    with pytest.raises(WorkbenchError, match="^REMOTE_CREDENTIAL_UNAVAILABLE$"):
        generator.generate(
            "Synthetic prompt",
            {"type": "object"},
            operation={
                "operation_id": "fixture",
                "task": "structured_extraction",
                "data_class": "public",
            },
        )
    assert recorder.records[0]["decision"] == "denied"
    assert recorder.records[0]["reason"] == "CREDENTIAL_UNAVAILABLE"
    assert recorder.transitions == []


@pytest.mark.integration
def test_managed_reference_real_tls_and_ledger(databases, tmp_path, monkeypatch, certificates):
    writer, reader, roles, store, doc = setup(databases, tmp_path)
    _, configured = _file_route(tmp_path)
    generator = governed(writer, configured, environ={})
    intel.enqueue(writer, generator, doc, data_class="public")
    with tls_peer(monkeypatch, certificates, wire=completion(proposals(claim()))) as peer:
        result = intel.enrich_once(writer, store, generator)
    assert result["status"] == "proposed"
    assert b"Authorization: Bearer " + CANARY.encode() + b"\r\n" in peer.requests[0]
    (record,) = ledger(roles)
    assert record["status"] == "completed"
    assert record["decision"] == "conforming"
    assert CANARY not in repr(record)
    assert intel.assertions(reader)["results"][0]["review_state"] == "pending"


@pytest.mark.integration
def test_managed_reference_denial_persisted_in_real_ledger(databases, tmp_path, monkeypatch):
    writer, _, roles, store, doc = setup(databases, tmp_path)
    path, configured = _file_route(tmp_path)
    path.unlink()
    generator = governed(writer, configured, environ=KEY)
    intel.enqueue(writer, generator, doc, data_class="public")

    def forbidden(*args, **kwargs):
        raise AssertionError("provider dispatch after credential refusal")

    monkeypatch.setattr(cloud, "post_json", forbidden)
    result = intel.enrich_once(writer, store, generator)
    assert result["error"] == "REMOTE_CREDENTIAL_UNAVAILABLE"
    (record,) = ledger(roles)
    assert record["status"] == "denied"
    assert record["reason"] == "CREDENTIAL_UNAVAILABLE"


@pytest.mark.parametrize("channel", ["environment", "file", "systemd"])
@pytest.mark.parametrize("escaped", [False, True])
def test_active_credential_echo_is_refused_after_decoding_without_erasing_outcome(
    tmp_path, monkeypatch, channel, escaped
):
    if channel == "environment":
        configured, selected, token = route(), KEY, next(iter(KEY.values()))
    else:
        path, configured = _file_route(tmp_path)
        selected, token = {}, CANARY
        if channel == "systemd":
            configured["credential"] = {"kind": "systemd", "name": path.name}
            selected = {"CREDENTIALS_DIRECTORY": str(tmp_path)}
    parsed, sha = policy(configured)
    generator = cloud.GovernedGenerator(
        None, parsed, sha, parsed.routes[0].route_id, environ=selected
    )
    recorder = _RecordingLedger()
    generator.ledger = recorder
    proposal = claim()
    proposal["subject"] = token
    text = proposals(proposal)
    if escaped:
        text = text.replace(token, "".join(f"\\u{ord(c):04x}" for c in token))
    body = json.dumps(
        {"choices": [{"message": {"content": text}, "finish_reason": "stop"}]}
    ).encode()
    calls = []

    def post(url, request, headers, deadline):
        calls.append(headers)
        return 200, body

    monkeypatch.setattr(cloud, "post_json", post)
    with pytest.raises(WorkbenchError, match="^REMOTE_CREDENTIAL_REFLECTED$"):
        generator.generate(
            "Synthetic source input",
            intel.Proposals.model_json_schema(),
            operation={
                "operation_id": "fixture",
                "task": "structured_extraction",
                "data_class": "public",
            },
        )
    assert calls == [[("Authorization", "Bearer " + token)]]
    assert recorder.transitions[-1][0] == ("fixture-attempt", "dispatched", "completed")
    assert recorder.transitions[-1][1]["error_code"] == "REMOTE_CREDENTIAL_REFLECTED"
    assert token not in repr(recorder.records) + repr(recorder.transitions)


@pytest.mark.integration
@pytest.mark.parametrize("escaped", [False, True])
@pytest.mark.parametrize("reported_usage", [False, True])
def test_credential_echo_real_tls_accepts_no_assertions_and_preserves_exposure(
    databases, tmp_path, monkeypatch, certificates, escaped, reported_usage
):
    writer, reader, roles, store, doc = setup(databases, tmp_path)
    _, configured = _file_route(tmp_path)
    generator = governed(writer, configured, environ={})
    intel.enqueue(writer, generator, doc, data_class="public")
    proposal = claim()
    proposal["subject"] = CANARY
    text = proposals(proposal)
    if escaped:
        text = text.replace(CANARY, "".join(f"\\u{ord(c):04x}" for c in CANARY))
    with tls_peer(
        monkeypatch, certificates, wire=completion(text, usage=True if reported_usage else None)
    ) as peer:
        result = intel.enrich_once(writer, store, generator)
    assert len(peer.requests) == 1
    assert result == {"status": "failed", "error": "REMOTE_CREDENTIAL_REFLECTED"}
    assert intel.assertions(reader)["results"] == []
    assert intel.enrich_once(writer, store, generator) == {"status": "idle"}
    (record,) = ledger(roles)
    assert record["status"] == "completed" and record["error_code"] == "REMOTE_CREDENTIAL_REFLECTED"
    assert record["usage"] == ("reported" if reported_usage else "missing")
    exposure = cloud.exposure(writer, configured["route_id"], configured["pricebook"]["currency"])
    expected = record["estimated_cost"] if reported_usage else record["reserved"]
    assert exposure == expected and exposure > 0
    assert CANARY not in repr(record)
