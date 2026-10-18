"""Confidential-client contract and actual synthetic authorization/resource TLS."""

import base64
import json
import time
from urllib.parse import urlunsplit

import pytest
from pydantic import ValidationError

from osint_workbench.api_acquisition import ApiAuth, ApiSource, _page
from osint_workbench.errors import SourceHTTPError, WorkbenchError
from osint_workbench.oauth import OAuthClient, obtain_token, parse_token
from osint_workbench.text import digest
from tests.test_api_transport import response, source
from tests.tls_fixture import generate_certificates, tls_peer

CLIENT_SECRET = "synthetic-client:secret+%/canary"
ACCESS_TOKEN = "synthetic.access-token_canary-481"


def client(**changes):
    return OAuthClient(
        **{
            "token_endpoint": "https://auth.fixture.invalid/token",
            "client_id": "synthetic-client:+%/",
            "scopes": ["records:read", "catalog:read"],
        }
        | changes
    )


def token_response(**changes):
    return json.dumps(
        {
            "access_token": ACCESS_TOKEN,
            "token_type": "Bearer",
            "expires_in": 300,
            "scope": "catalog:read records:read",
        }
        | changes
    ).encode()


@pytest.fixture(scope="module")
def oauth_certificates(tmp_path_factory):
    return generate_certificates(tmp_path_factory.mktemp("oauth-certs") / "certs")


def test_actual_tls_encoded_client_auth_and_resource_token_separation(
    monkeypatch, oauth_certificates
):
    from osint_workbench.credentials import CredentialRef

    auth = ApiAuth(
        kind="oauth-client-credentials",
        context="synthetic-account",
        credential=CredentialRef(kind="file", path="/synthetic/secret"),
        oauth=client(),
    )
    with tls_peer(
        monkeypatch, oauth_certificates, wires=[response(token_response()), response()]
    ) as peer:
        grant = obtain_token(client(), CLIENT_SECRET, time.monotonic() + 8)
        assert grant.token.get_secret_value() == ACCESS_TOKEN
        _page(source(auth=auth), None, grant.token.get_secret_value(), grant.expires_at)
    assert peer.sni == ["auth.fixture.invalid", "feed.fixture.invalid"]
    assert len(peer.requests) == 2
    expected = base64.b64encode(
        b"synthetic-client%3A%2B%25%2F:synthetic-client%3Asecret%2B%25%2Fcanary"
    )
    assert peer.requests[0].startswith(b"POST /token HTTP/1.1\r\n")
    assert b"Authorization: Basic " + expected in peer.requests[0]
    assert b"Content-Type: application/x-www-form-urlencoded" in peer.requests[0]
    assert peer.bodies == [
        b"grant_type=client_credentials&scope=records%3Aread+catalog%3Aread",
        b"",
    ]
    assert b"Authorization: Bearer " + ACCESS_TOKEN.encode() in peer.requests[1]
    assert b"Basic" not in peer.requests[1] and CLIENT_SECRET.encode() not in peer.requests[1]
    assert ACCESS_TOKEN not in repr(grant)


@pytest.mark.parametrize(
    "changes",
    [
        {"token_endpoint": "http://auth.fixture.invalid/token"},
        {"token_endpoint": "https://auth.fixture.invalid/token?"},
        {"token_endpoint": "https://auth.fixture.invalid/token#"},
        {"token_endpoint": "https://user:secret@auth.fixture.invalid/token"},
        {"token_endpoint": urlunsplit(("https", "127.0.0.1", "/token", "", ""))},
        {"client_id": "space forbidden"},
        {"client_id": "\n"},
        {"client_id": "\udfff"},
        {"scopes": []},
        {"scopes": ["read", "read"]},
        {"scopes": ["read write"]},
        {"scopes": ["read\\write"]},
        {"scopes": ['read"']},
        {"scopes": [1]},
        {"scopes": ["x" * 129]},
        {"scopes": [str(n) for n in range(33)]},
    ],
)
def test_private_configuration_is_bounded_and_explicit(changes):
    with pytest.raises((ValidationError, WorkbenchError)):
        client(**changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"access_token": ""},
        {"access_token": "x" * 4097},
        {"access_token": "has space"},
        {"access_token": "header\r\ninjection"},
        {"access_token": "\udfff"},
        {"access_token": "a=b"},
        {"access_token": 1},
        {"token_type": "DPoP"},
        {"token_type": None},
        {"expires_in": True},
        {"expires_in": "300"},
        {"expires_in": 0},
        {"expires_in": 86401},
        {"expires_in": 1.5},
        {"scope": "records:read"},
        {"scope": "catalog:read records:read admin"},
        {"scope": "catalog:read records:read records:read"},
        {"scope": " records:read catalog:read"},
        {"scope": ["records:read", "catalog:read"]},
        {"error": "private-response-canary"},
    ],
)
def test_invalid_grants_and_changed_scopes_fail_closed(changes):
    with pytest.raises(WorkbenchError, match="^OAUTH_INVALID_RESPONSE$"):
        parse_token(token_response(**changes), client(), time.monotonic())


def test_missing_fields_duplicate_keys_bounds_and_inert_extensions():
    for name in ("access_token", "token_type", "expires_in"):
        value = json.loads(token_response())
        del value[name]
        with pytest.raises(WorkbenchError, match="^OAUTH_INVALID_RESPONSE$"):
            parse_token(json.dumps(value).encode(), client(), time.monotonic())
    for raw in [
        b"[]",
        b"\xff",
        b"x" * 16385,
        b"[" * 33 + b"0" + b"]" * 33,
        b'{"access_token":"duplicate",' + token_response()[1:],
    ]:
        with pytest.raises(WorkbenchError, match="^OAUTH_INVALID_RESPONSE$"):
            parse_token(raw, client(), time.monotonic())
    value = json.loads(token_response())
    del value["scope"]
    # RFC 6749 permits omitted unchanged scope and requires ignoring extensions.
    value.update(refresh_token="unused-refresh-canary", id_token="unused-id-canary", extra={"x": 1})
    grant = parse_token(json.dumps(value).encode(), client(), time.monotonic())
    assert grant.token.get_secret_value() == ACCESS_TOKEN
    assert not hasattr(grant, "refresh_token") and "unused" not in repr(grant)
    with pytest.raises(WorkbenchError, match="^OAUTH_TOKEN_EXPIRED$"):
        parse_token(token_response(expires_in=1), client(), time.monotonic() - 2)


@pytest.mark.parametrize(
    "status,headers,error",
    [
        (b"400 Bad Request", b"", "OAUTH_TOKEN_REJECTED"),
        (b"401 Unauthorized", b"", "OAUTH_TOKEN_REJECTED"),
        (
            b"302 Found",
            b"Location: https://other.fixture.invalid/token\r\n",
            "OAUTH_REDIRECT_REFUSED",
        ),
        (b"200 OK", b"Content-Encoding: gzip\r\n", "OAUTH_INVALID_RESPONSE"),
    ],
)
def test_actual_tls_refusals_are_fixed_without_retry(
    monkeypatch, oauth_certificates, status, headers, error
):
    with tls_peer(
        monkeypatch, oauth_certificates, wire=response(b"private-canary", status, headers)
    ) as peer:
        with pytest.raises(WorkbenchError) as caught:
            obtain_token(client(), CLIENT_SECRET, time.monotonic() + 5)
    assert caught.value.args == (error,) and peer.connections == 1


def test_actual_tls_token_response_budget_and_retry_after(monkeypatch, oauth_certificates):
    with tls_peer(monkeypatch, oauth_certificates, wire=response(b"x" * 16385)):
        with pytest.raises(WorkbenchError, match="^OAUTH_RESPONSE_TOO_LARGE$"):
            obtain_token(client(), CLIENT_SECRET, time.monotonic() + 5)
    with tls_peer(
        monkeypatch,
        oauth_certificates,
        wire=response(status=b"503 Unavailable", headers=b"Retry-After: 120\r\n"),
    ):
        with pytest.raises(SourceHTTPError) as caught:
            obtain_token(client(), CLIENT_SECRET, time.monotonic() + 5)
    assert caught.value.retry_after_seconds == 120


@pytest.mark.parametrize("kind,trust", [("wrong", True), ("expired", True), ("valid", False)])
def test_actual_token_endpoint_tls_failure_sends_no_client_auth(
    monkeypatch, oauth_certificates, kind, trust
):
    with tls_peer(
        monkeypatch,
        oauth_certificates,
        kind=kind,
        trust_fixture=trust,
        wire=response(token_response()),
    ) as peer:
        with pytest.raises(WorkbenchError, match="^OAUTH_UNAVAILABLE$"):
            obtain_token(client(), CLIENT_SECRET, time.monotonic() + 5)
    assert peer.requests == []


def test_existing_profile_serialization_does_not_reset_continuation():
    configuration = ApiSource(
        source_id="fixture",
        endpoint="https://api.example.invalid/records",
        rights="all-existing-uses-permitted",
        request_billing="unmetered",
    )
    assert "oauth" not in configuration.model_dump_json()
    assert (
        digest(configuration.model_dump_json().encode())
        == "a7560d046599c32a6523692a2f8a759183cdd0c306f01b576d7a91d265e95e46"
    )


def test_authentication_modes_cannot_mix_authorities():
    from osint_workbench.credentials import CredentialRef

    ref = CredentialRef(kind="file", path="/synthetic/token")
    for values in [
        dict(kind="oauth-client-credentials", credential=ref),
        dict(kind="bearer", credential=ref, oauth=client()),
        dict(kind="none", oauth=client()),
        dict(kind="oauth-client-credentials", oauth=client()),
    ]:
        with pytest.raises(ValidationError):
            ApiAuth(**values, context="synthetic-account")
