"""Actual synthetic TLS transport and explicit API configuration boundaries."""

import time

import pytest
from pydantic import ValidationError

from osint_workbench import fetch
from osint_workbench.api_acquisition import ApiAuth, ApiSource, _page, collect_api
from osint_workbench.credentials import CredentialRef
from osint_workbench.errors import SourceHTTPError, WorkbenchError
from tests.tls_fixture import generate_certificates, tls_peer


@pytest.fixture(scope="module")
def api_certificates(tmp_path_factory):
    return generate_certificates(tmp_path_factory.mktemp("api-transport") / "certs")


def source(**changes):
    return ApiSource(
        **(
            {
                "source_id": "api-fixture",
                "endpoint": "https://feed.fixture.invalid/records",
                "enabled": True,
                "rights": "all-existing-uses-permitted",
                "request_billing": "unmetered",
            }
            | changes
        )
    )


def response(body=b'{"items":[],"next_cursor":null}', status=b"200 OK", headers=b""):
    return (
        b"HTTP/1.1 "
        + status
        + b"\r\nContent-Type: application/json\r\n"
        + headers
        + b"Content-Length: "
        + str(len(body)).encode()
        + b"\r\nConnection: close\r\n\r\n"
        + body
    )


def test_actual_tls_escapes_cursor_and_binds_authorization(monkeypatch, api_certificates):
    auth = ApiAuth(
        kind="bearer",
        context="synthetic-provider",
        credential=CredentialRef(kind="file", path="/synthetic/token"),
    )
    expected = b'{"items":[],"next_cursor":null}'
    with tls_peer(monkeypatch, api_certificates, wire=response(expected)) as peer:
        assert (
            _page(source(auth=auth), "a +/%?&=#", "synthetic-token", time.monotonic() + 5)
            == expected
        )
    assert peer.sni == ["feed.fixture.invalid"]
    request = peer.requests[0]
    assert request.startswith(b"GET /records?cursor=a+%2B%2F%25%3F%26%3D%23 HTTP/1.1\r\n")
    assert b"Authorization: Bearer synthetic-token\r\n" in request
    assert b"Accept-Encoding: identity\r\n" in request


@pytest.mark.parametrize("kind,header", [("none", None), ("api-key", b"apiKey: synthetic-token")])
def test_actual_tls_auth_profiles(monkeypatch, api_certificates, kind, header):
    auth = (
        ApiAuth()
        if kind == "none"
        else ApiAuth(
            kind=kind,
            header="apiKey",
            context="synthetic-provider",
            credential=CredentialRef(kind="file", path="/synthetic/token"),
        )
    )
    with tls_peer(monkeypatch, api_certificates, wire=response()) as peer:
        _page(source(auth=auth), None, "synthetic-token", time.monotonic() + 5)
    assert b"Authorization:" not in peer.requests[0]
    if header:
        assert header in peer.requests[0]
    else:
        assert b"synthetic-token" not in peer.requests[0]


@pytest.mark.parametrize(
    "status,headers,error",
    [
        (b"401 Unauthorized", b"", "API_AUTHENTICATION_FAILED"),
        (b"403 Forbidden", b"", "API_ENTITLEMENT_DENIED"),
        (
            b"302 Found",
            b"Location: https://other.fixture.invalid/secret\r\n",
            "API_REDIRECT_REFUSED",
        ),
        (b"500 Error", b"", "API_HTTP_ERROR"),
        (b"200 OK", b"Content-Encoding: gzip\r\n", "UNSUPPORTED_CONTENT_ENCODING"),
        (b"200 OK", b"Content-Type: text/plain\r\n", "API_MEDIA_TYPE_INVALID"),
    ],
)
def test_actual_tls_failures_are_fixed_and_redirects_not_followed(
    monkeypatch, api_certificates, status, headers, error
):
    with tls_peer(
        monkeypatch,
        api_certificates,
        wire=response(b"synthetic-private-response-canary", status, headers),
    ) as peer:
        with pytest.raises(WorkbenchError) as caught:
            _page(source(), None, "", time.monotonic() + 5)
    assert caught.value.args == (error,)
    assert peer.connections == len(peer.requests) == 1


def test_actual_tls_retry_after_is_typed(monkeypatch, api_certificates):
    with tls_peer(
        monkeypatch,
        api_certificates,
        wire=response(status=b"429 Too Many Requests", headers=b"Retry-After: 123\r\n"),
    ):
        with pytest.raises(SourceHTTPError) as caught:
            _page(source(), None, "", time.monotonic() + 5)
    assert caught.value.args == ("SOURCE_HTTP_ERROR",)
    assert caught.value.retry_after_seconds == 123


@pytest.mark.parametrize("kind,trust", [("wrong", True), ("expired", True), ("valid", False)])
def test_actual_tls_rejects_untrusted_or_wrong_peer(monkeypatch, api_certificates, kind, trust):
    with tls_peer(
        monkeypatch, api_certificates, kind=kind, trust_fixture=trust, wire=response()
    ) as peer:
        with pytest.raises(WorkbenchError, match="^API_UNAVAILABLE$"):
            _page(source(), None, "", time.monotonic() + 5)
    assert peer.requests == []


def test_actual_tls_byte_budget_before_parsing(monkeypatch, api_certificates):
    monkeypatch.setattr(fetch, "MAX_BYTES", 16)
    with tls_peer(monkeypatch, api_certificates, wire=response(b"x" * 100)):
        with pytest.raises(WorkbenchError, match="^SOURCE_TOO_LARGE$"):
            _page(source(), None, "", time.monotonic() + 5)


@pytest.mark.parametrize(
    "changes",
    [
        {"endpoint": "http://feed.fixture.invalid/records"},
        {"endpoint": "https://feed.fixture.invalid/records?secret=x"},
        {"rights": "retention-only"},
        {"request_billing": "metered"},
    ],
)
def test_unsupported_destination_rights_or_billing_rejected(changes):
    with pytest.raises((ValidationError, WorkbenchError)):
        source(**changes)


@pytest.mark.parametrize("limit", [0, 2, 8, 9, True, 1.5])
def test_page_budget_refused_before_database_or_network(limit):
    with pytest.raises(WorkbenchError, match="^API_LIMIT_INVALID$"):
        collect_api(source(), None, None, max_pages=limit)
