"""Native TLS with configured fixture trust; no public CA/live-network claim."""

import ssl
import time

import httpcore
import pytest

from osint_workbench import fetch as acquisition
from osint_workbench.errors import WorkbenchError
from tests.tls_fixture import generate_certificates, tls_peer


@pytest.fixture(scope="module")
def certificates(tmp_path_factory):
    return generate_certificates(tmp_path_factory.mktemp("tls-parent") / "pki")


def safe_error(caught):
    assert caught.value.code in {"SOURCE_UNAVAILABLE", "FETCH_DEADLINE"}
    assert caught.value.args == (caught.value.code,)
    assert "fixture.invalid" not in repr(caught.value)
    assert "BEGIN" not in repr(caught.value)


def test_default_tls_context_requires_certificates_and_hostnames():
    context = httpcore.default_ssl_context()
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname


def test_native_tls_valid_chain_origin_sni_and_http_host(certificates, monkeypatch):
    with tls_peer(monkeypatch, certificates) as peer:
        assert acquisition.fetch("https://feed.fixture.invalid/feed", timeout=2) == b"TLS evidence"
    assert peer.sni == ["feed.fixture.invalid"]
    assert len(peer.requests) == 1
    assert peer.requests[0].startswith(b"GET /feed HTTP/1.1\r\n")
    assert b"Host: feed.fixture.invalid\r\n" in peer.requests[0]
    assert peer.handshake_failures == 0


@pytest.mark.parametrize(
    "kind,trust_fixture", [("wrong", True), ("valid", False), ("expired", True)]
)
def test_native_tls_refuses_hostname_untrusted_chain_and_expiry(
    certificates, monkeypatch, kind, trust_fixture
):
    with tls_peer(monkeypatch, certificates, kind=kind, trust_fixture=trust_fixture) as peer:
        with pytest.raises(WorkbenchError) as caught:
            acquisition.fetch("https://feed.fixture.invalid/feed", timeout=2)
    safe_error(caught)
    assert peer.sni == ["feed.fixture.invalid"]
    assert peer.requests == []
    assert peer.handshake_failures == 1


def test_native_tls_refuses_plaintext_peer(certificates, monkeypatch):
    with tls_peer(monkeypatch, certificates, mode="plaintext") as peer:
        with pytest.raises(WorkbenchError) as caught:
            acquisition.fetch("https://feed.fixture.invalid/feed", timeout=1)
    safe_error(caught)
    assert peer.requests == []


def test_native_tls_handshake_stall_respects_absolute_transport_deadline(certificates, monkeypatch):
    with tls_peer(monkeypatch, certificates, mode="stall") as peer:
        started = time.monotonic()
        with pytest.raises(WorkbenchError) as caught:
            acquisition.fetch("https://feed.fixture.invalid/feed", timeout=0.25)
        elapsed = time.monotonic() - started
    safe_error(caught)
    assert elapsed < 1.25, "TLS handshake escaped its absolute request budget"
    assert peer.sni == [] and peer.requests == []


def test_native_tls_redirect_refuses_https_downgrade_before_another_request(
    certificates, monkeypatch
):
    wire = (
        b"HTTP/1.1 302 Found\r\nLocation: http://feed.fixture.invalid/other\r\n"
        b"Content-Length: 0\r\nConnection: close\r\n\r\n"
    )
    with tls_peer(monkeypatch, certificates, wire=wire) as peer:
        with pytest.raises(WorkbenchError, match="INSECURE_REDIRECT"):
            acquisition.fetch("https://feed.fixture.invalid/feed", timeout=2)
    assert peer.sni == ["feed.fixture.invalid"]
    assert len(peer.requests) == 1
    assert peer.requests[0].startswith(b"GET /feed HTTP/1.1\r\n")


def test_native_tls_body_drip_cannot_extend_absolute_request_deadline(certificates, monkeypatch):
    with tls_peer(monkeypatch, certificates, mode="drip") as peer:
        started = time.monotonic()
        with pytest.raises(WorkbenchError) as caught:
            acquisition.fetch("https://feed.fixture.invalid/feed", timeout=0.25)
        elapsed = time.monotonic() - started
    safe_error(caught)
    assert elapsed < 1.25, "TLS body reads escaped their absolute request budget"
    assert peer.sni == ["feed.fixture.invalid"] and len(peer.requests) == 1
    assert peer.handshake_failures == 0
    assert 1 <= peer.body_bytes_sent < 1024
