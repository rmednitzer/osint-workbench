"""Ambiguous response framing fails closed through the actual HTTP client path."""

import httpcore
import pytest

from osint_workbench import fetch as acquisition
from osint_workbench.errors import WorkbenchError


class RawWire:
    """One connection that returns exact response bytes after a full request head."""

    def __init__(self, response: bytes):
        self.response = response
        self.request = bytearray()

    def write(self, buffer, timeout=None):
        self.request.extend(buffer)

    def read(self, max_bytes, timeout=None):
        assert b"\r\n\r\n" in self.request
        result, self.response = self.response[:max_bytes], self.response[max_bytes:]
        return result

    def start_tls(self, *args, **kwargs):
        # Framing is under test here; native TLS identity has its own fixtures.
        return self

    def close(self):
        pass

    def get_extra_info(self, info):
        return None


class Backend(httpcore.SyncBackend):
    def __init__(self, wires):
        self.wires = wires

    def connect_tcp(self, *args, **kwargs):
        return self.wires.pop(0)


def install(monkeypatch, *responses):
    wires = [RawWire(response) for response in responses]
    backend = Backend(list(wires))
    monkeypatch.setattr(acquisition, "_PublicBackend", lambda _: backend)
    return wires


def ok(body=b"evidence", extra=b""):
    return b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n%s\r\n%s" % (len(body), extra, body)


def redirect(*locations):
    fields = b"".join(b"Location: " + location + b"\r\n" for location in locations)
    return b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\n" + fields + b"\r\n"


@pytest.mark.parametrize(
    "fields",
    [
        b"Content-Encoding: gzip\r\nContent-Encoding: identity\r\n",
        b"Content-Encoding: identity\r\nContent-Encoding: identity\r\n",
        b"Content-Encoding: gzip\r\n",
    ],
)
def test_repeated_or_non_identity_content_encoding_is_refused(monkeypatch, fields):
    install(monkeypatch, ok(b"\x1f\x8bpayload", fields))
    with pytest.raises(WorkbenchError, match="UNSUPPORTED_CONTENT_ENCODING"):
        acquisition.fetch("https://example.invalid/feed")


def test_single_identity_content_encoding_is_accepted(monkeypatch):
    install(monkeypatch, ok(extra=b"Content-Encoding: identity\r\n"))
    assert acquisition.fetch("https://example.invalid/feed") == b"evidence"


def test_repeated_location_is_refused_before_following(monkeypatch):
    wires = install(monkeypatch, redirect(b"/a", b"/b"), ok())
    with pytest.raises(WorkbenchError, match="INVALID_REDIRECT"):
        acquisition.fetch("https://example.invalid/feed")
    assert wires[1].request == b""


def test_non_ascii_location_is_a_typed_redirect_error(monkeypatch):
    install(monkeypatch, redirect(b"/caf\xc3\xa9"))
    with pytest.raises(WorkbenchError, match="INVALID_REDIRECT"):
        acquisition.fetch("https://example.invalid/feed")


def test_redirect_fragment_is_dropped_from_the_requested_target(monkeypatch):
    wires = install(monkeypatch, redirect(b"/moved?x=1#section"), ok())
    result = acquisition.fetch_response("https://example.invalid/feed", etag='"v1"')
    assert result.body == b"evidence"
    # Redirected representations never seed validators for the configured URI.
    assert result.etag is None and result.last_modified is None
    head = bytes(wires[1].request).split(b"\r\n")[0]
    assert head == b"GET /moved?x=1 HTTP/1.1"


def test_redirect_fragment_does_not_permit_tls_downgrade(monkeypatch):
    wires = install(monkeypatch, redirect(b"http://example.invalid/#x"), ok())
    with pytest.raises(WorkbenchError, match="INSECURE_REDIRECT"):
        acquisition.fetch("https://example.invalid/feed")
    assert wires[1].request == b""


@pytest.mark.parametrize("address", ["fec0::1", "fec0:1::abcd", "feff::1"])
def test_deprecated_site_local_ipv6_is_blocked(address):
    with pytest.raises(WorkbenchError, match="DESTINATION_BLOCKED"):
        acquisition.public_addresses([address])
