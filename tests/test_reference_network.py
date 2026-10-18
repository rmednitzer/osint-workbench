"""Native loopback protocol checks; never create or enter a network namespace."""

import importlib.util
import socket
import threading
import time
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/reference_network.py"


def load_helper():
    spec = importlib.util.spec_from_file_location("reference_network_protocol_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def network_helper():
    return load_helper()


def exchange(helper, phase, request, *, deadline=None, api=False):
    records, errors = [], []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(3)

        def receive():
            try:
                connection, _ = listener.accept()
                with connection:
                    if api:
                        helper.handle_api_connection(
                            connection,
                            phase,
                            b"synthetic-fixture-token",
                            records.append,
                            deadline=deadline,
                        )
                    else:
                        helper.handle_connection(
                            connection, phase, records.append, deadline=deadline
                        )
            except Exception as error:
                errors.append(type(error).__name__)

        thread = threading.Thread(target=receive, name="synthetic-reference-http-peer")
        thread.start()
        try:
            with socket.create_connection(listener.getsockname(), timeout=4) as client:
                client.sendall(request)
                response = bytearray()
                reset = False
                while True:
                    try:
                        block = client.recv(8192)
                    except ConnectionResetError:
                        # Refusing an oversized request can leave unread input
                        # and reset TCP. Accept only a complete bounded response;
                        # framing/content-length checks below still apply.
                        reset = True
                        break
                    if not block:
                        break
                    response.extend(block)
                    assert len(response) <= 32768, "fixture response exceeded its bound"
        finally:
            thread.join(timeout=4)
            assert not thread.is_alive(), "fixture protocol handler failed to stop"
        assert not errors, "fixture protocol handler raised unexpectedly"
    headers, separator, body = bytes(response).partition(b"\r\n\r\n")
    assert separator, "fixture response omitted complete HTTP framing"
    lines = headers.decode("ascii").split("\r\n")
    status = int(lines[0].split()[1])
    fields = {}
    for line in lines[1:]:
        name, value = line.split(":", 1)
        assert name.lower() not in fields, "fixture response duplicated a header"
        fields[name.lower()] = value.strip()
    assert fields["connection"].lower() == "close"
    assert int(fields["content-length"]) == len(body)
    if reset:
        assert status == 400 and body == b"" and records == []
    return status, fields, body, records


def request(*headers):
    return (
        "GET /feed HTTP/1.1\r\nHost: feed.fixture.invalid\r\n"
        + "".join(header + "\r\n" for header in headers)
        + "\r\n"
    ).encode("ascii")


def test_native_fixture_conditional_refresh_and_failure_phases(network_helper):
    status, headers, first, records = exchange(network_helper, "v1", request())
    assert status == 200 and first == network_helper.FEED_V1
    assert headers["etag"] == '"v1"'
    assert len(records) == 1 and records[0]["phase"] == "v1" and records[0]["status"] == 200

    status, conditional_headers, body, records = exchange(
        network_helper,
        "v1",
        request('If-None-Match: "v1"', "If-Modified-Since: " + headers["last-modified"]),
    )
    assert status == 304 and body == b""
    assert conditional_headers["etag"] == '"v1"'
    assert records == [
        {
            "phase": "v1",
            "status": 304,
            "if_none_match": '"v1"',
            "if_modified_since": headers["last-modified"],
        }
    ]

    # A stale ETag must not hide a changed body merely because a Last-Modified
    # validator is also supplied. These versions deliberately share a timestamp.
    status, refreshed_headers, second, records = exchange(
        network_helper,
        "v2",
        request('If-None-Match: "v1"', "If-Modified-Since: " + headers["last-modified"]),
    )
    assert status == 200 and second == network_helper.FEED_V2 and second != first
    assert refreshed_headers["etag"] == '"v2"'
    assert records[0]["if_none_match"] == '"v1"'

    status, _, body, records = exchange(network_helper, "v2", request('If-None-Match: "v2"'))
    assert status == 304 and body == b"" and records[0]["status"] == 304
    status, _, _, records = exchange(network_helper, "fail", request('If-None-Match: "v2"'))
    assert status == 503 and records[0]["phase"] == "fail" and records[0]["status"] == 503


@pytest.mark.parametrize(
    "invalid",
    [
        b"POST /feed HTTP/1.1\r\nHost: feed.fixture.invalid\r\n\r\n",
        b"GET /other HTTP/1.1\r\nHost: feed.fixture.invalid\r\n\r\n",
        b"GET /feed HTTP/1.0\r\nHost: feed.fixture.invalid\r\n\r\n",
        request("X-Long: " + "a" * 8192),
        request(*(f"X-{index}: value" for index in range(17))),
        b"GET /" + b"a" * 512 + b" HTTP/1.1\r\nHost: feed.fixture.invalid\r\n\r\n",
        request("If-None-Match: bad\x01value"),
    ],
    ids=["method", "path", "version", "header-bytes", "header-count", "request-line", "control"],
)
def test_native_fixture_rejects_invalid_requests_before_recording(network_helper, invalid):
    status, _, body, records = exchange(network_helper, "v1", invalid)
    assert status == 400 and body == b"" and records == []


def test_import_and_unguarded_serve_never_create_a_socket(monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)

    def forbidden_socket(*args, **kwargs):
        raise AssertionError("unguarded fixture attempted socket creation")

    monkeypatch.setattr(socket, "socket", forbidden_socket)
    helper = load_helper()
    with pytest.raises(RuntimeError):
        helper.serve(0, 0)


def test_native_fixture_accepts_the_declared_header_count_boundary(network_helper):
    status, _, body, records = exchange(
        network_helper, "v1", request(*(f"X-{index}: value" for index in range(15)))
    )
    assert status == 200 and body == network_helper.FEED_V1 and len(records) == 1


def test_fixture_rejects_unknown_phase_before_socket_io(network_helper):
    with pytest.raises(ValueError):
        network_helper.handle_connection(None, "unknown", lambda _record: None)


def test_native_fixture_expired_server_deadline_refuses_valid_request(network_helper):
    started = time.monotonic()
    status, _, body, records = exchange(network_helper, "v1", request(), deadline=started - 1)
    assert status == 400 and body == b"" and records == []
    assert time.monotonic() - started < 1


@pytest.mark.parametrize(
    "phase,path,token,status",
    [
        ("v1", "/records", "synthetic-fixture-token", 200),
        ("v2", "/records?cursor=page-2", "synthetic-fixture-token", 200),
        ("fail", "/records", "synthetic-fixture-token", 503),
        ("v1", "/records", "synthetic-invalid-token", 401),
        ("v2", "/records", "synthetic-fixture-token", 400),
    ],
)
def test_api_peer_records_only_status_and_booleans(network_helper, phase, path, token, status):
    wire = (
        f"GET {path} HTTP/1.1\r\nHost: feed.fixture.invalid\r\n"
        f"Authorization: Bearer {token}\r\n\r\n"
    ).encode()
    observed, headers, body, records = exchange(network_helper, phase, wire, api=True)
    assert observed == status and headers["content-type"] == "application/json"
    assert body == (network_helper.API_PAGES[phase] if status == 200 else b"")
    assert records == [
        {
            "phase": phase,
            "status": status,
            "authorized": token == "synthetic-fixture-token",
            "path_ok": path == ("/records?cursor=page-2" if phase == "v2" else "/records"),
        }
    ]
    if status == 503:
        assert headers["retry-after"] == "120"


def test_api_fixture_guard_precedes_tls_or_listener_creation(monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)

    def forbidden(*args, **kwargs):
        raise AssertionError("unguarded fixture attempted TLS or listener creation")

    helper = load_helper()
    monkeypatch.setattr(helper.ssl, "SSLContext", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    with pytest.raises(RuntimeError):
        helper.serve(0, 0, api=True)
