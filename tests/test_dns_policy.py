"""Real resolver-process and TCP boundaries using authored DNS-answer fixtures."""

import json
import multiprocessing
import os
import socket
import struct
import threading
import time
from pathlib import Path

import httpcore
import pytest

from osint_workbench import fetch as acquisition
from osint_workbench.errors import WorkbenchError

ANSWERS = {
    "mixed-v4.fixture.invalid": ["93.184.216.34", "127.0.0.1"],
    "mixed-v6.fixture.invalid": ["93.184.216.34", "fc00::1"],
    "mapped-private.fixture.invalid": ["93.184.216.34", "::ffff:10.0.0.1"],
    "malformed.fixture.invalid": ["93.184.216.34", "not-an-address"],
    "empty.fixture.invalid": [],
    "pin.fixture.invalid": ["93.184.216.34", "8.8.8.8", "93.184.216.34"],
    "too-many.fixture.invalid": ["8.8.8.8"] * 65,
    "maximum.fixture.invalid": ["8.8.8.8"] * 64,
    "too-long.fixture.invalid": ["8" * 65],
    "non-list.fixture.invalid": {"addresses": ["8.8.8.8"]},
    "bad-member.fixture.invalid": [8],
    "limit-error.fixture.invalid": {"error": "DNS_LIMIT"},
    "invalid-error.fixture.invalid": {"error": "DNS_INVALID"},
    "unknown-error.fixture.invalid": {"error": "synthetic-secret-error-canary"},
}


@pytest.mark.parametrize("scheme", ["http", "https"])
def test_explicit_zero_port_is_rejected_before_any_backend_connection(monkeypatch, scheme):
    attempts = []

    def forbidden_connect(*args, **kwargs):
        attempts.append(True)
        raise AssertionError("explicit port zero reached a network backend")

    monkeypatch.setattr(acquisition._PublicBackend, "connect_tcp", forbidden_connect)
    with pytest.raises(WorkbenchError, match="^INVALID_SOURCE_URL$"):
        acquisition.fetch_response(f"{scheme}://feed.fixture.invalid:0/feed", timeout=1)
    assert attempts == []


def authored_resolver_child(host, port, pipe):
    """Spawn-importable raw resolver substitute, retaining the actual IPC path."""
    try:
        if host.startswith("hang:"):
            Path(host.removeprefix("hang:")).write_text("resolver-entered")
            threading.Event().wait(60)
        elif host.startswith("partial:"):
            Path(host.removeprefix("partial:")).write_text("resolver-entered")
            os.write(pipe.fileno(), struct.pack("!i", 100) + b"x")
            threading.Event().wait(60)
        elif host == "oversized-packet.fixture.invalid":
            os.write(pipe.fileno(), struct.pack("!i", 4097))
            threading.Event().wait(60)
        elif host == "truncated-packet.fixture.invalid":
            os.write(pipe.fileno(), struct.pack("!i", 100) + b"x")
        elif host == "malformed-json.fixture.invalid":
            pipe.send_bytes(b"[broken-json")
        else:
            pipe.send_bytes(json.dumps(ANSWERS[host], separators=(",", ":")).encode())
    finally:
        pipe.close()


def observe_spawn_children(monkeypatch):
    context = multiprocessing.get_context("spawn")
    children = []

    class ObservedContext:
        def Pipe(self, *args, **kwargs):
            return context.Pipe(*args, **kwargs)

        def Process(self, *args, **kwargs):
            process = context.Process(*args, **kwargs)
            children.append(process)
            return process

    monkeypatch.setattr(
        acquisition.multiprocessing, "get_context", lambda method: ObservedContext()
    )
    return children


def close_observed_children(children):
    for process in children:
        if process.is_alive():
            process.kill()
            process.join(timeout=2)
        process.close()


def receiver_threads():
    return {
        thread.ident
        for thread in threading.enumerate()
        if thread.name == "ow-dns-receiver" and thread.is_alive()
    }


@pytest.mark.parametrize(
    ("host", "code"),
    [
        ("mixed-v4.fixture.invalid", "DESTINATION_BLOCKED"),
        ("mixed-v6.fixture.invalid", "DESTINATION_BLOCKED"),
        ("mapped-private.fixture.invalid", "DESTINATION_BLOCKED"),
        ("malformed.fixture.invalid", "DNS_INVALID"),
        ("empty.fixture.invalid", "DNS_EMPTY"),
    ],
)
def test_real_spawn_rejects_entire_dns_answer_before_any_tcp_attempt(monkeypatch, host, code):
    attempts = []

    def forbidden_connect(*args, **kwargs):
        attempts.append(True)
        raise AssertionError("a prohibited DNS answer reached the TCP backend")

    monkeypatch.setattr(acquisition, "_resolve_child", authored_resolver_child)
    monkeypatch.setattr(httpcore.SyncBackend, "connect_tcp", forbidden_connect)
    with pytest.raises(WorkbenchError) as caught:
        acquisition._PublicBackend(time.monotonic() + 5).connect_tcp(host, 80)
    assert caught.value.code == code and str(caught.value) == code
    assert attempts == []


def test_real_spawn_resolver_deadline_terminates_entered_child(monkeypatch, tmp_path):
    children = observe_spawn_children(monkeypatch)
    before = receiver_threads()
    monkeypatch.setattr(acquisition, "_resolve_child", authored_resolver_child)
    marker = tmp_path / "resolver-started"
    started = time.monotonic()
    try:
        with pytest.raises(WorkbenchError, match="^FETCH_DEADLINE$"):
            acquisition.resolve("hang:" + str(marker), 80, started + 2)
        assert marker.read_text() == "resolver-entered"
        assert 1.5 <= time.monotonic() - started < 5
        assert len(children) == 1 and not children[0].is_alive()
        assert children[0].exitcode is not None and children[0].exitcode != 0
        assert receiver_threads() == before
    finally:
        close_observed_children(children)


def test_partial_ipc_frame_obeys_deadline_and_reaps_child_and_receiver(monkeypatch, tmp_path):
    children = observe_spawn_children(monkeypatch)
    monkeypatch.setattr(acquisition, "_resolve_child", authored_resolver_child)
    before = receiver_threads()
    marker = tmp_path / "partial-resolver-started"
    started = time.monotonic()
    try:
        with pytest.raises(WorkbenchError, match="^FETCH_DEADLINE$"):
            acquisition.resolve("partial:" + str(marker), 80, started + 0.5)
        assert marker.read_text() == "resolver-entered"
        assert 0.4 <= time.monotonic() - started < 1.25
        assert len(children) == 1 and not children[0].is_alive()
        assert children[0].exitcode is not None and children[0].exitcode != 0
        assert receiver_threads() == before
    finally:
        close_observed_children(children)


@pytest.mark.parametrize(
    ("host", "code"),
    [
        ("too-many.fixture.invalid", "DNS_LIMIT"),
        ("too-long.fixture.invalid", "DNS_LIMIT"),
        ("oversized-packet.fixture.invalid", "DNS_INVALID"),
        ("truncated-packet.fixture.invalid", "DNS_INVALID"),
        ("malformed-json.fixture.invalid", "DNS_INVALID"),
        ("non-list.fixture.invalid", "DNS_INVALID"),
        ("bad-member.fixture.invalid", "DNS_INVALID"),
        ("limit-error.fixture.invalid", "DNS_LIMIT"),
        ("invalid-error.fixture.invalid", "DNS_INVALID"),
        ("unknown-error.fixture.invalid", "DNS_INVALID"),
    ],
)
def test_real_spawn_rejects_oversized_or_invalid_resolver_packets(monkeypatch, host, code):
    children = observe_spawn_children(monkeypatch)
    monkeypatch.setattr(acquisition, "_resolve_child", authored_resolver_child)
    before = receiver_threads()
    started = time.monotonic()
    try:
        with pytest.raises(WorkbenchError) as caught:
            acquisition.resolve(host, 80, started + 2)
        assert caught.value.code == code and str(caught.value) == code
        assert "synthetic-secret-error-canary" not in repr(caught.value)
        assert time.monotonic() - started < 2.5
        assert len(children) == 1 and not children[0].is_alive()
        assert receiver_threads() == before
    finally:
        close_observed_children(children)


def test_real_spawn_accepts_full_sixty_four_address_boundary_before_deduplication(monkeypatch):
    monkeypatch.setattr(acquisition, "_resolve_child", authored_resolver_child)
    before = receiver_threads()
    assert acquisition.resolve("maximum.fixture.invalid", 80, time.monotonic() + 2) == ["8.8.8.8"]
    assert receiver_threads() == before


@pytest.mark.parametrize(
    ("addresses", "code"),
    [
        (["8.8.8.8"] * 65, "DNS_LIMIT"),
        (["synthetic-private-address-canary-" * 3], "DNS_LIMIT"),
        ([8], "DNS_INVALID"),
    ],
    ids=["record-count", "address-length", "address-type"],
)
def test_child_packet_encoder_emits_only_bounded_error_for_invalid_addresses(addresses, code):
    packet = acquisition._resolver_packet(addresses)
    assert type(packet) is bytes and len(packet) <= 4096
    assert json.loads(packet) == {"error": code}
    assert b"synthetic-private-address-canary" not in packet


def test_native_http_uses_validated_numeric_pin_and_original_host(monkeypatch):
    targets, requests, errors = [], [], []
    original_connect = httpcore.SyncBackend.connect_tcp
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(3)

        def serve():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(3)
                    request = bytearray()
                    while b"\r\n\r\n" not in request:
                        part = connection.recv(1024)
                        if not part:
                            raise RuntimeError("synthetic client closed before request")
                        request.extend(part)
                        if len(request) > 8192:
                            raise RuntimeError("synthetic request exceeded test bound")
                    requests.append(bytes(request))
                    connection.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nfixture!"
                    )
            except Exception as error:
                errors.append(type(error).__name__)

        def routed_connect(self, host, port, **kwargs):
            # Only the final socket destination is routed into the fixture. The
            # production backend must pass its validated numeric pin here, never
            # the original DNS label for another resolver lookup.
            targets.append((host, port))
            assert host == "93.184.216.34" and port == 80
            return original_connect(self, "127.0.0.1", listener.getsockname()[1], **kwargs)

        monkeypatch.setattr(acquisition, "_resolve_child", authored_resolver_child)
        monkeypatch.setattr(httpcore.SyncBackend, "connect_tcp", routed_connect)
        thread = threading.Thread(target=serve, name="synthetic-dns-pin-peer")
        thread.start()
        try:
            result = acquisition.fetch_response("http://pin.fixture.invalid/feed", timeout=5)
        finally:
            thread.join(timeout=4)
            assert not thread.is_alive(), "synthetic DNS-pin peer failed to stop"
        assert not errors and result.status == 200 and result.body == b"fixture!"
        assert targets == [("93.184.216.34", 80)]
        assert len(requests) == 1 and requests[0].startswith(b"GET /feed HTTP/1.1\r\n")
        assert b"\r\nHost: pin.fixture.invalid\r\n" in requests[0]
        assert b"\r\nHost: 93.184.216.34\r\n" not in requests[0]
