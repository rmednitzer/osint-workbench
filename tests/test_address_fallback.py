"""Ordered numeric-pin fallback over real loopback TCP/TLS, without public I/O."""

import socket
import ssl
import threading
import time
from contextlib import contextmanager

import httpcore
import httpcore._sync.connection as http_connection
import pytest

from osint_workbench import fetch as acquisition
from osint_workbench.errors import WorkbenchError
from tests.tls_fixture import generate_certificates

V6 = "2606:4700:4700::1111"
V4 = "93.184.216.34"


@contextmanager
def native_peer(*, bundle=None, kind="valid"):
    stop = threading.Event()
    requests, names, errors = [], [], []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        listener.settimeout(0.05)
        context = None
        if bundle is not None:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(bundle.leaves[kind]["cert"], bundle.leaves[kind]["key"])
            context.set_servername_callback(lambda _socket, name, _ctx: names.append(name))

        def serve():
            try:
                while not stop.is_set():
                    try:
                        connection, _ = listener.accept()
                        break
                    except TimeoutError:
                        continue
                else:
                    return
                with connection:
                    connection.settimeout(1)
                    try:
                        stream = (
                            context.wrap_socket(connection, server_side=True)
                            if context
                            else connection
                        )
                    except ssl.SSLError:
                        return
                    with stream:
                        data = bytearray()
                        deadline = time.monotonic() + 1
                        while b"\r\n\r\n" not in data:
                            remaining = deadline - time.monotonic()
                            if remaining <= 0:
                                raise RuntimeError("fixture request deadline")
                            stream.settimeout(remaining)
                            piece = stream.recv(1024)
                            if not piece:
                                raise RuntimeError("fixture request truncated")
                            data.extend(piece)
                            if len(data) > 8192:
                                raise RuntimeError("fixture request limit")
                        requests.append(bytes(data))
                        stream.sendall(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n"
                            b"Connection: close\r\n\r\nfixture!"
                        )
            except Exception as exc:
                errors.append(type(exc).__name__)

        thread = threading.Thread(target=serve, name="synthetic-address-fallback")
        thread.start()
        try:
            yield listener.getsockname(), requests, names
        finally:
            stop.set()
            thread.join(timeout=2)
            assert not thread.is_alive() and not errors, "synthetic fallback peer failed"


@contextmanager
def native_closed_port(*, ipv6=False):
    with socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_STREAM) as reserved:
        reserved.bind(("::1" if ipv6 else "127.0.0.1", 0))
        yield reserved.getsockname()[:2]


@contextmanager
def native_blackhole():
    # A full Linux loopback accept queue makes another real TCP handshake time
    # out. This tests a connect timeout, not a post-connect HTTP read stall.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(0)
        with socket.create_connection(listener.getsockname(), timeout=1):
            yield listener.getsockname()


def route(monkeypatch, answers, targets):
    original = httpcore.SyncBackend.connect_tcp
    calls, failures = [], []
    monkeypatch.setattr(acquisition, "resolve", lambda *_: answers)

    def connect(self, host, port, **kwargs):
        assert host in targets and port in (80, 443)
        calls.append((host, kwargs["timeout"]))
        target = targets[host]
        try:
            return original(self, target[0], target[1], **kwargs)
        except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
            failures.append(type(exc))
            raise

    monkeypatch.setattr(httpcore.SyncBackend, "connect_tcp", connect)
    return calls, failures


def test_public_answer_validation_preserves_family_order_and_canonical_deduplication():
    assert acquisition.public_addresses([V6, V4, V6, "::ffff:" + V4]) == [V6, V4]


def test_native_primary_ipv6_refusal_falls_back_without_changing_http_origin(monkeypatch):
    with native_closed_port(ipv6=True) as refused, native_peer() as (good, requests, _):
        calls, failures = route(monkeypatch, [V6, V4], {V6: refused, V4: good})
        assert acquisition.fetch("http://feed.fixture.invalid/feed", timeout=2) == b"fixture!"
    assert [c[0] for c in calls] == [V6, V4] and failures == [httpcore.ConnectError]
    assert b"\r\nHost: feed.fixture.invalid\r\n" in requests[0]
    assert requests[0].startswith(b"GET /feed HTTP/1.1\r\n")


def test_native_primary_connect_timeout_leaves_budget_for_reachable_fallback(monkeypatch):
    with native_blackhole() as blackhole, native_peer() as (good, requests, _):
        calls, failures = route(monkeypatch, [V6, V4], {V6: blackhole, V4: good})
        started = time.monotonic()
        assert acquisition.fetch("http://feed.fixture.invalid/feed", timeout=0.6) == b"fixture!"
        elapsed = time.monotonic() - started
    assert [c[0] for c in calls] == [V6, V4] and failures == [httpcore.ConnectTimeout]
    assert calls[0][1] <= 0.3 and elapsed < 1.5
    assert len(requests) == 1


def test_native_exhaustion_stays_inside_one_absolute_budget(monkeypatch):
    with native_blackhole() as blackhole:
        calls, failures = route(monkeypatch, [V6, V4], {V6: blackhole, V4: blackhole})
        started = time.monotonic()
        with pytest.raises(WorkbenchError) as caught:
            acquisition.fetch("http://feed.fixture.invalid/feed", timeout=0.3)
        elapsed = time.monotonic() - started
    assert caught.value.code in {"FETCH_DEADLINE", "SOURCE_UNAVAILABLE"}
    assert [c[0] for c in calls] == [V6, V4]
    assert failures == [httpcore.ConnectTimeout, httpcore.ConnectTimeout]
    assert elapsed < 1.25


def test_more_public_answers_are_validated_but_only_eight_connections_attempted(monkeypatch):
    answers = [f"93.184.216.{n}" for n in range(1, 10)]
    with native_closed_port() as refused:
        calls, _ = route(monkeypatch, answers, {a: refused for a in answers})
        with pytest.raises(WorkbenchError, match="SOURCE_UNAVAILABLE"):
            acquisition.fetch("http://feed.fixture.invalid/feed", timeout=2)
    assert [c[0] for c in calls] == answers[:8]


def test_private_answer_beyond_attempt_cap_blocks_every_connection(monkeypatch):
    answers = [f"93.184.216.{n}" for n in range(1, 9)] + ["127.0.0.1"]
    calls, _ = route(monkeypatch, answers, {})
    with pytest.raises(WorkbenchError, match="DESTINATION_BLOCKED"):
        acquisition.fetch("http://feed.fixture.invalid/feed", timeout=2)
    assert calls == []


@pytest.fixture(scope="module")
def certificates(tmp_path_factory):
    return generate_certificates(tmp_path_factory.mktemp("fallback-tls") / "pki")


def trust(monkeypatch, certificates):
    original = http_connection.default_ssl_context

    def context():
        value = original()
        assert value.check_hostname and value.verify_mode == ssl.CERT_REQUIRED
        value.load_verify_locations(cafile=str(certificates.ca))
        return value

    monkeypatch.setattr(http_connection, "default_ssl_context", context)


def test_native_tls_after_tcp_fallback_keeps_original_sni_and_host(monkeypatch, certificates):
    trust(monkeypatch, certificates)
    with native_closed_port() as refused, native_peer(bundle=certificates) as (good, requests, sni):
        calls, _ = route(monkeypatch, [V6, V4], {V6: refused, V4: good})
        assert acquisition.fetch("https://feed.fixture.invalid/feed", timeout=2) == b"fixture!"
    assert [c[0] for c in calls] == [V6, V4]
    assert sni == ["feed.fixture.invalid"]
    assert b"\r\nHost: feed.fixture.invalid\r\n" in requests[0]


def test_tls_certificate_failure_does_not_try_another_address(monkeypatch, certificates):
    trust(monkeypatch, certificates)
    with (
        native_peer(bundle=certificates, kind="wrong") as (wrong, bad_requests, sni),
        native_peer(bundle=certificates) as (good, requests, _),
    ):
        calls, failures = route(monkeypatch, [V6, V4], {V6: wrong, V4: good})
        with pytest.raises(WorkbenchError, match="SOURCE_UNAVAILABLE"):
            acquisition.fetch("https://feed.fixture.invalid/feed", timeout=2)
    assert [c[0] for c in calls] == [V6] and failures == []
    assert sni == ["feed.fixture.invalid"] and bad_requests == [] and requests == []
