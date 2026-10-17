"""Retry hints over real local TCP and httpcore framing; no external acquisition."""

import socket
import threading
from contextlib import contextmanager
from datetime import UTC, datetime

import httpcore
import pytest

from osint_workbench import fetch as acquisition
from osint_workbench.errors import SourceHTTPError, WorkbenchError

NOW = datetime(2026, 10, 17, 12, 0, tzinfo=UTC)
BODY_CANARY = b"synthetic-response-body-must-not-appear-in-error"


def response(status, headers=(), *, body=BODY_CANARY):
    lines = [f"HTTP/1.1 {status} Fixture".encode()]
    lines.extend(name + b": " + value for name, value in headers)
    lines.extend([b"Content-Length: " + str(len(body)).encode(), b"Connection: close"])
    return b"\r\n".join(lines) + b"\r\n\r\n" + body


@contextmanager
def routed_responses(monkeypatch, responses):
    stopping = threading.Event()
    requests, errors = [], []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        listener.settimeout(0.1)

        def serve():
            try:
                for wire in responses:
                    while not stopping.is_set():
                        try:
                            connection, _ = listener.accept()
                            break
                        except TimeoutError:
                            continue
                    else:
                        return
                    with connection:
                        connection.settimeout(2)
                        received = bytearray()
                        while b"\r\n\r\n" not in received:
                            part = connection.recv(1024)
                            if not part:
                                raise RuntimeError("synthetic client closed before request")
                            received.extend(part)
                            if len(received) > 8192:
                                raise RuntimeError("synthetic request exceeded test bound")
                        requests.append(bytes(received).split(b"\r\n", 1)[0])
                        connection.sendall(wire)
            except Exception as error:
                errors.append(type(error).__name__)

        class RoutedBackend(acquisition._PublicBackend):
            def connect_tcp(self, host, port, timeout=None, **kwargs):
                assert host in ("feed.fixture.invalid", b"feed.fixture.invalid") and port == 80
                stream = httpcore.SyncBackend.connect_tcp(
                    self, "127.0.0.1", listener.getsockname()[1], timeout=timeout
                )
                return acquisition._Stream(stream, self.deadline)

        monkeypatch.setattr(acquisition, "_PublicBackend", RoutedBackend)
        thread = threading.Thread(target=serve, name="synthetic-retry-after-peer")
        thread.start()
        try:
            yield requests
        finally:
            stopping.set()
            thread.join(timeout=3)
            assert not thread.is_alive(), "synthetic Retry-After peer did not stop"
            assert not errors, "synthetic Retry-After peer failed"


def assert_safe_error(error, code):
    assert error.code == code and str(error) == code and error.args == (code,)
    assert BODY_CANARY.decode() not in repr(error)
    assert "feed.fixture.invalid" not in repr(error)
    assert set(vars(error)) <= {"code", "retry_after_seconds", "retry_after_at"}


@pytest.mark.parametrize("status", [429, 503])
@pytest.mark.parametrize("seconds", [0, 120, 604800, 604801])
def test_native_http_retryable_status_exposes_only_typed_delay(monkeypatch, status, seconds):
    wire = response(status, [(b"Retry-After", str(seconds).encode())])
    with routed_responses(monkeypatch, [wire]) as requests:
        with pytest.raises(SourceHTTPError) as caught:
            acquisition.fetch_response("http://feed.fixture.invalid/feed", timeout=3)
    assert_safe_error(caught.value, "SOURCE_HTTP_ERROR")
    assert caught.value.retry_after_seconds == seconds
    assert caught.value.retry_after_at is None
    assert requests == [b"GET /feed HTTP/1.1"]


@pytest.mark.parametrize("status", [429, 503])
def test_native_http_retryable_status_without_hint_remains_typed(monkeypatch, status):
    with routed_responses(monkeypatch, [response(status)]):
        with pytest.raises(SourceHTTPError) as caught:
            acquisition.fetch_response("http://feed.fixture.invalid/feed", timeout=3)
    assert_safe_error(caught.value, "SOURCE_HTTP_ERROR")
    assert caught.value.retry_after_seconds is None and caught.value.retry_after_at is None


@pytest.mark.parametrize("status", [429, 503])
def test_native_http_date_hint_preserves_absolute_utc_instant(monkeypatch, status):
    wire = response(status, [(b"Retry-After", b"Sun, 06 Nov 1994 08:49:37 GMT")])
    with routed_responses(monkeypatch, [wire]):
        with pytest.raises(SourceHTTPError) as caught:
            acquisition.fetch_response("http://feed.fixture.invalid/feed", timeout=3)
    assert_safe_error(caught.value, "SOURCE_HTTP_ERROR")
    assert caught.value.retry_after_seconds is None
    assert caught.value.retry_after_at == datetime(1994, 11, 6, 8, 49, 37, tzinfo=UTC)


@pytest.mark.parametrize(
    "headers",
    [
        [(b"Retry-After", b"not-a-delay")],
        [(b"Retry-After", b"+12")],
        [(b"Retry-After", b"1.5")],
        [(b"Retry-After", b"1, 2")],
        [(b"Retry-After", b"\xff")],
        [(b"Retry-After", b"1" * 129)],
        [(b"Retry-After", b"12"), (b"retry-after", b"12")],
        [(b"Retry-After", b"12"), (b"Retry-After", b"30")],
    ],
    ids=["text", "signed", "fraction", "list", "non-ascii", "oversize", "duplicate", "conflict"],
)
def test_native_http_rejects_malformed_hints_without_echoing_them(monkeypatch, headers):
    with routed_responses(monkeypatch, [response(503, headers)]):
        with pytest.raises(SourceHTTPError) as caught:
            acquisition.fetch_response("http://feed.fixture.invalid/feed", timeout=3)
    assert_safe_error(caught.value, "INVALID_RETRY_AFTER")
    assert caught.value.retry_after_seconds is None and caught.value.retry_after_at is None


def test_native_http_success_ignores_retry_after_metadata(monkeypatch):
    with routed_responses(monkeypatch, [response(200, [(b"Retry-After", b"invalid")])]):
        result = acquisition.fetch_response("http://feed.fixture.invalid/feed", timeout=3)
    assert result.status == 200 and result.body == BODY_CANARY


def test_native_http_conditional_success_ignores_retry_after_metadata(monkeypatch):
    wire = response(304, [(b"Retry-After", b"invalid"), (b"ETag", b'"v1"')], body=b"")
    with routed_responses(monkeypatch, [wire]):
        result = acquisition.fetch_response(
            "http://feed.fixture.invalid/feed", etag='"v1"', timeout=3
        )
    assert result.status == 304 and result.body == b"" and result.etag == '"v1"'


@pytest.mark.parametrize("status", [400, 401, 404, 500, 502])
def test_native_http_other_failures_do_not_acquire_retry_metadata(monkeypatch, status):
    with routed_responses(monkeypatch, [response(status, [(b"Retry-After", b"120")])]):
        with pytest.raises(WorkbenchError) as caught:
            acquisition.fetch_response("http://feed.fixture.invalid/feed", timeout=3)
    assert not isinstance(caught.value, SourceHTTPError)
    assert_safe_error(caught.value, "SOURCE_HTTP_ERROR")


def test_native_http_non_retryable_failure_does_not_parse_malformed_hint(monkeypatch):
    with routed_responses(monkeypatch, [response(500, [(b"Retry-After", b"invalid")])]):
        with pytest.raises(WorkbenchError) as caught:
            acquisition.fetch_response("http://feed.fixture.invalid/feed", timeout=3)
    assert not isinstance(caught.value, SourceHTTPError)
    assert_safe_error(caught.value, "SOURCE_HTTP_ERROR")


def test_native_http_redirect_ignores_hop_hint_and_uses_final_hint(monkeypatch):
    wires = [
        response(302, [(b"Location", b"/final"), (b"Retry-After", b"invalid")]),
        response(429, [(b"Retry-After", b"75")]),
    ]
    with routed_responses(monkeypatch, wires) as requests:
        with pytest.raises(SourceHTTPError) as caught:
            acquisition.fetch_response("http://feed.fixture.invalid/feed", timeout=3)
    assert_safe_error(caught.value, "SOURCE_HTTP_ERROR")
    assert caught.value.retry_after_seconds == 75
    assert requests == [b"GET /feed HTTP/1.1", b"GET /final HTTP/1.1"]


def test_native_http_compatibility_fetch_propagates_typed_retry_metadata(monkeypatch):
    with routed_responses(monkeypatch, [response(503, [(b"Retry-After", b"180")])]):
        with pytest.raises(SourceHTTPError) as caught:
            acquisition.fetch("http://feed.fixture.invalid/feed", timeout=3)
    assert_safe_error(caught.value, "SOURCE_HTTP_ERROR")
    assert caught.value.retry_after_seconds == 180


@pytest.mark.parametrize(
    ("wire", "expected"),
    [
        (b"0", 0),
        (b"604800", 604800),
        (b"604801", 604801),
        (b"9" * 128, 604801),
        (b"0" * 127 + b"1", 1),
    ],
)
def test_retry_after_numeric_boundaries_without_unbounded_integer_conversion(wire, expected):
    assert acquisition.parse_retry_after(wire, now=NOW) == (expected, None)


@pytest.mark.parametrize(
    "wire",
    [
        b"Sun, 06 Nov 1994 08:49:37 GMT",
        b"Sunday, 06-Nov-94 08:49:37 GMT",
        b"Sun Nov  6 08:49:37 1994",
    ],
)
def test_retry_after_all_three_http_date_forms_preserve_same_utc_instant(wire):
    seconds, instant = acquisition.parse_retry_after(wire, now=NOW)
    assert seconds is None and instant == datetime(1994, 11, 6, 8, 49, 37, tzinfo=UTC)


def test_retry_after_leap_second_normalizes_forward_without_early_retry():
    seconds, instant = acquisition.parse_retry_after(b"Sat, 31 Dec 2016 23:59:60 GMT", now=NOW)
    assert seconds is None and instant == datetime(2017, 1, 1, tzinfo=UTC)


@pytest.mark.parametrize(
    ("wire", "instant"),
    [
        (b"Saturday, 17-Oct-76 12:00:00 GMT", datetime(2076, 10, 17, 12, 0, tzinfo=UTC)),
        (b"Sunday, 17-Oct-76 12:00:01 GMT", datetime(1976, 10, 17, 12, 0, 1, tzinfo=UTC)),
    ],
)
def test_retry_after_obsolete_date_rolling_fifty_year_boundary_uses_full_instant(wire, instant):
    assert acquisition.parse_retry_after(wire, now=NOW) == (None, instant)


@pytest.mark.parametrize(
    ("now", "wire", "instant"),
    [
        (
            datetime(2080, 1, 1, tzinfo=UTC),
            b"Friday, 01-Jan-00 00:00:00 GMT",
            datetime(2100, 1, 1, tzinfo=UTC),
        ),
        (
            datetime(2090, 1, 1, tzinfo=UTC),
            b"Thursday, 01-Jan-05 00:00:00 GMT",
            datetime(2105, 1, 1, tzinfo=UTC),
        ),
    ],
)
def test_retry_after_obsolete_date_window_crosses_century_without_early_retry(now, wire, instant):
    assert acquisition.parse_retry_after(wire, now=now) == (None, instant)


def test_retry_after_http_optional_whitespace_is_accepted_within_byte_budget():
    assert acquisition.parse_retry_after(b" \t12\t ", now=NOW) == (12, None)


@pytest.mark.parametrize(
    "wire",
    [
        b"",
        b"-1",
        b"+1",
        b"1.0",
        b"1,2",
        b"12\r\nInjected: value",
        b"\xff",
        b"1" * 129,
        b"Mon, 06 Nov 1994 08:49:37 GMT",
        b"Sunday, 06-Nov-94 08:49:37 UTC",
        b"Sun, 06 Nov 1994 08:49:37 +0000",
        b"Sun, 31 Nov 1994 08:49:37 GMT",
        b"Sat, 31 Dec 2016 08:49:60 GMT",
    ],
)
def test_retry_after_parser_refuses_ambiguous_or_invalid_values(wire):
    with pytest.raises(SourceHTTPError) as caught:
        acquisition.parse_retry_after(wire, now=NOW)
    assert_safe_error(caught.value, "INVALID_RETRY_AFTER")
