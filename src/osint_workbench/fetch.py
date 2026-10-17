"""Bounded public HTTP acquisition with connection-time DNS pinning.

Resolver subprocesses and network streams share an absolute deadline. TLS uses
the original HTTP origin, while TCP connects only to a validated public address.
There are no environment proxy or private-address override options.
"""

import ipaddress
import json
import multiprocessing
import queue
import re
import socket
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime, parsedate_to_datetime
from urllib.parse import urljoin, urlsplit

import httpcore

from .errors import SourceHTTPError, WorkbenchError

MAX_BYTES = 10 * 1024 * 1024
MAX_DNS_ADDRESSES = 64
MAX_DNS_PACKET = 4096
MAX_DNS_ADDRESS = 64
MAX_RETRY_AFTER_SECONDS = 604800
_WEEKDAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
_LONG_WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_TIME = r"(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
_HTTP_DATES = (
    re.compile(
        r"(?P<weekday>[A-Za-z]{3}), (?P<day>[0-9]{2}) (?P<month>[A-Za-z]{3}) "
        r"(?P<year>[0-9]{4}) " + _TIME + r" GMT"
    ),
    re.compile(
        r"(?P<weekday>[A-Za-z]+), (?P<day>[0-9]{2})-(?P<month>[A-Za-z]{3})-"
        r"(?P<year>[0-9]{2}) " + _TIME + r" GMT"
    ),
    re.compile(
        r"(?P<weekday>[A-Za-z]{3}) (?P<month>[A-Za-z]{3}) (?P<day>[0-9]{2}| [0-9]) "
        + _TIME
        + r" (?P<year>[0-9]{4})"
    ),
)


def parse_retry_after(value: bytes, *, now: datetime | None = None):
    """Normalize a scalar hint; dates remain UTC for database-clock comparison.

    Oversized valid decimal delays become the seven-day-plus-one sentinel;
    callers must explicitly apply/report the selected cap. Only RFC850 century
    unfolding uses the application's UTC clock. No raw value survives failure.
    """
    if not isinstance(value, bytes) or not 1 <= len(value) <= 128:
        raise SourceHTTPError("INVALID_RETRY_AFTER")
    stripped = value.strip(b" \t")
    if any(byte > 127 for byte in stripped):
        raise SourceHTTPError("INVALID_RETRY_AFTER")
    if re.fullmatch(rb"[0-9]+", stripped):
        digits = stripped.lstrip(b"0") or b"0"
        if len(digits) > len(str(MAX_RETRY_AFTER_SECONDS)):
            seconds = MAX_RETRY_AFTER_SECONDS + 1
        else:
            seconds = min(int(digits), MAX_RETRY_AFTER_SECONDS + 1)
        return seconds, None
    clock = now if now is not None else datetime.now(UTC)
    if not isinstance(clock, datetime) or clock.utcoffset() is None:
        raise ValueError("INVALID_RETRY_CLOCK")
    clock = clock.astimezone(UTC)
    try:
        text = stripped.decode("ascii")
        for index, expression in enumerate(_HTTP_DATES):
            match = expression.fullmatch(text)
            if not match:
                continue
            groups = match.groupdict()
            year, day = int(groups["year"]), int(groups["day"])
            month = _MONTHS.index(groups["month"]) + 1
            hour, minute, second = (int(groups[k]) for k in ("hour", "minute", "second"))
            if second > 60 or (second == 60 and (hour, minute) != (23, 59)):
                raise ValueError
            if index == 1:
                year += (clock.year + 50) // 100 * 100
                candidate = (year, month, day, hour, minute, second)
                limit = (
                    clock.year + 50,
                    clock.month,
                    clock.day,
                    clock.hour,
                    clock.minute,
                    clock.second,
                )
                if candidate > limit:
                    year -= 100
            result = datetime(year, month, day, hour, minute, min(second, 59), tzinfo=UTC)
            weekday = (
                _LONG_WEEKDAYS[result.weekday()] if index == 1 else _WEEKDAYS[result.weekday()]
            )
            if groups["weekday"] != weekday:
                raise ValueError
            if second == 60:
                result += timedelta(seconds=1)
            return None, result
        raise ValueError
    except (ValueError, UnicodeError, OverflowError):
        raise SourceHTTPError("INVALID_RETRY_AFTER") from None


def validate_url(url: str) -> tuple[str, int]:
    if not isinstance(url, str) or len(url) > 4096 or any(ord(c) < 33 for c in url):
        raise WorkbenchError("INVALID_SOURCE_URL")
    try:
        part = urlsplit(url)
        port = part.port if part.port is not None else (443 if part.scheme == "https" else 80)
        if (
            part.scheme not in {"https", "http"}
            or not part.hostname
            or part.username is not None
            or part.password is not None
            or part.fragment
            or port not in {80, 443}
        ):
            raise ValueError
        host = part.hostname.encode("idna").decode("ascii")
    except (ValueError, UnicodeError):
        raise WorkbenchError("INVALID_SOURCE_URL") from None
    return host, port


def public_addresses(addresses: list[str]) -> list[str]:
    if not addresses:
        raise WorkbenchError("DNS_EMPTY")
    result = []
    for address in addresses:
        try:
            value = ipaddress.ip_address(address)
        except ValueError:
            raise WorkbenchError("DNS_INVALID") from None
        if isinstance(value, ipaddress.IPv6Address) and value.ipv4_mapped:
            value = value.ipv4_mapped
        if (
            not value.is_global
            or value.is_multicast
            or value.is_unspecified
            or value.is_reserved
            or value.is_loopback
            or value.is_link_local
        ):
            raise WorkbenchError("DESTINATION_BLOCKED")
        result.append(str(value))
    return sorted(set(result))


def _bounded_dns_addresses(addresses):
    if not isinstance(addresses, list):
        raise WorkbenchError("DNS_INVALID")
    if len(addresses) > MAX_DNS_ADDRESSES:
        raise WorkbenchError("DNS_LIMIT")
    for address in addresses:
        if not isinstance(address, str) or not address.isascii():
            raise WorkbenchError("DNS_INVALID")
        if len(address) > MAX_DNS_ADDRESS:
            raise WorkbenchError("DNS_LIMIT")
    return addresses


def _resolver_packet(addresses):
    try:
        packet = json.dumps(_bounded_dns_addresses(addresses), separators=(",", ":")).encode()
        if len(packet) > MAX_DNS_PACKET:
            raise WorkbenchError("DNS_LIMIT")
        return packet
    except WorkbenchError as exc:
        return json.dumps({"error": exc.code}).encode()


def _resolve_child(host, port, pipe):
    try:
        try:
            records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            # Reject the whole oversized result, never truncate a later private
            # address out of the set. OS/NSS allocation precedes this Python cap.
            if len(records) > MAX_DNS_ADDRESSES:
                packet = b'{"error":"DNS_LIMIT"}'
            else:
                packet = _resolver_packet([record[4][0] for record in records])
        except OSError:
            packet = b"[]"
        pipe.send_bytes(packet)
    except (OSError, EOFError):
        # The parent may already have closed after its deadline.
        pass
    finally:
        pipe.close()


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise WorkbenchError("FETCH_DEADLINE")
    return remaining


def resolve(host: str, port: int, deadline: float) -> list[str]:
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    process = context.Process(target=_resolve_child, args=(host, port, child), daemon=True)
    received = queue.Queue(maxsize=1)
    started = False
    receiver = None

    def receive():
        try:
            packet = parent.recv_bytes(MAX_DNS_PACKET)
        except (OSError, EOFError, ValueError):
            packet = None
        received.put_nowait(packet)

    try:
        _remaining(deadline)
        process.start()
        started = True
        child.close()
        # Readability alone does not establish a complete frame. Keep the entire
        # bounded receive under the same deadline; no pickle decoding is used.
        pending_receiver = threading.Thread(target=receive, name="ow-dns-receiver", daemon=True)
        pending_receiver.start()
        receiver = pending_receiver
        try:
            packet = received.get(timeout=_remaining(deadline))
        except queue.Empty:
            raise WorkbenchError("FETCH_DEADLINE") from None
        _remaining(deadline)
        if packet is None:
            raise WorkbenchError("DNS_INVALID")
        try:
            addresses = json.loads(packet)
        except (ValueError, UnicodeError, RecursionError):
            raise WorkbenchError("DNS_INVALID") from None
        if isinstance(addresses, dict):
            if set(addresses) == {"error"} and addresses["error"] in ("DNS_LIMIT", "DNS_INVALID"):
                raise WorkbenchError(addresses["error"])
            raise WorkbenchError("DNS_INVALID")
        validated = public_addresses(_bounded_dns_addresses(addresses))
        _remaining(deadline)
        return validated
    finally:
        child.close()
        if started:
            if process.is_alive():
                process.terminate()
            process.join(timeout=1)
            if process.is_alive():
                process.kill()
                process.join(timeout=1)
        # Termination closes the owned writer and releases a partial-frame read.
        if receiver is not None:
            receiver.join(timeout=1)
        parent.close()
        if (started and process.is_alive()) or (receiver is not None and receiver.is_alive()):
            raise WorkbenchError("DNS_RESOLVER_CLEANUP_FAILED")


class _Stream:
    def __init__(self, stream, deadline):
        self.stream, self.deadline = stream, deadline

    def _timeout(self, timeout):
        remaining = _remaining(self.deadline)
        return min(timeout, remaining) if timeout is not None else remaining

    def read(self, max_bytes, timeout=None):
        return self.stream.read(max_bytes, timeout=self._timeout(timeout))

    def write(self, buffer, timeout=None):
        return self.stream.write(buffer, timeout=self._timeout(timeout))

    def close(self):
        self.stream.close()

    def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        return _Stream(
            self.stream.start_tls(
                ssl_context, server_hostname=server_hostname, timeout=self._timeout(timeout)
            ),
            self.deadline,
        )

    def get_extra_info(self, info):
        return self.stream.get_extra_info(info)


class _PublicBackend(httpcore.SyncBackend):
    def __init__(self, deadline):
        self.deadline = deadline

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        if isinstance(host, bytes):
            host = host.decode("ascii")
        addresses = resolve(host, port, self.deadline)
        # Validate the entire answer set before connecting to any address.
        stream = super().connect_tcp(
            addresses[0],
            port,
            timeout=_remaining(self.deadline),
            local_address=local_address,
            socket_options=socket_options,
        )
        return _Stream(stream, self.deadline)


@dataclass(frozen=True)
class FetchResult:
    status: int
    body: bytes
    etag: str | None = None
    last_modified: str | None = None


def validators(etag=None, last_modified=None):
    if etag is not None and (
        not isinstance(etag, str)
        or len(etag) > 512
        or not re.fullmatch(r'(?:W/)?"[\x21\x23-\x7e]*"', etag)
    ):
        raise WorkbenchError("INVALID_HTTP_VALIDATOR")
    if last_modified is not None:
        try:
            if (
                not isinstance(last_modified, str)
                or len(last_modified) > 128
                or format_datetime(parsedate_to_datetime(last_modified), usegmt=True)
                != last_modified
            ):
                raise ValueError
        except (TypeError, ValueError, OverflowError):
            raise WorkbenchError("INVALID_HTTP_VALIDATOR") from None
    return etag, last_modified


def fetch_response(
    url: str, *, etag=None, last_modified=None, timeout: float = 30, max_bytes: int = MAX_BYTES
) -> FetchResult:
    validators(etag, last_modified)
    if (
        type(timeout) not in (int, float)
        or not 0 < timeout <= 120
        or not 1 <= max_bytes <= MAX_BYTES
    ):
        raise WorkbenchError("INVALID_FETCH_LIMIT")
    deadline = time.monotonic() + timeout
    try:
        with httpcore.ConnectionPool(
            network_backend=_PublicBackend(deadline), max_connections=1, max_keepalive_connections=0
        ) as pool:
            current = url
            for _ in range(6):
                validate_url(current)
                request_headers = [
                    ("Accept-Encoding", "identity"),
                    ("User-Agent", "osint-workbench/0.1"),
                ]
                # Validators are scoped to the exact configured URI. Redirect hops
                # never receive them, even when the origin is unchanged.
                if current == url:
                    if etag is not None:
                        request_headers.append(("If-None-Match", etag))
                    elif last_modified is not None:
                        request_headers.append(("If-Modified-Since", last_modified))
                with pool.stream(
                    "GET",
                    current,
                    headers=request_headers,
                    extensions={
                        "timeout": {
                            "connect": _remaining(deadline),
                            "read": _remaining(deadline),
                            "write": _remaining(deadline),
                        }
                    },
                ) as response:
                    headers = {k.lower(): v for k, v in response.headers}
                    if response.status in {301, 302, 303, 307, 308}:
                        location = headers.get(b"location")
                        if location is None:
                            raise WorkbenchError("INVALID_REDIRECT")
                        target = urljoin(current, location.decode("ascii"))
                        if (
                            urlsplit(current).scheme == "https"
                            and urlsplit(target).scheme != "https"
                        ):
                            raise WorkbenchError("INSECURE_REDIRECT")
                        validate_url(target)
                        current = target
                        continue
                    if response.status in {429, 503}:
                        hints = [
                            value
                            for name, value in response.headers
                            if name.lower() == b"retry-after"
                        ]
                        if len(hints) > 1:
                            raise SourceHTTPError("INVALID_RETRY_AFTER")
                        seconds, retry_at = parse_retry_after(hints[0]) if hints else (None, None)
                        raise SourceHTTPError(retry_after_seconds=seconds, retry_after_at=retry_at)
                    if response.status not in {200, 304}:
                        raise WorkbenchError("SOURCE_HTTP_ERROR")
                    fields = {}
                    for name, value in response.headers:
                        key = name.lower()
                        if key in {b"etag", b"last-modified"}:
                            if key in fields:
                                raise WorkbenchError("INVALID_HTTP_VALIDATOR")
                            fields[key] = value.decode("ascii")
                    new_etag, new_modified = validators(
                        fields.get(b"etag"), fields.get(b"last-modified")
                    )
                    if response.status == 304:
                        if current != url or (etag is None and last_modified is None):
                            raise WorkbenchError("UNSOLICITED_NOT_MODIFIED")
                        if (
                            new_etag is not None
                            and etag is not None
                            and (new_etag.removeprefix("W/") != etag.removeprefix("W/"))
                        ):
                            raise WorkbenchError("VALIDATOR_MISMATCH")
                        return FetchResult(304, b"", new_etag, new_modified)
                    if headers.get(b"content-encoding", b"identity").lower() != b"identity":
                        raise WorkbenchError("UNSUPPORTED_CONTENT_ENCODING")
                    body = bytearray()
                    for chunk in response.iter_stream():
                        _remaining(deadline)
                        if len(body) + len(chunk) > max_bytes:
                            raise WorkbenchError("SOURCE_TOO_LARGE")
                        body.extend(chunk)
                    # A representation obtained after a redirect cannot seed
                    # validators for the configured URI.
                    return FetchResult(
                        200,
                        bytes(body),
                        new_etag if current == url else None,
                        new_modified if current == url else None,
                    )
        raise WorkbenchError("REDIRECT_LIMIT")
    except WorkbenchError:
        raise
    except (
        httpcore.TimeoutException,
        httpcore.NetworkError,
        httpcore.ProtocolError,
        httpcore.ProxyError,
        httpcore.UnsupportedProtocol,
        OSError,
        UnicodeError,
        EOFError,
    ):
        raise WorkbenchError("SOURCE_UNAVAILABLE") from None


def fetch(url: str, *, timeout: float = 30, max_bytes: int = MAX_BYTES) -> bytes:
    """Compatibility API: unconditional acquisition always requires a full response."""
    return fetch_response(url, timeout=timeout, max_bytes=max_bytes).body
