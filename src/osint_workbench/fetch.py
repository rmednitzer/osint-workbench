"""Bounded public HTTP acquisition with connection-time DNS pinning.

Resolver subprocesses and network streams share an absolute deadline. TLS uses
the original HTTP origin, while TCP connects only to a validated public address.
There are no environment proxy or private-address override options.
"""

import ipaddress
import multiprocessing
import socket
import time
from urllib.parse import urljoin, urlsplit

import httpcore

from .errors import WorkbenchError

MAX_BYTES = 10 * 1024 * 1024


def validate_url(url: str) -> tuple[str, int]:
    if not isinstance(url, str) or len(url) > 4096 or any(ord(c) < 33 for c in url):
        raise WorkbenchError("INVALID_SOURCE_URL")
    try:
        part = urlsplit(url)
        port = part.port or (443 if part.scheme == "https" else 80)
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


def _resolve_child(host, port, pipe):
    try:
        pipe.send([r[4][0] for r in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)])
    except OSError:
        pipe.send([])
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
    process.start()
    child.close()
    try:
        if not parent.poll(_remaining(deadline)):
            raise WorkbenchError("FETCH_DEADLINE")
        return public_addresses(parent.recv())
    finally:
        parent.close()
        if process.is_alive():
            process.terminate()
        process.join(timeout=1)
        if process.is_alive():
            process.kill()
            process.join(timeout=1)


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


def fetch(url: str, *, timeout: float = 30, max_bytes: int = MAX_BYTES) -> bytes:
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
                with pool.stream(
                    "GET",
                    current,
                    headers=[
                        ("Accept-Encoding", "identity"),
                        ("User-Agent", "osint-workbench/0.1"),
                    ],
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
                    if response.status != 200:
                        raise WorkbenchError("SOURCE_HTTP_ERROR")
                    if headers.get(b"content-encoding", b"identity").lower() != b"identity":
                        raise WorkbenchError("UNSUPPORTED_CONTENT_ENCODING")
                    body = bytearray()
                    for chunk in response.iter_stream():
                        _remaining(deadline)
                        if len(body) + len(chunk) > max_bytes:
                            raise WorkbenchError("SOURCE_TOO_LARGE")
                        body.extend(chunk)
                    return bytes(body)
        raise WorkbenchError("REDIRECT_LIMIT")
    except WorkbenchError:
        raise
    except (httpcore.HTTPError, OSError, UnicodeError, EOFError):
        raise WorkbenchError("SOURCE_UNAVAILABLE") from None
