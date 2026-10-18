"""Disconnected synthetic HTTP fixture for explicit disposable hosted acceptance.

Importing this module creates no files, namespace, process or listener. Runtime
markers are cooperative admission guards, not cryptographic host attestation.
The fixed public-classified address exists only on this namespace's loopback;
production URL/address admission is unchanged. Protocol fixtures are bounded to
64 connections with a 180-second accept budget and per-request absolute deadlines.
The caller must stop its owned service before namespace removal.
"""

import argparse
import hashlib
import hmac
import json
import os
import signal
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

NAME = "ow-reference"
ADDRESS = "93.184.216.34"
PORT = 80
ROOT = Path("/opt/osint-workbench/reference-network")
NAMESPACE = Path("/run/netns") / NAME
CONTROL = ROOT / "phase"
OBSERVATIONS = ROOT / "requests.jsonl"
READY = ROOT / "ready"
API_TOKEN_DIGEST = ROOT / "api-token.sha256"
API_CERT = ROOT / "api.pem"
API_KEY = ROOT / "api.key"
API_PAGES = {
    "v1": (
        b'{"items":[{"id":"api-one","title":"API One","text":"First API evidence"}],'
        b'"next_cursor":"page-2"}'
    ),
    "v2": (
        b'{"items":[{"id":"api-two","title":"API Two","text":"Second API evidence"}],'
        b'"next_cursor":null}'
    ),
}
API_PAGES["kev"] = json.dumps(
    {
        "catalogVersion": "synthetic-1",
        "dateReleased": "2026-10-18T12:00:00Z",
        "count": 1,
        "vulnerabilities": [
            {
                "cveID": "CVE-2099-10001",
                "vendorProject": "Synthetic vendor",
                "product": "Synthetic product",
                "vulnerabilityName": "KEV Fixture",
                "dateAdded": "2026-10-18",
                "dueDate": "2026-11-01",
                "shortDescription": "KEV synthetic evidence",
                "requiredAction": "Synthetic recommendation",
                "forensicTriage": "No",
                "knownRansomwareCampaignUse": "Unknown",
                "notes": "",
                "cwes": [],
            }
        ],
    }
).encode()
API_PAGES["kev-invalid"] = API_PAGES["kev"].replace(b'"count": 1', b'"count": 2')
MAX_HEADER = 8192
MAX_REQUESTS = 64
MODIFIED = "Wed, 14 Oct 2026 12:00:00 GMT"
FEED_V1 = b"""<rss version="2.0"><channel><title>Fixture</title>
<link>http://feed.fixture.invalid/</link><description>Fixture</description>
<item><guid>1</guid><title>One</title><description>First evidence</description></item>
<item><guid>2</guid><title>Two</title><description>Second evidence</description></item>
</channel></rss>"""
FEED_V2 = FEED_V1.replace(b"Second evidence", b"Changed evidence")
ENVIRONMENT = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


def feed_bytes(phase):
    if phase not in ("v1", "v2"):
        raise ValueError("INVALID_FIXTURE_PHASE")
    return FEED_V1 if phase == "v1" else FEED_V2


def guard():
    if os.geteuid() != 0:
        raise RuntimeError("ROOT_REQUIRED")
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("GITHUB_ACTIONS_REQUIRED")
    if os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise RuntimeError("HOSTED_RUNNER_REQUIRED")
    if Path("/proc/1/comm").read_text().strip() != "systemd":
        raise RuntimeError("SYSTEMD_PID1_REQUIRED")


def run(arguments):
    result = subprocess.run(
        arguments, env=ENVIRONMENT, capture_output=True, text=True, timeout=10, check=False
    )
    if result.returncode:
        raise RuntimeError("NAMESPACE_OPERATION_FAILED")
    return result.stdout


def _inventory(arguments, *, namespace=False):
    prefix = ["ip", "netns", "exec", NAME] if namespace else []
    return json.loads(run(prefix + ["ip", "-j", *arguments]))


def assert_isolated(expected_inode, host_inode, *, namespace=False):
    current = NAMESPACE.stat().st_ino if namespace else Path("/proc/self/ns/net").stat().st_ino
    if expected_inode == host_inode or current != expected_inode:
        raise RuntimeError("NAMESPACE_IDENTITY_MISMATCH")
    links = _inventory(["link", "show"], namespace=namespace)
    if len(links) != 1 or links[0].get("ifname") != "lo" or "UP" not in links[0].get("flags", []):
        raise RuntimeError("UNEXPECTED_NAMESPACE_INTERFACES")
    addresses = _inventory(["address", "show"], namespace=namespace)
    locals_found = []
    for interface in addresses:
        if interface.get("ifname") != "lo":
            raise RuntimeError("UNEXPECTED_NAMESPACE_ADDRESS")
        for address in interface.get("addr_info", []):
            value = (address.get("local"), address.get("prefixlen"))
            if value not in (("127.0.0.1", 8), (ADDRESS, 32), ("::1", 128)):
                raise RuntimeError("UNEXPECTED_NAMESPACE_ADDRESS")
            locals_found.append(value)
    if (ADDRESS, 32) not in locals_found:
        raise RuntimeError("FIXTURE_ADDRESS_MISSING")
    allowed = {
        "127.0.0.0/8",
        "127.0.0.0",
        "127.0.0.1",
        "127.255.255.255",
        ADDRESS,
        "::1",
        "::1/128",
    }
    for family in ("-4", "-6"):
        for route in _inventory([family, "route", "show", "table", "all"], namespace=namespace):
            if (
                route.get("dev") != "lo"
                or route.get("dst") not in allowed
                or any(key in route for key in ("gateway", "via", "nhid", "multipath"))
            ):
                raise RuntimeError("UNEXPECTED_NAMESPACE_ROUTE")


def _response(connection, status, body=b"", *, etag=None, media_type=None):
    reason = {
        200: "OK",
        304: "Not Modified",
        400: "Bad Request",
        401: "Unauthorized",
        503: "Service Unavailable",
    }[status]
    headers = [f"HTTP/1.1 {status} {reason}", f"Content-Length: {len(body)}", "Connection: close"]
    if media_type is not None:
        headers.append("Content-Type: " + media_type)
    if status == 503:
        headers.append("Retry-After: 120")
    if etag is not None:
        headers.extend([f"ETag: {etag}", f"Last-Modified: {MODIFIED}"])
    connection.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + body)


def handle_connection(connection, phase, record, *, deadline=None):
    """Bounded protocol implementation on an already connected stream; never binds."""
    if phase not in ("v1", "v2", "fail"):
        raise ValueError("INVALID_FIXTURE_PHASE")
    deadline = min(time.monotonic() + 3, deadline or float("inf"))
    connection.settimeout(3)
    try:
        data = b""
        while b"\r\n\r\n" not in data:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError
            connection.settimeout(remaining)
            part = connection.recv(min(1024, MAX_HEADER + 1 - len(data)))
            if not part:
                raise ValueError
            data += part
            if len(data) > MAX_HEADER:
                raise ValueError
        head, remainder = data.split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
        if (
            len(lines[0]) > 512
            or lines[0] != b"GET /feed HTTP/1.1"
            or len(lines) - 1 > 16
            or remainder
        ):
            raise ValueError
        headers = {}
        for line in lines[1:]:
            name, value = line.split(b":", 1)
            name = name.decode("ascii").lower()
            value = value.strip().decode("ascii")
            if (
                not name
                or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in name)
                or name in headers
                or any(ord(c) < 32 or ord(c) > 126 for c in value)
            ):
                raise ValueError
            headers[name] = value
        if (
            "host" not in headers
            or headers.get("content-length", "0") != "0"
            or "transfer-encoding" in headers
            or len(headers.get("if-none-match", "")) > 256
            or len(headers.get("if-modified-since", "")) > 128
        ):
            raise ValueError
        etag = f'"{phase}"'
        status = 503 if phase == "fail" else (304 if headers.get("if-none-match") == etag else 200)
        body = feed_bytes(phase) if status == 200 else b""
        record(
            {
                "phase": phase,
                "status": status,
                "if_none_match": headers.get("if-none-match"),
                "if_modified_since": headers.get("if-modified-since"),
            }
        )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError
        connection.settimeout(remaining)
        _response(connection, status, body, etag=etag if phase != "fail" else None)
    except (ValueError, UnicodeError, OSError):
        try:
            connection.settimeout(0.1)
            _response(connection, 400)
        except OSError:
            pass


def handle_api_connection(connection, phase, expected_digest, record, *, deadline=None):
    """Synthetic provider contract; record only fixed status/boolean observations."""
    if phase not in (*API_PAGES, "fail"):
        raise ValueError("INVALID_FIXTURE_PHASE")
    deadline = min(time.monotonic() + 3, deadline or float("inf"))
    data = b""
    try:
        while b"\r\n\r\n" not in data:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError
            connection.settimeout(remaining)
            part = connection.recv(min(1024, MAX_HEADER + 1 - len(data)))
            if not part:
                raise ValueError
            data += part
            if len(data) > MAX_HEADER:
                raise ValueError
        head, remainder = data.split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
        expected_path = b"/records?cursor=page-2" if phase == "v2" else b"/records"
        if len(lines) > 17 or remainder or len(lines[0]) > 512:
            raise ValueError
        headers = {}
        for line in lines[1:]:
            key, value = line.split(b":", 1)
            key = key.decode("ascii").lower()
            value = value.strip()
            if (
                not key
                or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in key)
                or key in headers
                or any(c < 32 or c > 126 for c in value)
            ):
                raise ValueError
            headers[key] = value
        if (
            headers.get("host") != b"feed.fixture.invalid"
            or headers.get("content-length", b"0") != b"0"
            or "transfer-encoding" in headers
        ):
            raise ValueError
        authorized = hmac.compare_digest(
            hashlib.sha256(headers.get("authorization", b"")).hexdigest(), expected_digest
        )
        path_ok = lines[0] == b"GET " + expected_path + b" HTTP/1.1"
        status = (
            401 if not authorized else (400 if not path_ok else (503 if phase == "fail" else 200))
        )
        record({"phase": phase, "status": status, "authorized": authorized, "path_ok": path_ok})
        body = API_PAGES[phase] if status == 200 else b""
        _response(connection, status, body, media_type="application/json")
    except (ValueError, UnicodeError, OSError):
        try:
            connection.settimeout(0.1)
            _response(connection, 400)
        except OSError:
            pass


def _write_new(path, value, mode=0o600):
    with path.open("x", encoding="utf-8") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(mode)


def serve(expected_inode, host_inode, *, api=False):
    guard()
    assert_isolated(expected_inode, host_inode)
    # Admission and complete inventory checks precede creation of any listener.
    deadline = time.monotonic() + 180
    context = None
    if api:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(API_CERT, API_KEY)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((ADDRESS, 443 if api else PORT))
        listener.listen(4)
        listener.settimeout(0.5)
        _write_new(READY, "ready\n")
        count = 0
        while count < MAX_REQUESTS and time.monotonic() < deadline:
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                continue
            count += 1
            phase = CONTROL.read_text().strip()
            if phase not in ((*API_PAGES, "fail") if api else ("v1", "v2", "fail")):
                raise RuntimeError("INVALID_FIXTURE_PHASE")

            def record(row):
                with OBSERVATIONS.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(row, sort_keys=True) + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())

            with connection:
                if api:
                    connection.settimeout(3)
                    try:
                        with context.wrap_socket(connection, server_side=True) as secure:
                            handle_api_connection(
                                secure,
                                phase,
                                API_TOKEN_DIGEST.read_text(),
                                record,
                                deadline=deadline,
                            )
                    except (ssl.SSLError, OSError):
                        # TLS rejection records no application request or authentication data.
                        pass
                else:
                    handle_connection(connection, phase, record, deadline=deadline)


class ReferenceNetwork:
    url = "http://feed.fixture.invalid/feed"
    namespace_path = NAMESPACE
    hosts_file = ROOT / "hosts"

    def __init__(self, *, before_close=None, api_token=None):
        self._api_token = api_token
        self._before_close = before_close
        self._process = None
        self._namespace_owned = False
        self._directory_owned = False

    def __enter__(self):
        guard()
        if os.path.lexists(ROOT) or os.path.lexists(NAMESPACE):
            raise RuntimeError("FIXTURE_TARGET_ALREADY_EXISTS")
        parent = ROOT.parent.stat()
        if parent.st_uid != 0 or parent.st_mode & 0o022:
            raise RuntimeError("UNSAFE_FIXTURE_PARENT")
        try:
            ROOT.mkdir(mode=0o700)
            self._directory_owned = True
            if self._api_token is not None:
                if not isinstance(self._api_token, str) or not 16 <= len(self._api_token) <= 128:
                    raise RuntimeError("FIXTURE_TOKEN_INVALID")
                _write_new(
                    API_TOKEN_DIGEST,
                    hashlib.sha256(("Bearer " + self._api_token).encode()).hexdigest(),
                )
                run(
                    [
                        "openssl",
                        "req",
                        "-x509",
                        "-newkey",
                        "rsa:2048",
                        "-nodes",
                        "-days",
                        "2",
                        "-keyout",
                        str(API_KEY),
                        "-out",
                        str(API_CERT),
                        "-subj",
                        "/CN=feed.fixture.invalid",
                        "-addext",
                        "subjectAltName=DNS:feed.fixture.invalid",
                        "-addext",
                        "basicConstraints=critical,CA:true",
                    ]
                )
                API_KEY.chmod(0o600)
                API_CERT.chmod(0o644)
            _write_new(CONTROL, "v1\n")
            _write_new(OBSERVATIONS, "")
            _write_new(
                self.hosts_file, f"127.0.0.1 localhost\n{ADDRESS} feed.fixture.invalid\n", 0o644
            )
            host_inode = Path("/proc/self/ns/net").stat().st_ino
            run(["ip", "netns", "add", NAME])
            self._namespace_owned = True
            run(["ip", "-n", NAME, "link", "set", "lo", "up"])
            run(["ip", "-n", NAME, "address", "add", f"{ADDRESS}/32", "dev", "lo"])
            expected_inode = NAMESPACE.stat().st_ino
            assert_isolated(expected_inode, host_inode, namespace=True)
            environment = {
                **ENVIRONMENT,
                "GITHUB_ACTIONS": "true",
                "RUNNER_ENVIRONMENT": "github-hosted",
            }
            self._process = subprocess.Popen(
                [
                    "ip",
                    "netns",
                    "exec",
                    NAME,
                    "/usr/bin/python3",
                    str(Path(__file__).resolve()),
                    "--serve",
                    *(["--api"] if self._api_token is not None else []),
                    "--expected-inode",
                    str(expected_inode),
                    "--host-inode",
                    str(host_inode),
                ],
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            deadline = time.monotonic() + 10
            while not READY.is_file():
                if self._process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("FIXTURE_START_FAILED")
                time.sleep(0.05)
            if Path(f"/proc/{self._process.pid}/ns/net").stat().st_ino != expected_inode:
                raise RuntimeError("SERVER_NAMESPACE_MISMATCH")
            return self
        except Exception:
            self.close()
            raise

    def set_phase(self, phase):
        if phase not in (*API_PAGES, "fail"):
            raise ValueError("INVALID_FIXTURE_PHASE")
        if self._process is None or self._process.poll() is not None:
            raise RuntimeError("FIXTURE_NOT_RUNNING")
        pending = ROOT / "phase.pending"
        _write_new(pending, phase + "\n")
        pending.replace(CONTROL)

    def observations(self):
        data = OBSERVATIONS.read_bytes()
        if len(data) > 64 * 1024:
            raise RuntimeError("FIXTURE_OBSERVATION_LIMIT")
        rows = [json.loads(line) for line in data.splitlines()]
        if len(rows) > MAX_REQUESTS:
            raise RuntimeError("FIXTURE_OBSERVATION_LIMIT")
        return rows

    def close(self):
        failure = False
        if self._before_close is not None:
            try:
                self._before_close()
            except Exception:
                failure = True
        if self._process is not None:
            if self._process.poll() is None:
                try:
                    try:
                        os.killpg(self._process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    self._process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(self._process.pid, signal.SIGKILL)
                    self._process.wait(timeout=3)
            self._process = None
        if self._namespace_owned:
            try:
                if run(["ip", "netns", "pids", NAME]).strip():
                    raise RuntimeError("FIXTURE_NAMESPACE_STILL_IN_USE")
                run(["ip", "netns", "delete", NAME])
                self._namespace_owned = False
            except RuntimeError:
                failure = True
        if self._directory_owned:
            for name in (
                "phase",
                "phase.pending",
                "requests.jsonl",
                "ready",
                "hosts",
                "api-token.sha256",
                "api.pem",
                "api.key",
            ):
                (ROOT / name).unlink(missing_ok=True)
            ROOT.rmdir()
            self._directory_owned = False
        if failure:
            raise RuntimeError("FIXTURE_NAMESPACE_CLEANUP_FAILED")

    def __exit__(self, *_):
        self.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serve", action="store_true", required=True)
    parser.add_argument("--api", action="store_true")
    parser.add_argument("--expected-inode", type=int, required=True)
    parser.add_argument("--host-inode", type=int, required=True)
    args = parser.parse_args()
    try:
        serve(args.expected_inode, args.host_inode, api=args.api)
    except (RuntimeError, OSError, ValueError):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
