"""Synthetic ephemeral TLS PKI and loopback peers; importing has no effects."""

import shutil
import socket
import ssl
import subprocess
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpcore
import httpcore._sync.connection as http_connection
import pytest

from osint_workbench import fetch as acquisition


@dataclass(frozen=True)
class CertificateBundle:
    ca: Path
    leaves: dict


def generate_certificates(directory):
    """Generate every key under a pytest-owned private temporary directory."""
    executable = shutil.which("openssl")
    if executable is None:
        pytest.fail("openssl is required for native TLS verification")
    directory.mkdir(mode=0o700, parents=True)
    directory.chmod(0o700)

    def openssl(*arguments):
        result = subprocess.run(
            [executable, *arguments],
            cwd=directory,
            capture_output=True,
            timeout=20,
            check=False,
            umask=0o077,
        )
        if result.returncode:
            pytest.fail("synthetic certificate generation failed")

    openssl(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "3",
        "-keyout",
        "ca.key",
        "-out",
        "ca.pem",
        "-subj",
        "/CN=Synthetic TLS Fixture CA",
        "-addext",
        "basicConstraints=critical,CA:true,pathlen:0",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-addext",
        "subjectKeyIdentifier=hash",
        "-addext",
        "authorityKeyIdentifier=keyid:always",
    )
    (directory / "index.txt").write_text("")
    (directory / "serial").write_text("01\n")
    (directory / "newcerts").mkdir(mode=0o700)
    now = datetime.now(UTC)
    leaves = {}
    for kind, name in (
        ("valid", "feed.fixture.invalid"),
        ("wrong", "other.fixture.invalid"),
        ("expired", "feed.fixture.invalid"),
    ):
        openssl(
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            f"{kind}.key",
            "-out",
            f"{kind}.csr",
            "-subj",
            f"/CN={name}",
        )
        config = f"""[ca]
default_ca=fixture
[fixture]
database=index.txt
new_certs_dir=newcerts
serial=serial
private_key=ca.key
certificate=ca.pem
default_md=sha256
policy=fixture_policy
unique_subject=no
x509_extensions=server_cert
[fixture_policy]
commonName=supplied
[server_cert]
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
subjectAltName=DNS:{name}
"""
        (directory / f"{kind}.cnf").write_text(config)
        start = (
            "20200101000000Z"
            if kind == "expired"
            else (now - timedelta(days=1)).strftime("%Y%m%d%H%M%SZ")
        )
        end = (
            "20200102000000Z"
            if kind == "expired"
            else (now + timedelta(days=2)).strftime("%Y%m%d%H%M%SZ")
        )
        openssl(
            "ca",
            "-batch",
            "-notext",
            "-config",
            f"{kind}.cnf",
            "-in",
            f"{kind}.csr",
            "-out",
            f"{kind}.pem",
            "-startdate",
            start,
            "-enddate",
            end,
        )
        leaves[kind] = {"cert": directory / f"{kind}.pem", "key": directory / f"{kind}.key"}
    return CertificateBundle(directory / "ca.pem", leaves)


@dataclass
class Peer:
    sni: list = field(default_factory=list)
    requests: list = field(default_factory=list)
    bodies: list = field(default_factory=list)
    connections: int = 0
    handshake_failures: int = 0
    body_bytes_sent: int = 0


@contextmanager
def tls_peer(
    monkeypatch,
    bundle,
    *,
    kind="valid",
    trust_fixture=True,
    mode="tls",
    body=b"TLS evidence",
    wire=None,
):
    """Route TCP only; retain original HTTPS origin, SNI and certificate checks."""
    peer = Peer()
    stopping, errors = threading.Event(), []
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(bundle.leaves[kind]["cert"], bundle.leaves[kind]["key"])
    server_context.set_servername_callback(lambda _socket, name, _context: peer.sni.append(name))
    original_context = http_connection.default_ssl_context

    def configured_context():
        context = original_context()
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
        context.load_verify_locations(cafile=str(bundle.ca))
        return context

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        listener.settimeout(0.1)
        port = listener.getsockname()[1]

        def serve():
            try:
                while not stopping.is_set():
                    try:
                        connection, _ = listener.accept()
                        break
                    except TimeoutError:
                        continue
                else:
                    return
                peer.connections += 1
                with connection:
                    connection.settimeout(1.5)
                    if mode == "stall":
                        stopping.wait(2)
                        return
                    if mode == "plaintext":
                        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        return
                    try:
                        secure = server_context.wrap_socket(connection, server_side=True)
                    except ssl.SSLError:
                        peer.handshake_failures += 1
                        return
                    with secure:
                        request = bytearray()
                        request_deadline = time.monotonic() + 1.5
                        while b"\r\n\r\n" not in request:
                            remaining = request_deadline - time.monotonic()
                            if remaining <= 0:
                                raise RuntimeError("synthetic TLS request exceeded deadline")
                            secure.settimeout(remaining)
                            part = secure.recv(1024)
                            if not part:
                                raise RuntimeError("synthetic TLS client closed before request")
                            request.extend(part)
                            if len(request) > 8192:
                                raise RuntimeError("synthetic TLS request exceeded bound")
                        head, _, rest = bytes(request).partition(b"\r\n\r\n")
                        peer.requests.append(head + b"\r\n\r\n")
                        # Read a declared request body so POST clients finish writing
                        # before the scripted response; GET requests declare none.
                        length = 0
                        for line in head.split(b"\r\n")[1:]:
                            name, _, value = line.partition(b":")
                            if name.strip().lower() == b"content-length":
                                length = int(value.strip())
                        if length > 1024 * 1024:
                            raise RuntimeError("synthetic TLS request body exceeded bound")
                        body_in = bytearray(rest)
                        while len(body_in) < length:
                            remaining = request_deadline - time.monotonic()
                            if remaining <= 0:
                                raise RuntimeError("synthetic TLS body exceeded deadline")
                            secure.settimeout(remaining)
                            part = secure.recv(65536)
                            if not part:
                                raise RuntimeError("synthetic TLS client closed in body")
                            body_in.extend(part)
                        peer.bodies.append(bytes(body_in))
                        if mode == "drip":
                            try:
                                secure.sendall(
                                    b"HTTP/1.1 200 OK\r\nContent-Length: 1024\r\n"
                                    b"Connection: close\r\n\r\n"
                                )
                                for _ in range(32):
                                    if stopping.wait(0.06):
                                        break
                                    secure.sendall(b"x")
                                    peer.body_bytes_sent += 1
                            except OSError:
                                # Client deadline closes an established TLS stream.
                                pass
                            return
                        response = (
                            wire
                            if wire is not None
                            else (
                                b"HTTP/1.1 200 OK\r\nContent-Length: "
                                + str(len(body)).encode()
                                + b"\r\nConnection: close\r\n\r\n"
                                + body
                            )
                        )
                        secure.sendall(response)
            except Exception as error:
                errors.append(type(error).__name__)

        class RoutedBackend(acquisition._PublicBackend):
            def connect_tcp(self, host, port, timeout=None, **kwargs):
                assert host in ("feed.fixture.invalid", b"feed.fixture.invalid") and port == 443
                stream = httpcore.SyncBackend.connect_tcp(
                    self, "127.0.0.1", listener_port, timeout=acquisition._remaining(self.deadline)
                )
                return acquisition._Stream(stream, self.deadline)

        listener_port = port
        with monkeypatch.context() as patch:
            patch.setattr(acquisition, "_PublicBackend", RoutedBackend)
            if trust_fixture:
                patch.setattr(http_connection, "default_ssl_context", configured_context)
            thread = threading.Thread(target=serve, name="synthetic-tls-peer")
            thread.start()
            try:
                yield peer
            finally:
                stopping.set()
                thread.join(timeout=3)
                assert not thread.is_alive(), "synthetic TLS peer did not stop"
                assert not errors, "synthetic TLS peer failed"
