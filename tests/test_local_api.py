"""Real local HTTP contract fixtures; no vendor/model download or external request."""

import contextlib
import json
import socket
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from pydantic import ValidationError

from osint_workbench.errors import WorkbenchError
from osint_workbench.inference_state import admission
from osint_workbench.local_api import LocalApiGenerator, LocalApiManifest
from osint_workbench.text import digest

SCHEMA = {
    "type": "object",
    "properties": {"answer": {"type": "string"}},
    "required": ["answer"],
    "additionalProperties": False,
}
OPERATION = {
    "operation_id": "12345678-1234-4234-8234-123456789abc",
    "task": "structured_extraction",
    "data_class": "public",
}


def manifest(endpoint="http:" + "//127.0.0.1:11434/v1/chat/completions", **changes):
    return LocalApiManifest.model_validate(
        {
            "schema_version": 1,
            "endpoint": endpoint,
            "model": "synthetic",
            "operator_controlled": True,
            "remote_forwarding": False,
            "metered": False,
            "qualification_sha256": "a" * 64,
            "model_revision_sha256": "b" * 64,
            "data_classes": ["public"],
            "timeout_seconds": 2,
            **changes,
        }
    )


def completion(**changes):
    return {
        "model": "synthetic",
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": '{"answer":"verified"}'},
            }
        ],
        **changes,
    }


@contextlib.contextmanager
def api_peer(
    *,
    result=None,
    status=200,
    get_status=200,
    models=None,
    raw=None,
    disconnect=False,
    delay=0,
    encoding=None,
    entered=None,
    release=None,
    forward=None,
):
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def send(self, code, body):
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", "application/json")
            if encoding:
                self.send_header("Content-Encoding", encoding)
            self.end_headers()
            with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                self.wfile.write(body)

        def do_GET(self):
            calls.append(
                {
                    "method": "GET",
                    "path": self.path,
                    "authorization": self.headers.get("Authorization"),
                }
            )
            if forward is not None:
                code, body = forward("GET", self.path, None)
                self.send(code, body)
                return
            self.send(
                get_status,
                json.dumps(
                    models if models is not None else {"data": [{"id": "synthetic"}]}
                ).encode(),
            )

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            calls.append(
                {
                    "method": "POST",
                    "path": self.path,
                    "authorization": self.headers.get("Authorization"),
                    "body": json.loads(body),
                }
            )
            if forward is not None:
                code, payload = forward("POST", self.path, body)
                self.send(code, payload)
                return
            if entered:
                entered.set()
            if release:
                release.wait(3)
            if delay:
                time.sleep(delay)
            if disconnect:
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
                return
            payload = raw if raw is not None else json.dumps(result or completion()).encode()
            self.send(status, payload)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
    )
    thread.start()
    try:
        yield "http:" + f"//127.0.0.1:{server.server_port}/v1/chat/completions", calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


@pytest.fixture
def lock(tmp_path, monkeypatch):
    p = tmp_path / "admission.lock"
    monkeypatch.setenv("OW_INFERENCE_LOCK", str(p))
    return p


@pytest.mark.parametrize(
    "endpoint",
    [
        "http:" + "//localhost:11434/v1/chat/completions",
        "https:" + "//provider.example.invalid/v1/chat/completions",
        "https:" + "//8.8.8.8/v1/chat/completions",
        "http:" + "//192.168.1.2:8000/v1/chat/completions",
        "http:" + "//169.254.169.254/v1/chat/completions",
        "http:" + "//0.0.0.0:8000/v1/chat/completions",
        "http:" + "//[::ffff:127.0.0.1]:8000/v1/chat/completions",
        "http:" + "//127.0.0.1/v1/chat/completions?",
        "http:" + "//127.0.0.1/v1/chat/completions#",
        "http:" + "//user:secret@127.0.0.1/v1/chat/completions",
        "http:" + "//127.0.0.1:0/v1/chat/completions",
        "http:" + "//127.0.0.1/v1/embeddings",
        "http:" + "//127.0.0.1/v1/%63hat/completions",
    ],
)
def test_endpoint_authority_is_literal_local_and_fixed(endpoint):
    with pytest.raises(ValidationError):
        manifest(endpoint)


@pytest.mark.parametrize(
    "changes",
    [
        {"operator_controlled": False},
        {"remote_forwarding": True},
        {"metered": True},
        {"data_classes": []},
        {"data_classes": ["public", "public"]},
        {"data_classes": ["unknown"]},
        {"credential_env": "OW_FAKE"},
        {"ca_path": "/private/fixture.pem"},
    ],
)
def test_missing_or_conflicting_declarations_deny_configuration(changes):
    with pytest.raises(ValidationError):
        manifest(**changes)


def test_network_locality_does_not_replace_authentication_or_trust():
    with pytest.raises(ValidationError):
        manifest("https:" + "//192.168.1.2:8000/v1/chat/completions")
    value = manifest(
        "https:" + "//192.168.1.2:8000/v1/chat/completions",
        credential={"kind": "file", "path": "/private/credential"},
    )
    assert value.identity() != manifest().identity()
    assert manifest("http:" + "//[::1]:11434/v1/chat/completions")


def test_actual_http_success_is_typed_bounded_and_releases_admission(lock):
    with api_peer() as (url, calls):
        generator = LocalApiGenerator(manifest(url))
        result = generator.generate("Synthetic source data.", SCHEMA, operation=OPERATION)
    assert result["output"] == {"answer": "verified"}
    assert result["generator_id"] == generator.manifest.identity()
    assert [(c["method"], c["path"]) for c in calls] == [
        ("GET", "/v1/models"),
        ("POST", "/v1/chat/completions"),
    ]
    body = calls[1]["body"]
    assert body["stream"] is False and body["response_format"]["json_schema"]["schema"] == SCHEMA
    assert not {"tools", "tool_choice", "functions"} & body.keys()
    assert body["messages"][1] == {"role": "user", "content": "Synthetic source data."}
    with admission() as held:
        assert held.read_marker() is None


@pytest.mark.parametrize(
    ("result", "code"),
    [
        (completion(choices=[{"finish_reason": "length"}]), "GENERATION_INCOMPLETE"),
        (
            completion(
                choices=[{"finish_reason": "content_filter", "message": {"role": "assistant"}}]
            ),
            "LOCAL_API_REFUSED",
        ),
        (
            completion(choices=[{"finish_reason": "tool_calls", "message": {"role": "assistant"}}]),
            "LOCAL_API_TOOLS_REFUSED",
        ),
        (
            completion(
                choices=[
                    {"finish_reason": "stop", "message": {"role": "assistant", "content": "{}"}}
                ]
            ),
            "INVALID_MODEL_RESULT",
        ),
        (
            completion(
                choices=[
                    {
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": '{"answer":NaN}'},
                    }
                ]
            ),
            "INVALID_MODEL_RESULT",
        ),
    ],
)
def test_recognized_completion_errors_are_terminal_and_release(lock, result, code):
    with api_peer(result=result) as (url, calls):
        generator = LocalApiGenerator(manifest(url))
        with pytest.raises(WorkbenchError, match=f"^{code}$"):
            generator.generate("Synthetic.", SCHEMA, operation=OPERATION)
    assert sum(c["method"] == "POST" for c in calls) == 1
    with admission() as held:
        assert held.read_marker() is None


@pytest.mark.parametrize(
    "changes",
    [
        {"disconnect": True},
        {"raw": b"not-json"},
        {"status": 302},
        {"result": completion(model="different")},
        {"result": completion(choices=[])},
        {"result": completion(choices=[{"finish_reason": "unexpected"}])},
        {"raw": b"x" * (1024 * 1024 + 1)},
        {"delay": 1.3},
    ],
)
def test_ambiguous_post_retains_reservation_and_cannot_retry(lock, changes):
    with api_peer(**changes) as (url, calls):
        generator = LocalApiGenerator(manifest(url, timeout_seconds=1))
        with pytest.raises(WorkbenchError, match="^INFERENCE_OUTCOME_UNKNOWN$"):
            generator.generate("Synthetic.", SCHEMA, operation=OPERATION)
        with pytest.raises(WorkbenchError, match="^INFERENCE_OUTCOME_UNKNOWN$"):
            generator.generate("Synthetic.", SCHEMA, operation=OPERATION)
    assert sum(c["method"] == "POST" for c in calls) == 1
    with admission(allow_uncertain=True) as held:
        receipt = held.read_marker()
        assert receipt.value["operation_id"] == OPERATION["operation_id"]
        assert receipt.value["format"] == "local-api-operation/1"
        assert set(receipt.value) == {"format", "generator_id", "operation_id", "request_sha256"}
    with pytest.raises(WorkbenchError, match="TERMINATION_EVIDENCE_REQUIRED"):
        generator.reconcile()
    with pytest.raises(WorkbenchError, match="TERMINATION_EVIDENCE_REQUIRED"):
        generator.reconcile(
            operation_id=str(uuid.uuid4()), evidence_sha256="c" * 64, confirmed=True
        )
    assert (
        generator.reconcile(
            operation_id=OPERATION["operation_id"], evidence_sha256="c" * 64, confirmed=True
        )["status"]
        == "resolved"
    )
    audit = lock.parent / ("ow-inference-resolution-" + OPERATION["operation_id"] + ".json")
    record = json.loads(audit.read_text())
    assert record["receipt"] == receipt.value
    assert record["evidence_sha256"] == "c" * 64
    assert audit.stat().st_mode & 0o777 == 0o600
    with admission() as held:
        assert held.read_marker() is None


@pytest.mark.parametrize(
    "operation", [{}, {**OPERATION, "data_class": None}, {**OPERATION, "data_class": "personal"}]
)
def test_unclassified_or_unapproved_data_never_connects(lock, operation):
    with api_peer() as (url, calls):
        with pytest.raises(WorkbenchError, match="DATA_CLASS_DENIED"):
            LocalApiGenerator(manifest(url)).generate("Synthetic", SCHEMA, operation=operation)
    assert calls == []


def test_model_probe_and_credential_refusal_never_post(lock, tmp_path):
    with api_peer(models={"data": [{"id": "other"}]}) as (url, calls):
        with pytest.raises(WorkbenchError, match="MODEL_UNAVAILABLE"):
            LocalApiGenerator(manifest(url)).generate("Synthetic", SCHEMA, operation=OPERATION)
        assert len(calls) == 1 and calls[0]["method"] == "GET"
    with api_peer() as (url, calls):
        generator = LocalApiGenerator(
            manifest(url, credential={"kind": "file", "path": str(tmp_path / "missing")})
        )
        with pytest.raises(WorkbenchError, match="CREDENTIAL_UNAVAILABLE"):
            generator.generate("Synthetic", SCHEMA, operation=OPERATION)
        assert calls == []


@pytest.mark.parametrize("escaped", [False, True])
@pytest.mark.parametrize("kind", ["file", "systemd"])
def test_checked_credential_is_bound_once_and_reflection_never_accepted(
    lock, tmp_path, monkeypatch, escaped, kind
):
    key = "synthetic-local-credential-canary"
    p = tmp_path / "credential"
    p.write_text(key)
    p.chmod(0o600)
    text = json.dumps({"answer": key})
    if escaped:
        text = text.replace("synthetic", "\\u0073ynthetic")
    output = completion(
        choices=[{"finish_reason": "stop", "message": {"role": "assistant", "content": text}}]
    )
    reference = {"kind": "file", "path": str(p)}
    if kind == "systemd":
        monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
        reference = {"kind": "systemd", "name": "credential"}

    def rotate_after_probe(method, path, body):
        if method == "GET":
            p.write_text("replacement-synthetic-credential")
            return 200, json.dumps({"data": [{"id": "synthetic"}]}).encode()
        return 200, json.dumps(output).encode()

    with api_peer(forward=rotate_after_probe) as (url, calls):
        generator = LocalApiGenerator(manifest(url, credential=reference))
        with pytest.raises(WorkbenchError, match="^LOCAL_API_CREDENTIAL_REFLECTED$"):
            generator.generate("Synthetic", SCHEMA, operation=OPERATION)
        assert all(c["authorization"] == "Bearer " + key for c in calls)
    with admission() as held:
        assert held.read_marker() is None


def test_busy_generation_cannot_overlap_other_cooperating_profiles(lock):
    entered, release = threading.Event(), threading.Event()
    results = []
    with api_peer(entered=entered, release=release) as (url, calls):
        generator = LocalApiGenerator(manifest(url))
        thread = threading.Thread(
            target=lambda: results.append(
                generator.generate("Synthetic", SCHEMA, operation=OPERATION)
            )
        )
        thread.start()
        assert entered.wait(3)
        try:
            with pytest.raises(WorkbenchError, match="^INFERENCE_BUSY$"):
                with admission():
                    pass
        finally:
            release.set()
            thread.join(timeout=3)
    assert results[0]["output"] == {"answer": "verified"}


def test_actual_tls_private_trust_and_peer_identity(lock, tmp_path):
    import shutil
    import ssl
    import subprocess

    assert shutil.which("openssl"), "OpenSSL is required for the TLS fixture"
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-subj",
            "/CN=Synthetic local API",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
            "-addext",
            "basicConstraints=critical,CA:true",
        ],
        capture_output=True,
        check=True,
    )
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def respond(self, data):
            body = json.dumps(data).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            calls.append((self.path, self.headers.get("Authorization")))
            self.respond({"data": [{"id": "synthetic"}]})

        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            calls.append((self.path, self.headers.get("Authorization")))
            self.respond(completion())

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
    )
    thread.start()
    token = tmp_path / "token"
    token.write_text("synthetic-tls-token")
    token.chmod(0o600)
    try:
        endpoint = "https:" + f"//127.0.0.1:{server.server_port}/v1/chat/completions"
        selected = manifest(
            endpoint,
            ca_path=str(cert),
            ca_sha256=digest(cert.read_bytes()),
            credential={"kind": "file", "path": str(token)},
        )
        assert LocalApiGenerator(selected).generate("Synthetic", SCHEMA, operation=OPERATION)[
            "output"
        ] == {"answer": "verified"}
        assert len(calls) == 2 and all(h == "Bearer synthetic-tls-token" for _, h in calls)
        with pytest.raises(WorkbenchError, match="LOCAL_API_TRUST_INVALID"):
            LocalApiGenerator(manifest(endpoint, ca_path=str(cert), ca_sha256="f" * 64)).generate(
                "Synthetic", SCHEMA, operation=OPERATION
            )
        assert len(calls) == 2
        with pytest.raises(WorkbenchError, match="LOCAL_API_UNAVAILABLE"):
            LocalApiGenerator(manifest(endpoint)).generate("Synthetic", SCHEMA, operation=OPERATION)
        assert len(calls) == 2
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_api_resolution_write_before_unlink_retry_is_idempotent(lock, monkeypatch):
    from osint_workbench.inference_state import Admission

    with admission() as held:
        held.create_api_marker(manifest().identity(), OPERATION["operation_id"], "d" * 64)
    original = Admission.remove_marker

    def fail_unlink(self, expected):
        raise WorkbenchError("INFERENCE_LOCK_UNSAFE")

    monkeypatch.setattr(Admission, "remove_marker", fail_unlink)
    generator = LocalApiGenerator(manifest())
    with pytest.raises(WorkbenchError, match="INFERENCE_LOCK_UNSAFE"):
        generator.reconcile(
            operation_id=OPERATION["operation_id"], evidence_sha256="c" * 64, confirmed=True
        )
    assert Path(str(lock) + ".unknown").exists()
    # A conflicting disposition never overwrites the retained audit.
    with pytest.raises(WorkbenchError, match="INFERENCE_LOCK_UNSAFE"):
        generator.reconcile(
            operation_id=OPERATION["operation_id"], evidence_sha256="e" * 64, confirmed=True
        )
    monkeypatch.setattr(Admission, "remove_marker", original)
    assert (
        generator.reconcile(
            operation_id=OPERATION["operation_id"], evidence_sha256="c" * 64, confirmed=True
        )["status"]
        == "resolved"
    )


def test_other_generator_cannot_clear_an_api_reservation(lock):
    with admission() as held:
        held.create_api_marker(manifest().identity(), OPERATION["operation_id"], "d" * 64)
    other = LocalApiGenerator(manifest(model="other"))
    with pytest.raises(WorkbenchError, match="INFERENCE_OWNER_MISMATCH"):
        other.reconcile(
            operation_id=OPERATION["operation_id"], evidence_sha256="c" * 64, confirmed=True
        )
    assert Path(str(lock) + ".unknown").exists()


@pytest.mark.parametrize(
    "changes", [{"metered": 0}, {"operator_controlled": 1}, {"remote_forwarding": 0}]
)
def test_control_declarations_require_json_booleans(changes):
    with pytest.raises(ValidationError):
        manifest(**changes)


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "partial"])
def test_unsafe_resolution_audit_never_clears_reservation(lock, tmp_path, kind):
    import os

    with admission() as held:
        held.create_api_marker(manifest().identity(), OPERATION["operation_id"], "d" * 64)
    audit = lock.parent / ("ow-inference-resolution-" + OPERATION["operation_id"] + ".json")
    target = tmp_path / "unchanged"
    target.write_text("fixture-canary")
    target.chmod(0o600)
    if kind == "symlink":
        audit.symlink_to(target)
    elif kind == "hardlink":
        os.link(target, audit)
    elif kind == "fifo":
        os.mkfifo(audit, 0o600)
    else:
        audit.write_text("{")
        audit.chmod(0o600)
    with pytest.raises(WorkbenchError, match="INFERENCE_LOCK_UNSAFE"):
        LocalApiGenerator(manifest()).reconcile(
            operation_id=OPERATION["operation_id"], evidence_sha256="c" * 64, confirmed=True
        )
    assert Path(str(lock) + ".unknown").exists()
    assert target.read_text() == "fixture-canary"


@pytest.mark.parametrize(
    "flags",
    [
        ["--manifest", "unused"],
        ["--route", "unused"],
        ["--cloud-policy", "unused"],
        ["--confirm-terminated"],
    ],
)
def test_installed_cli_rejects_conflicting_selection_or_resolution_without_effects(tmp_path, flags):
    import os
    import subprocess
    import sys

    path = tmp_path / "api.json"
    path.write_text(manifest().model_dump_json())
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            "osint_workbench.cli",
            "enrich",
            "enqueue",
            "--local-api-manifest",
            str(path),
            *flags,
        ],
        env={k: v for k, v in os.environ.items() if not k.startswith("OW_")},
        capture_output=True,
        text=True,
        timeout=4,
        check=False,
    )
    expected = (
        "INVALID_LOCAL_API_RECONCILIATION"
        if "--confirm-terminated" in flags
        else "GENERATOR_SELECTION_REQUIRED"
    )
    assert result.returncode == 1 and result.stdout == ""
    assert json.loads(result.stderr) == {"error": expected}


@pytest.mark.parametrize("mutation", ["rename", "truncate", "same-size"])
@pytest.mark.parametrize("existing", [False, True])
def test_resolution_audit_replacement_after_write_keeps_marker(
    lock, monkeypatch, mutation, existing
):
    import os
    import stat

    with admission() as held:
        held.create_api_marker(manifest().identity(), OPERATION["operation_id"], "d" * 64)
    audit = lock.parent / ("ow-inference-resolution-" + OPERATION["operation_id"] + ".json")
    if existing:
        with admission(allow_uncertain=True) as held:
            value = {
                "format": "local-api-resolution/1",
                "receipt": held.read_marker().value,
                "disposition": "operator-confirmed-terminated",
                "evidence_sha256": "c" * 64,
            }
        audit.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")))
        audit.chmod(0o600)
    original = os.fsync
    changed = False

    def substitute_after_fsync(fd):
        nonlocal changed
        original(fd)
        info = os.fstat(fd)
        if stat.S_ISREG(info.st_mode) and audit.exists() and not changed:
            changed = True
            if mutation == "rename":
                audit.rename(audit.with_suffix(".retained"))
                audit.write_bytes(b"substituted-audit")
                audit.chmod(0o600)
            elif mutation == "same-size":
                audit.write_bytes(b"x" * audit.stat().st_size)
            else:
                audit.write_bytes(b"truncated-audit")

    monkeypatch.setattr(os, "fsync", substitute_after_fsync)
    with pytest.raises(WorkbenchError, match="INFERENCE_LOCK_UNSAFE"):
        LocalApiGenerator(manifest()).reconcile(
            operation_id=OPERATION["operation_id"], evidence_sha256="c" * 64, confirmed=True
        )
    assert changed and Path(str(lock) + ".unknown").exists()


def test_long_lock_basename_still_has_bounded_resolution_filename(lock, monkeypatch):
    long_lock = lock.parent / ("x" * 220)
    monkeypatch.setenv("OW_INFERENCE_LOCK", str(long_lock))
    with admission() as held:
        held.create_api_marker(manifest().identity(), OPERATION["operation_id"], "d" * 64)
    result = LocalApiGenerator(manifest()).reconcile(
        operation_id=OPERATION["operation_id"], evidence_sha256="c" * 64, confirmed=True
    )
    assert result["status"] == "resolved"
    assert not Path(str(long_lock) + ".unknown").exists()
    assert (
        lock.parent / ("ow-inference-resolution-" + OPERATION["operation_id"] + ".json")
    ).exists()


@pytest.mark.parametrize("operation_id", ["../escape", "a/b", "unqualified", 42])
def test_resolution_rejects_unqualified_basename_input_before_file_effects(lock, operation_id):
    from dataclasses import replace

    with admission() as held:
        receipt = held.create_api_marker(manifest().identity(), OPERATION["operation_id"], "d" * 64)
        forged = replace(receipt, value={**receipt.value, "operation_id": operation_id})
        with pytest.raises(WorkbenchError, match="INFERENCE_LOCK_UNSAFE"):
            held.resolve_api_marker(forged, "c" * 64)
        assert held.read_marker() == receipt
    assert not list(lock.parent.glob("ow-inference-resolution-*"))


@pytest.mark.integration
def test_local_api_batch_cap_identity_and_installed_cli(databases, tmp_path, lock):
    import os
    import subprocess
    import sys

    from osint_workbench import intelligence
    from osint_workbench.contracts import DocumentInput
    from osint_workbench.evidence import EvidenceStore

    writer, _, roles = databases
    store = EvidenceStore(tmp_path / "evidence")
    document = writer.ingest(
        DocumentInput(source_id="fixture", external_id="batch", title="Synthetic", text="Bounded."),
        b"Bounded.",
        store,
    )
    response = completion(
        choices=[
            {"finish_reason": "stop", "message": {"role": "assistant", "content": '{"claims":[]}'}}
        ]
    )
    with api_peer(result=response) as (url, calls):
        selected = manifest(url)
        generator = LocalApiGenerator(selected)
        for operation in ("one", "two", "three"):
            intelligence.enqueue(writer, generator, document, operation, "public")
        other = LocalApiGenerator(manifest(url, qualification_sha256="c" * 64))
        intelligence.enqueue(writer, other, document, "other", "public")
        config = tmp_path / "api.json"
        config.write_text(selected.model_dump_json())
        environment = {
            **os.environ,
            "OW_WRITER_DSN": roles["writer"],
            "OW_EVIDENCE_ROOT": str(store.root),
        }
        command = [
            sys.executable,
            "-m",
            "osint_workbench.cli",
            "enrich",
            "work",
            "--local-api-manifest",
            str(config),
            "--max-jobs",
            "2",
        ]
        first = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=30)
        assert first.returncode == 0, first.stderr
        value = json.loads(first.stdout)
        assert value["attempted"] == value["abstained"] == 2 and value["limit_reached"]
        second = subprocess.run(
            command, env=environment, capture_output=True, text=True, timeout=30
        )
        assert second.returncode == 0, second.stderr
        value = json.loads(second.stdout)
        assert value["attempted"] == value["abstained"] == 1 and value["idle_observed"]
        assert len([call for call in calls if call["method"] == "POST"]) == 3
        with writer.connect() as conn:
            assert (
                conn.execute(
                    "SELECT count(*) AS n FROM ow.jobs WHERE kind=%s AND status='ready'",
                    (intelligence._kind(other),),
                ).fetchone()["n"]
                == 1
            )


@pytest.mark.integration
def test_local_api_batch_stops_after_uncertain_outcome_without_redispatch(
    databases, tmp_path, lock
):
    from osint_workbench import intelligence
    from osint_workbench.contracts import DocumentInput
    from osint_workbench.evidence import EvidenceStore

    writer, _, _ = databases
    store = EvidenceStore(tmp_path / "evidence")
    document = writer.ingest(
        DocumentInput(
            source_id="fixture", external_id="uncertain-batch", title="Synthetic", text="Bounded."
        ),
        b"Bounded.",
        store,
    )
    with api_peer(disconnect=True) as (url, calls):
        generator = LocalApiGenerator(manifest(url))
        for operation in ("one", "two"):
            intelligence.enqueue(writer, generator, document, operation, "public")
        result = intelligence.enrich_batch(writer, store, generator, max_jobs=4)
        assert result["attempted"] == result["failed"] == 1 and result["stopped_on_failure"]
        assert not result["limit_reached"] and not result["idle_observed"]
        before = len(calls)
        result = intelligence.enrich_batch(writer, store, generator, max_jobs=4)
        assert result["attempted"] == result["failed"] == 1
        assert len(calls) == before
        with admission() as held:
            assert held.read_marker() is not None


@pytest.mark.parametrize(
    "flags,code",
    [
        (["--route", "fixture"], "LOCAL_API_BATCH_REQUIRED"),
        (["--manifest", "/absent"], "LOCAL_API_BATCH_REQUIRED"),
        (["--local-api-manifest", "/absent", "--max-jobs", "33"], "INVALID_WORK_LIMIT"),
    ],
)
def test_local_api_batch_cli_refuses_wrong_profile_before_configuration(
    monkeypatch, capsys, flags, code
):
    import sys

    from osint_workbench import cli

    monkeypatch.setattr(sys, "argv", ["osint-workbench", "enrich", "work", *flags])
    with pytest.raises(SystemExit) as failed:
        cli.main()
    assert failed.value.code == 1
    captured = capsys.readouterr()
    assert json.loads(captured.err) == {"error": code} and not captured.out
