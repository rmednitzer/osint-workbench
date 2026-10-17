import contextlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from socketserver import UnixStreamServer

import httpcore
import pytest

from osint_workbench.errors import WorkbenchError
from osint_workbench.local_generation import GeneratorManifest, LocalGenerator, file_digest
from tests.native_model import make_model

pytestmark = pytest.mark.integration
REVISION = "f2f667b02dc76d675395ae3b14546c8108d26387"
SCHEMA = {
    "type": "object",
    "properties": {"answer": {"type": "string", "enum": ["verified"]}},
    "required": ["answer"],
    "additionalProperties": False,
}


@pytest.fixture
def native_generator(monkeypatch):
    binary = os.environ.get("OW_TEST_LLAMA_BIN")
    if not binary:
        pytest.skip("native generation not provisioned; not verified")
    with tempfile.TemporaryDirectory(prefix="ow-native-", dir="/tmp") as directory:
        root = Path(directory)
        model = root / "model.gguf"
        sock = root / "server.sock"
        make_model(model)
        monkeypatch.setenv("OW_INFERENCE_LOCK", str(root / "admission.lock"))
        with (root / "server.log").open("w+b") as log:
            child = subprocess.Popen(
                [
                    binary,
                    "-m",
                    str(model),
                    "--host",
                    str(sock),
                    "--alias",
                    "synthetic",
                    "-c",
                    "4096",
                    "-np",
                    "1",
                    "-t",
                    "1",
                    "-ngl",
                    "0",
                    "--no-ui",
                ],
                stdout=log,
                stderr=log,
                env={"PATH": os.environ.get("PATH", "")},
            )
            try:
                deadline = time.monotonic() + 30
                ready = False
                while time.monotonic() < deadline and child.poll() is None:
                    if sock.exists():
                        sock.chmod(0o600)
                        try:
                            with httpcore.ConnectionPool(uds=str(sock)) as pool:
                                if (
                                    pool.request("GET", "http://inference.invalid/health").status
                                    == 200
                                ):
                                    ready = True
                                    break
                        except httpcore.HTTPError:
                            pass
                    time.sleep(0.05)
                if not ready:
                    log.seek(0)
                    pytest.fail(
                        "native fixture startup failed: "
                        + log.read().decode(errors="replace")[-4000:]
                    )
                yield LocalGenerator(
                    GeneratorManifest(
                        socket_path=str(sock),
                        peer_uid=os.getuid(),
                        runtime_binary_sha256=file_digest(binary, 256 * 1024**2),
                        runtime_source_revision=REVISION,
                        model_path=str(model),
                        model_sha256=file_digest(model, 32 * 1024**3),
                        model_alias="synthetic",
                        context_tokens=4096,
                        max_output_tokens=256,
                        timeout_seconds=15,
                    )
                )
            finally:
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=5)


def test_actual_native_cpu_generation_and_context_guard(native_generator):
    generator = native_generator
    result = generator.generate("Return a JSON result.", SCHEMA)
    assert result["output"] == {"answer": "verified"}
    assert result["generator_id"] == generator.manifest.identity()
    assert generator.reconcile()["status"] == "idle"
    with pytest.raises(WorkbenchError, match="CONTEXT_EXCEEDED"):
        generator.generate("x" * 12000, SCHEMA)


@contextlib.contextmanager
def fixture_server(tmp_path, monkeypatch):
    # Short pathname stays below Linux sockaddr_un limits.
    with tempfile.TemporaryDirectory(prefix="ow-wire-", dir="/tmp") as directory:
        root = Path(directory)
        sock = root / "server.sock"
        model = root / "fixture.gguf"
        model.write_bytes(b"synthetic fixture model, not operational data")
        state = {
            "mode": "valid",
            "busy": False,
            "calls": [],
            "entered": threading.Event(),
            "release": threading.Event(),
        }

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.answer()

            def do_POST(self):
                self.answer()

            def answer(self):
                body = json.loads(
                    self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}"
                )
                state["calls"].append((self.path, body))
                if self.path == "/props":
                    value = {
                        "model_path": str(model),
                        "total_slots": 1,
                        "default_generation_settings": {"n_ctx": 4096},
                    }
                elif self.path == "/slots":
                    value = [{"is_processing": state["busy"]}]
                elif self.path == "/tokenize":
                    value = {"tokens": [1, 3, 4]}
                elif self.path == "/completion":
                    if state["mode"] == "hold":
                        state["entered"].set()
                        assert state["release"].wait(10)
                    if state["mode"] == "disconnect":
                        self.close_connection = True
                        return
                    value = {
                        "model": "synthetic",
                        "content": '{"answer":"verified"}',
                        "stop_type": "eos",
                        "truncated": False,
                    }
                    if state["mode"] == "schema":
                        value["content"] = '{"shell":"forbidden"}'
                    if state["mode"] == "truncated":
                        value["truncated"] = True
                else:
                    self.send_error(404)
                    return
                data = json.dumps(value).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                try:
                    self.wfile.write(data)
                except BrokenPipeError:
                    pass

        server = UnixStreamServer(str(sock), Handler)
        sock.chmod(0o600)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        monkeypatch.setenv("OW_INFERENCE_LOCK", str(root / "admission.lock"))
        manifest = GeneratorManifest(
            socket_path=str(sock),
            peer_uid=os.getuid(),
            runtime_binary_sha256=file_digest(
                f"/proc/{os.getpid()}/exe", 256 * 1024**2, kernel_link=True
            ),
            runtime_source_revision=REVISION,
            model_path=str(model),
            model_sha256=file_digest(model, 1024),
            model_alias="synthetic",
            context_tokens=4096,
            max_output_tokens=256,
            timeout_seconds=2,
        )
        try:
            yield LocalGenerator(manifest), state, sock, root
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


def test_native_wire_validation_and_unknown_ownership(tmp_path, monkeypatch):
    with fixture_server(tmp_path, monkeypatch) as (generator, state, sock, root):
        assert generator.generate("Fixture prompt", SCHEMA)["output"] == {"answer": "verified"}
        state["mode"] = "schema"
        with pytest.raises(WorkbenchError, match="INVALID_MODEL_RESULT"):
            generator.generate("Fixture prompt", SCHEMA)
        state["mode"] = "truncated"
        with pytest.raises(WorkbenchError, match="INCOMPLETE"):
            generator.generate("Fixture prompt", SCHEMA)
        state["mode"] = "disconnect"
        with pytest.raises(WorkbenchError, match="OUTCOME_UNKNOWN"):
            generator.generate("Fixture prompt", SCHEMA)
        assert (root / "admission.lock.unknown").exists()
        with pytest.raises(WorkbenchError, match="OUTCOME_UNKNOWN"):
            generator.generate("Fixture prompt", SCHEMA)
        state["busy"] = True
        with pytest.raises(WorkbenchError, match="STILL_RUNNING"):
            generator.reconcile()
        state["busy"] = False
        assert generator.reconcile()["status"] == "idle"
        assert not (root / "admission.lock.unknown").exists()
        state["mode"] = "valid"
        sock.chmod(stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
        with pytest.raises(WorkbenchError, match="SOCKET_UNSAFE"):
            generator.generate("Fixture prompt", SCHEMA)


def test_killed_generation_client_preserves_uncertain_reservation(tmp_path, monkeypatch):
    with fixture_server(tmp_path, monkeypatch) as (generator, state, _, root):
        state["mode"] = "hold"
        config = root / "generator.json"
        config.write_text(generator.manifest.model_dump_json())
        script = """import sys
from pathlib import Path
from osint_workbench.local_generation import GeneratorManifest,LocalGenerator
manifest=GeneratorManifest.model_validate_json(Path(sys.argv[1]).read_bytes())
LocalGenerator(manifest).generate('Fixture prompt',{'type':'object'})
"""
        child = subprocess.Popen(
            [sys.executable, "-c", script, str(config)], stderr=subprocess.DEVNULL
        )
        try:
            assert state["entered"].wait(10)
            assert (root / "admission.lock.unknown").exists()
        finally:
            child.kill()
            child.wait(timeout=5)
            state["release"].set()
        with pytest.raises(WorkbenchError, match="OUTCOME_UNKNOWN"):
            generator.generate("Fixture prompt", SCHEMA)
        assert generator.reconcile()["status"] == "idle"
