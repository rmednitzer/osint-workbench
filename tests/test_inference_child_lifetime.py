"""Inference children are owned by the process holding admission."""

import json
import os
import signal
import subprocess
import sys
import time

import pytest

from osint_workbench import local_encoder, local_reranker
from osint_workbench.errors import WorkbenchError

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux parent-death signal")

CHILDREN = ["osint_workbench.encoder_process", "osint_workbench.rerank_process"]


@pytest.mark.parametrize("module", CHILDREN)
@pytest.mark.parametrize("parent", [None, "1", "not-a-pid"])
def test_child_without_its_actual_parent_binding_refuses_work(module, parent):
    env = {} if parent is None else {"OW_INFERENCE_PARENT": parent}
    result = subprocess.run(
        [sys.executable, "-I", "-m", module],
        input=b"{}",
        capture_output=True,
        timeout=30,
        check=False,
        env=env,
    )
    assert result.returncode == 1
    assert json.loads(result.stdout) == {"error": "INFERENCE_PARENT_UNBOUND"}


# The intermediate parent starts the real child bound to itself and reports
# its PID. The test process holds the packet pipe's write end, so the child
# stays blocked after the parent dies unless the lifetime binding kills it.
PARENT = """
import os, subprocess, sys
child = subprocess.Popen(
    [sys.executable, "-I", "-m", sys.argv[1]],
    stdin=int(sys.argv[2]), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    env={"OW_INFERENCE_PARENT": str(os.getpid())},
)
print(child.pid, flush=True)
child.wait()
"""


def _alive(pid):
    try:
        with open(f"/proc/{pid}/stat") as handle:
            return handle.read().split(") ", 1)[1][0] != "Z"
    except FileNotFoundError:
        return False


@pytest.mark.parametrize("module", CHILDREN)
def test_killed_parent_takes_its_running_child_with_it(module, tmp_path):
    read_end, write_end = os.pipe()
    parent = subprocess.Popen(
        [sys.executable, "-c", PARENT, module, str(read_end)],
        stdout=subprocess.PIPE,
        cwd=tmp_path,
        pass_fds=(read_end,),
    )
    os.close(read_end)
    child = None
    try:
        child = int(parent.stdout.readline())
        # Let the child pass its own binding check and block on stdin.
        time.sleep(1.0)
        assert _alive(child)
        os.kill(parent.pid, signal.SIGKILL)
        parent.wait(timeout=10)
        deadline = time.monotonic() + 10
        while _alive(child) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not _alive(child)
    finally:
        if child is not None and _alive(child):
            os.kill(child, signal.SIGKILL)
        if parent.poll() is None:
            parent.kill()
        parent.stdout.close()
        os.close(write_end)


class Exited:
    def __init__(self, code, payload=b""):
        self.code, self.payload = code, payload

    def __call__(self, args, *, stdout, **kwargs):
        stdout.write(self.payload)
        return subprocess.CompletedProcess(args, self.code)


@pytest.mark.parametrize(
    "code,payload,expected",
    [
        (-signal.SIGXCPU, b"", "ENCODER_UNAVAILABLE"),
        (-signal.SIGKILL, b'{"error":"MODEL_INTEGRITY_MISMATCH"}', "ENCODER_UNAVAILABLE"),
        (1, b"", "ENCODER_UNAVAILABLE"),
        (1, b'{"error":"ENCODER_RESULT_LIMIT"}', "ENCODER_RESULT_LIMIT"),
        (2, b'{"error":"ARBITRARY_CHILD_TEXT"}', "ENCODER_UNAVAILABLE"),
    ],
)
def test_encoder_exit_status_is_classified_before_result_decoding(
    encoder_bundle, monkeypatch, code, payload, expected
):
    monkeypatch.setattr(local_encoder.subprocess, "run", Exited(code, payload))
    with pytest.raises(WorkbenchError, match=f"^{expected}$"):
        encoder_bundle.chunks("storage disk")


@pytest.mark.parametrize(
    "code,payload,expected",
    [
        (-signal.SIGXCPU, b"", "RERANK_UNAVAILABLE"),
        (1, b"[]", "RERANK_UNAVAILABLE"),
        (0, b"[]", "RERANK_INVALID_RESULT"),
        (0, b'{"scores":{"a":1}}', "RERANK_INVALID_RESULT"),
        (0, b'"text"', "RERANK_INVALID_RESULT"),
    ],
)
def test_reranker_exit_and_result_shape_are_typed(
    reranker_bundle, monkeypatch, code, payload, expected
):
    monkeypatch.setattr(local_reranker.subprocess, "run", Exited(code, payload))
    with pytest.raises(WorkbenchError, match=f"^{expected}$"):
        reranker_bundle.rank("patch", [{"document_id": "a" * 64, "excerpt": "storage disk"}])
