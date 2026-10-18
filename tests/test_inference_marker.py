"""Real filesystem/process boundaries; synthetic receipts never contain user data."""

import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from osint_workbench.errors import WorkbenchError
from osint_workbench.inference_state import admission
from osint_workbench.local_generation import _process_start
from tests.test_generation import SCHEMA, fixture_server

GENERATOR_ID = "a" * 64


@pytest.fixture
def lock_path(tmp_path, monkeypatch):
    path = tmp_path / "admission.lock"
    monkeypatch.setenv("OW_INFERENCE_LOCK", str(path))
    return path


def peer():
    # Filesystem-only fixtures do not claim a verified native peer identity.
    return {"pid": os.getpid(), "start": "123456789"}


def child_admission(path, *, uncertain=False, read_marker=False):
    # Actual installed import, bounded subprocess and no alternate production route.
    return subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            "from osint_workbench.inference_state import admission\n"
            "from osint_workbench.errors import WorkbenchError\n"
            "try:\n"
            f" with admission(allow_uncertain={uncertain}) as held:\n"
            f"  {'held.read_marker()' if read_marker else 'pass'}\n"
            "except WorkbenchError as exc: print(exc.code); raise SystemExit(1)\n",
        ],
        env={**os.environ, "OW_INFERENCE_LOCK": str(path)},
        capture_output=True,
        text=True,
        timeout=3,
        check=False,
    )


@pytest.mark.parametrize("mode", [0o700, 0o750, 0o755])
def test_safe_operator_owned_parent_modes_support_receipt_roundtrip(lock_path, mode):
    lock_path.parent.chmod(mode)
    with admission() as held:
        receipt = held.create_marker(GENERATOR_ID, peer())
        assert held.read_marker() == receipt
        assert receipt.value["generator_id"] == GENERATOR_ID
        assert (lock_path.stat().st_mode & 0o7777) == 0o600
        assert (Path(str(lock_path) + ".unknown").stat().st_mode & 0o7777) == 0o600
        held.remove_marker(receipt)
        assert held.read_marker() is None


@pytest.mark.parametrize("mode", [0o777, 0o770, 0o1777])
def test_writable_configured_parent_rejected_before_lock_creation(lock_path, mode):
    lock_path.parent.chmod(mode)
    result = child_admission(lock_path)
    assert result.returncode == 1 and result.stdout == "INFERENCE_LOCK_UNSAFE\n"
    assert result.stderr == "" and not lock_path.exists()


def test_root_sticky_tmp_remains_supported(tmp_path, monkeypatch):
    # Only this test's unique lock is created in the existing root-owned /tmp.
    path = Path("/tmp") / ("ow-marker-fixture-" + tmp_path.name + f"-{os.getpid()}")
    monkeypatch.setenv("OW_INFERENCE_LOCK", str(path))
    try:
        with admission() as held:
            assert held.read_marker() is None
        assert path.stat().st_uid == os.getuid()
    finally:
        path.unlink(missing_ok=True)


def test_symlink_parent_component_is_not_followed(lock_path, tmp_path):
    actual = tmp_path / "actual"
    actual.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(actual, target_is_directory=True)
    result = child_admission(alias / "admission.lock")
    assert result.returncode == 1 and result.stdout == "INFERENCE_LOCK_UNSAFE\n"
    assert result.stderr == "" and list(actual.iterdir()) == []


@pytest.mark.parametrize("kind", ["fifo", "symlink", "directory", "hardlink", "public-mode"])
def test_unsafe_lock_fails_closed_without_blocking(lock_path, kind):
    target = lock_path.parent / "unchanged-target"
    target.write_bytes(b"synthetic path-content canary")
    target.chmod(0o600)
    if kind == "fifo":
        os.mkfifo(lock_path, 0o600)
    elif kind == "symlink":
        lock_path.symlink_to(target)
    elif kind == "directory":
        lock_path.mkdir(mode=0o700)
    elif kind == "hardlink":
        os.link(target, lock_path)
    else:
        lock_path.write_bytes(b"")
        lock_path.chmod(0o644)
    result = child_admission(lock_path)
    assert result.returncode == 1 and result.stdout == "INFERENCE_LOCK_UNSAFE\n"
    assert result.stderr == "" and target.read_bytes() == b"synthetic path-content canary"


@pytest.mark.parametrize(
    "kind", ["fifo", "symlink", "directory", "hardlink", "public-mode", "oversize", "malformed"]
)
def test_unsafe_marker_blocks_admission_and_bounded_receipt_read(lock_path, kind):
    with admission() as held:
        receipt = held.create_marker(GENERATOR_ID, peer())
    marker = Path(str(lock_path) + ".unknown")
    marker.unlink()
    target = lock_path.parent / "unchanged-receipt-target"
    target.write_bytes(receipt.data)
    target.chmod(0o600)
    if kind == "fifo":
        os.mkfifo(marker, 0o600)
    elif kind == "symlink":
        marker.symlink_to(target)
    elif kind == "directory":
        marker.mkdir(mode=0o700)
    elif kind == "hardlink":
        os.link(target, marker)
    else:
        marker.write_bytes(
            b"x" * 4097 if kind == "oversize" else b"{" if kind == "malformed" else receipt.data
        )
        marker.chmod(0o644 if kind == "public-mode" else 0o600)
    result = child_admission(lock_path)
    assert result.returncode == 1 and result.stdout == "INFERENCE_OUTCOME_UNKNOWN\n"
    result = child_admission(lock_path, uncertain=True, read_marker=True)
    assert result.returncode == 1 and result.stdout == "INFERENCE_LOCK_UNSAFE\n"
    assert result.stderr == ""
    assert target.read_bytes() == receipt.data
    assert os.path.lexists(marker)


@pytest.mark.parametrize("change", ["replacement", "content", "same-content", "mode", "hardlink"])
def test_changed_receipt_cannot_be_removed_using_old_identity(lock_path, change):
    marker = Path(str(lock_path) + ".unknown")
    with admission() as held:
        receipt = held.create_marker(GENERATOR_ID, peer())
        if change == "replacement":
            replacement = lock_path.parent / "replacement"
            replacement.write_bytes(receipt.data)
            replacement.chmod(0o600)
            os.replace(replacement, marker)
        elif change in {"content", "same-content"}:
            value = receipt.data.replace(b'"' + b"a" * 64 + b'"', b'"' + b"b" * 64 + b'"')
            marker.write_bytes(value if change == "content" else receipt.data)
        elif change == "mode":
            marker.chmod(0o644)
        else:
            os.link(marker, lock_path.parent / "extra-link")
        with pytest.raises(WorkbenchError, match="^INFERENCE_LOCK_UNSAFE$"):
            held.remove_marker(receipt)
        assert marker.exists()
    assert child_admission(lock_path).stdout == "INFERENCE_OUTCOME_UNKNOWN\n"


def test_replaced_lock_refuses_marker_mutation(lock_path):
    with admission() as held:
        lock_path.rename(lock_path.with_suffix(".old"))
        lock_path.write_bytes(b"")
        lock_path.chmod(0o600)
        with pytest.raises(WorkbenchError, match="^INFERENCE_LOCK_UNSAFE$"):
            held.create_marker(GENERATOR_ID, peer())
    assert not Path(str(lock_path) + ".unknown").exists()


def test_renamed_parent_never_redirects_receipt_removal(lock_path):
    parent = lock_path.parent
    moved = parent.with_name(parent.name + "-moved")
    with admission() as held:
        receipt = held.create_marker(GENERATOR_ID, peer())
        parent.rename(moved)
        try:
            parent.mkdir(mode=0o700)
            replacement = parent / (lock_path.name + ".unknown")
            replacement.write_bytes(b"synthetic replacement canary")
            with pytest.raises(WorkbenchError, match="^INFERENCE_LOCK_UNSAFE$"):
                held.remove_marker(receipt)
            assert replacement.read_bytes() == b"synthetic replacement canary"
            assert (moved / (lock_path.name + ".unknown")).read_bytes() == receipt.data
        finally:
            replacement.unlink()
            parent.rmdir()
            moved.rename(parent)


def test_failed_receipt_fsync_preserves_fail_closed_reservation(lock_path, monkeypatch):
    with admission() as held:

        def fail_fsync(fd):
            raise OSError("synthetic private error canary")

        monkeypatch.setattr(os, "fsync", fail_fsync)
        with pytest.raises(WorkbenchError, match="^INFERENCE_LOCK_UNSAFE$"):
            held.create_marker(GENERATOR_ID, peer())
    assert child_admission(lock_path).stdout == "INFERENCE_OUTCOME_UNKNOWN\n"


def test_process_exit_releases_lock_but_preserves_durable_unknown_receipt(lock_path):
    code = (
        "import os\n"
        "from osint_workbench.inference_state import admission\n"
        "with admission() as held:\n"
        f" held.create_marker({GENERATOR_ID!r},"
        " {'pid':os.getpid(),'start':'123456789'})\n"
        " os._exit(17)\n"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-c", code], capture_output=True, timeout=3, check=False
    )
    assert result.returncode == 17 and result.stdout == result.stderr == b""
    assert child_admission(lock_path).stdout == "INFERENCE_OUTCOME_UNKNOWN\n"
    with admission(allow_uncertain=True) as held:
        receipt = held.read_marker()
        assert receipt.value["generator_id"] == GENERATOR_ID
        assert _process_start(receipt.value["pid"]) != receipt.value["start"]
        held.remove_marker(receipt)
    assert child_admission(lock_path).returncode == 0


def test_actual_process_lock_contention_recovers_after_release(lock_path):
    with admission():
        result = child_admission(lock_path)
        assert result.returncode == 1 and result.stdout == "INFERENCE_BUSY\n"
        assert result.stderr == ""
    assert child_admission(lock_path).returncode == 0


@pytest.mark.integration
def test_native_completion_receipt_replacement_preserves_unknown_fence(tmp_path, monkeypatch):
    with fixture_server(tmp_path, monkeypatch) as (generator, state, _, root):
        state["mode"] = "hold"
        with ThreadPoolExecutor(max_workers=1) as executor:
            result = executor.submit(generator.generate, "Synthetic fixture", SCHEMA)
            try:
                assert state["entered"].wait(5)
                marker = root / "admission.lock.unknown"
                replacement = root / "replacement"
                replacement.write_bytes(marker.read_bytes())
                replacement.chmod(0o600)
                os.replace(replacement, marker)
            finally:
                state["release"].set()
            with pytest.raises(WorkbenchError, match="^INFERENCE_OUTCOME_UNKNOWN$"):
                result.result(timeout=5)
        assert marker.exists()
        with pytest.raises(WorkbenchError, match="^INFERENCE_OUTCOME_UNKNOWN$"):
            generator.generate("Synthetic fixture", SCHEMA)
        assert generator.reconcile()["status"] == "idle" and not marker.exists()


@pytest.mark.integration
def test_native_reconcile_does_not_clear_another_generator_receipt(tmp_path, monkeypatch):
    with fixture_server(tmp_path, monkeypatch) as (generator, state, _, root):
        with admission() as held:
            held.create_marker("f" * 64, peer())
        marker = root / "admission.lock.unknown"
        original = marker.read_bytes()
        with pytest.raises(WorkbenchError, match="^INFERENCE_OWNER_MISMATCH$"):
            generator.reconcile()
        assert marker.read_bytes() == original
        assert "/completion" not in [path for path, _ in state["calls"]]


def test_receipt_growth_after_file_inspection_is_rejected(lock_path, monkeypatch):
    with admission() as held:
        receipt = held.create_marker(GENERATOR_ID, peer())
        marker = Path(str(lock_path) + ".unknown")
        inode = marker.stat().st_ino
        original_fstat = os.fstat
        changed = []

        def grow_after_inspection(fd):
            info = original_fstat(fd)
            if info.st_ino == inode and not changed:
                marker.write_bytes(receipt.data + b" " * (4097 - len(receipt.data)))
                changed.append(info.st_size)
            return info

        monkeypatch.setattr(os, "fstat", grow_after_inspection)
        with pytest.raises(WorkbenchError, match="^INFERENCE_LOCK_UNSAFE$"):
            held.read_marker()
        assert changed == [len(receipt.data)] and marker.stat().st_size == 4097


@pytest.mark.parametrize("corruption", ["pid-path", "missing-start", "duplicate-owner"])
def test_malformed_receipt_identity_cannot_authorize_removal(lock_path, corruption):
    with admission() as held:
        receipt = held.create_marker(GENERATOR_ID, peer())
        marker = Path(str(lock_path) + ".unknown")
        if corruption == "pid-path":
            raw = receipt.data.replace(f'"pid":{os.getpid()}'.encode(), b'"pid":"../synthetic"')
        elif corruption == "missing-start":
            raw = receipt.data.replace(b'"start":"123456789"', b'"start":null')
        else:
            raw = receipt.data[:-1] + b',"generator_id":"' + b"f" * 64 + b'"}'
        marker.write_bytes(raw)
        with pytest.raises(WorkbenchError, match="^INFERENCE_LOCK_UNSAFE$"):
            held.read_marker()
        assert marker.read_bytes() == raw
    assert child_admission(lock_path).stdout == "INFERENCE_OUTCOME_UNKNOWN\n"


@pytest.fixture
def held_native_process():
    child = subprocess.Popen(
        [sys.executable, "-I", "-c", "import sys; sys.stdin.buffer.read(1)"],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        yield child
    finally:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=3)
        child.stdin.close()


def test_unreadable_live_native_process_keeps_uncertain_receipt(
    lock_path, held_native_process, monkeypatch
):
    from osint_workbench import local_generation

    child = held_native_process
    monkeypatch.setattr(local_generation, "_process_start", lambda pid: None)
    with admission() as held:
        held.create_marker(GENERATOR_ID, {"pid": child.pid, "start": "123456789"})
        with pytest.raises(WorkbenchError, match="^INFERENCE_PRIOR_PROCESS_UNKNOWN$"):
            local_generation._check_prior_process(child.pid, "123456789", -1)
        assert held.read_marker() is not None and child.poll() is None


def test_kernel_confirmed_terminated_process_can_release_receipt(
    lock_path, held_native_process, monkeypatch
):
    from osint_workbench import local_generation

    child = held_native_process
    child.terminate()
    child.wait(timeout=3)
    monkeypatch.setattr(local_generation, "_process_start", lambda pid: None)
    with admission() as held:
        receipt = held.create_marker(GENERATOR_ID, {"pid": child.pid, "start": "123456789"})
        local_generation._check_prior_process(child.pid, "123456789", -1)
        held.remove_marker(receipt)
        assert held.read_marker() is None


@pytest.mark.parametrize("observed", ["123456789", "987654321"])
def test_verified_native_start_identity_distinguishes_alive_and_pid_reuse(
    held_native_process, monkeypatch, observed
):
    from osint_workbench import local_generation

    # Substitute only the /proc identity observation; PID liveness is real.
    child = held_native_process
    monkeypatch.setattr(local_generation, "_process_start", lambda pid: observed)
    if observed == "123456789":
        with pytest.raises(WorkbenchError, match="^INFERENCE_PRIOR_PROCESS_ALIVE$"):
            local_generation._check_prior_process(child.pid, "123456789", -1)
    else:
        local_generation._check_prior_process(child.pid, "123456789", -1)
    assert child.poll() is None


def test_verified_idle_current_peer_does_not_require_foreign_process_probe(monkeypatch):
    from osint_workbench import local_generation

    def unexpected_probe(pid):
        pytest.fail("current native peer should not be treated as a foreign process")

    monkeypatch.setattr(local_generation, "_process_start", unexpected_probe)
    local_generation._check_prior_process(os.getpid(), "123456789", os.getpid())


def test_denied_process_liveness_probe_preserves_unknown(monkeypatch):
    from osint_workbench import local_generation

    monkeypatch.setattr(local_generation, "_process_start", lambda pid: None)

    def denied(pid, signal):
        raise PermissionError("synthetic private process canary")

    monkeypatch.setattr(local_generation.os, "kill", denied)
    with pytest.raises(WorkbenchError, match="^INFERENCE_PRIOR_PROCESS_UNKNOWN$"):
        local_generation._check_prior_process(1234, "123456789", -1)
