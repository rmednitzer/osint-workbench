"""Bounded concurrency oracles plus real installed native encoder execution."""

import os
import select
import signal
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from osint_workbench.errors import WorkbenchError
from osint_workbench.query_flights import QueryFlights


def waiting(flights, count):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        with flights._lock:
            if flights._waiters == count:
                return
        time.sleep(0.001)
    raise AssertionError("participants did not reach bounded wait")


def test_identical_requests_share_one_owner_and_independent_results():
    flights = QueryFlights()
    entered, release = threading.Event(), threading.Event()
    calls = []

    def compute():
        calls.append(1)
        entered.set()
        assert release.wait(5)
        return [1.0, 0.0]

    with ThreadPoolExecutor(max_workers=4) as pool:
        owner = pool.submit(flights.run, b"same", compute)
        assert entered.wait(5)
        followers = [pool.submit(flights.run, b"same", compute) for _ in range(3)]
        try:
            waiting(flights, 3)
        finally:
            release.set()
        results = [f.result(5) for f in [owner, *followers]]
    assert calls == [1]
    results[0][0] = 42
    assert all(r == [1.0, 0.0] for r in results[1:])
    assert flights.run(b"same", lambda: [0.0, 1.0]) == [0.0, 1.0]


def test_waiter_timeout_does_not_release_or_cancel_owner():
    flights = QueryFlights(max_owners=1, wait_seconds=0.02)
    entered, release = threading.Event(), threading.Event()

    def compute():
        entered.set()
        assert release.wait(5)
        return [1.0]

    with ThreadPoolExecutor(max_workers=1) as pool:
        owner = pool.submit(flights.run, b"same", compute)
        assert entered.wait(5)
        try:
            with pytest.raises(WorkbenchError, match="ENCODER_WAIT_TIMEOUT"):
                flights.run(b"same", lambda: pytest.fail("second owner"))
            with pytest.raises(WorkbenchError, match="ENCODER_COALESCING_BUSY"):
                flights.run(b"different", lambda: [2.0])
        finally:
            release.set()
        assert owner.result(5) == [1.0]
    assert flights.run(b"different", lambda: [2.0]) == [2.0]


@pytest.mark.parametrize(
    "error", [WorkbenchError("ENCODER_TIMEOUT"), RuntimeError("private detail"), SystemExit(2)]
)
def test_owner_failure_wakes_waiters_and_allows_retry(error):
    flights = QueryFlights()
    entered, release = threading.Event(), threading.Event()

    def fail():
        entered.set()
        assert release.wait(5)
        raise error

    with ThreadPoolExecutor(max_workers=2) as pool:
        owner = pool.submit(flights.run, b"same", fail)
        assert entered.wait(5)
        follower = pool.submit(flights.run, b"same", lambda: pytest.fail("second owner"))
        try:
            waiting(flights, 1)
        finally:
            release.set()
        with pytest.raises(type(error)):
            owner.result(5)
        expected = "ENCODER_TIMEOUT" if isinstance(error, WorkbenchError) else "ENCODER_UNAVAILABLE"
        with pytest.raises(WorkbenchError, match=expected) as result:
            follower.result(5)
        assert "private detail" not in str(result.value)
    assert flights.run(b"same", lambda: [1.0]) == [1.0]


def test_global_waiter_bound_does_not_dispatch_another_computation():
    flights = QueryFlights(max_waiters=1)
    entered, release = threading.Event(), threading.Event()

    def compute():
        entered.set()
        assert release.wait(5)
        return [1.0]

    with ThreadPoolExecutor(max_workers=2) as pool:
        owner = pool.submit(flights.run, b"same", compute)
        assert entered.wait(5)
        follower = pool.submit(flights.run, b"same", compute)
        try:
            waiting(flights, 1)
            with pytest.raises(WorkbenchError, match="ENCODER_COALESCING_BUSY"):
                flights.run(b"same", lambda: pytest.fail("excess dispatch"))
        finally:
            release.set()
        assert owner.result(5) == follower.result(5) == [1.0]


def test_distinct_keys_and_instances_do_not_share_results():
    first, second = QueryFlights(), QueryFlights()
    entered, release = threading.Event(), threading.Event()

    def compute():
        entered.set()
        assert release.wait(5)
        return [1]

    with ThreadPoolExecutor(max_workers=1) as pool:
        owner = pool.submit(first.run, b"a", compute)
        assert entered.wait(5)
        try:
            assert first.run(b"b", lambda: [2]) == [2]
            assert second.run(b"a", lambda: [3]) == [3]
        finally:
            release.set()
        assert owner.result(5) == [1]


def test_forked_instance_refuses_before_inherited_mutex():
    flights = QueryFlights()
    read_fd, write_fd = os.pipe()
    with flights._lock:
        child = os.fork()
        if child == 0:
            os.close(read_fd)
            try:
                flights.run(b"a", lambda: [1])
            except WorkbenchError as exc:
                os.write(write_fd, exc.code.encode())
            finally:
                os._exit(0)
    os.close(write_fd)
    try:
        assert select.select([read_fd], [], [], 5)[0], "fork child did not refuse promptly"
        assert os.read(read_fd, 100) == b"ENCODER_INSTANCE_FORKED"
    finally:
        os.close(read_fd)
        # This PID belongs only to this test. Also bound cleanup on a regression.
        waited, status = os.waitpid(child, os.WNOHANG)
        deadline = time.monotonic() + 1
        while not waited and time.monotonic() < deadline:
            time.sleep(0.001)
            waited, status = os.waitpid(child, os.WNOHANG)
        if not waited:
            os.kill(child, signal.SIGKILL)
            _, status = os.waitpid(child, 0)
    assert status == 0


@pytest.mark.parametrize(
    "options",
    [
        {"max_owners": 0},
        {"max_waiters": True},
        {"wait_seconds": float("nan")},
        {"wait_seconds": 61},
    ],
)
def test_invalid_limits(options):
    with pytest.raises(ValueError, match="INVALID_QUERY_FLIGHT_LIMITS"):
        QueryFlights(**options)


def test_actual_native_encoder_coalesces_and_rechecks_completed_model(encoder_bundle, monkeypatch):
    import osint_workbench.local_encoder as module

    # Instrument and coordinate the actual spawn; never substitute child output.
    original = module.subprocess.run
    entered, release = threading.Event(), threading.Event()
    calls = []

    def observed(*args, **kwargs):
        calls.append(args[0])
        entered.set()
        assert release.wait(5)
        return original(*args, **kwargs)

    monkeypatch.setattr(module.subprocess, "run", observed)
    with ThreadPoolExecutor(max_workers=4) as pool:
        owner = pool.submit(encoder_bundle.query, "storage")
        assert entered.wait(5)
        followers = [pool.submit(encoder_bundle.query, "storage") for _ in range(3)]
        try:
            waiting(encoder_bundle._queries, 3)
        finally:
            release.set()
        results = [f.result(50) for f in [owner, *followers]]
    assert len(calls) == 1
    assert results == [[1.0, 0.0, 0.0]] * 4
    results[0][0] = 2
    assert results[1] == [1.0, 0.0, 0.0]
    Path(encoder_bundle.manifest.model_path).write_bytes(b"tampered")
    with pytest.raises(WorkbenchError, match="MODEL_INTEGRITY_MISMATCH"):
        encoder_bundle.query("storage")
    assert len(calls) == 2


def test_native_active_flight_keeps_verified_snapshot_after_file_replacement(
    encoder_bundle, monkeypatch
):
    import osint_workbench.local_encoder as module

    original = module.subprocess.run
    computed, release = threading.Event(), threading.Event()

    def observed(*args, **kwargs):
        result = original(*args, **kwargs)
        # Actual child execution and integrity verification have finished.
        computed.set()
        assert release.wait(5)
        return result

    monkeypatch.setattr(module.subprocess, "run", observed)
    with ThreadPoolExecutor(max_workers=2) as pool:
        owner = pool.submit(encoder_bundle.query, "storage")
        assert computed.wait(45)
        Path(encoder_bundle.manifest.model_path).write_bytes(b"tampered")
        follower = pool.submit(encoder_bundle.query, "storage")
        try:
            waiting(encoder_bundle._queries, 1)
        finally:
            release.set()
        assert owner.result(5) == follower.result(5) == [1.0, 0.0, 0.0]
    with pytest.raises(WorkbenchError, match="MODEL_INTEGRITY_MISMATCH"):
        encoder_bundle.query("storage")


def test_native_changed_manifest_does_not_join_existing_query(encoder_bundle, monkeypatch):
    import osint_workbench.local_encoder as module

    original = module.subprocess.run
    entered, release = threading.Event(), threading.Event()

    def observed(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return original(*args, **kwargs)

    monkeypatch.setattr(module.subprocess, "run", observed)
    with ThreadPoolExecutor(max_workers=1) as pool:
        owner = pool.submit(encoder_bundle.query, "storage")
        assert entered.wait(5)
        try:
            encoder_bundle.manifest.max_tokens = 32
            # Different packet: attempts its own ordinary inference admission,
            # which remains owned by the first actual subprocess invocation.
            with pytest.raises(WorkbenchError, match="INFERENCE_BUSY"):
                encoder_bundle.query("storage")
        finally:
            encoder_bundle.manifest.max_tokens = 16
            release.set()
        assert owner.result(50) == [1.0, 0.0, 0.0]
