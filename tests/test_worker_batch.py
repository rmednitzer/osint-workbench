import pytest

from osint_workbench import worker
from osint_workbench.errors import WorkbenchError


def test_batch_preserves_failed_tick_and_committed_independent_work(monkeypatch):
    results = iter(
        [
            {"status": "failed", "job_id": "private", "error": "private"},
            {"status": "succeeded", "job_id": "private", "chunks": 1},
            {"status": "superseded", "job_id": "private"},
            {"status": "idle"},
        ]
    )
    monkeypatch.setattr(worker, "run_once", lambda *_: next(results))
    assert worker.run_batch(None, None, max_jobs=8) == {
        "kind": "chunk_worker_tick",
        "attempted": 3,
        "succeeded": 1,
        "failed": 1,
        "superseded": 1,
        "idle_observed": True,
        "limit_reached": False,
    }


def test_batch_stops_at_cap_without_claiming_queue_empty(monkeypatch):
    calls = []

    def process(*_):
        calls.append(True)
        return {"status": "succeeded"}

    monkeypatch.setattr(worker, "run_once", process)
    result = worker.run_batch(None, None, max_jobs=2)
    assert len(calls) == result["attempted"] == 2
    assert result["limit_reached"] and not result["idle_observed"]


@pytest.mark.parametrize("limit", [True, 0, -1, 1001, 1.5, "3"])
def test_invalid_batch_limit_never_claims(monkeypatch, limit):
    def forbidden(*_):
        pytest.fail("invalid limit must not claim a job")

    monkeypatch.setattr(worker, "run_once", forbidden)
    with pytest.raises(WorkbenchError, match="INVALID_WORK_LIMIT"):
        worker.run_batch(None, None, max_jobs=limit)


def test_batch_backend_fault_does_not_continue_claiming(monkeypatch):
    calls = []

    def process(*_):
        calls.append(True)
        raise WorkbenchError("WORKER_BACKEND_FAILURE")

    monkeypatch.setattr(worker, "run_once", process)
    with pytest.raises(WorkbenchError, match="WORKER_BACKEND_FAILURE"):
        worker.run_batch(None, None, max_jobs=3)
    assert len(calls) == 1


@pytest.mark.integration
def test_exhausted_reap_bound_returns_idle_before_next_tick_claims_remaining_work(
    databases, tmp_path
):
    from osint_workbench.contracts import DocumentInput
    from osint_workbench.evidence import EvidenceStore

    writer, _, _ = databases
    store = EvidenceStore(tmp_path / "synthetic-worker-evidence")
    document = writer.ingest(
        DocumentInput(
            source_id="synthetic-bounded-poll",
            external_id="remaining-eligible-item",
            title="Synthetic eligible document",
            text="Synthetic evidence for the next bounded claim poll.",
        ),
        b"synthetic bounded-poll raw evidence",
        store,
    )
    with writer.connect() as conn:
        conn.execute("""INSERT INTO ow.jobs
            (job_id,kind,dedup_key,payload,status,attempt,max_attempts,available_at)
            SELECT gen_random_uuid(),'document.accepted','synthetic-exhausted-'||n,
              '{}'::jsonb,'ready',5,5,clock_timestamp()-interval '1 day'
            FROM generate_series(1,64) n""")
    before = sorted(str(path.relative_to(store.root)) for path in store.root.rglob("*"))
    reader_store = EvidenceStore(store.root, read_only=True)
    first = worker.run_batch(writer, reader_store, max_jobs=1)
    assert first == {
        "kind": "chunk_worker_tick",
        "attempted": 0,
        "succeeded": 0,
        "failed": 0,
        "superseded": 0,
        "idle_observed": True,
        "limit_reached": False,
    }
    with writer.connect() as conn:
        rows = conn.execute(
            "SELECT status,last_error FROM ow.jobs WHERE kind='document.accepted'"
        ).fetchall()
        assert sum(row["status"] == "ready" for row in rows) == 1
        assert (
            sum(
                row["status"] == "failed" and row["last_error"] == "ATTEMPTS_EXHAUSTED"
                for row in rows
            )
            == 64
        )
        assert conn.execute("SELECT count(*) AS n FROM ow.chunks").fetchone()["n"] == 0
        assert conn.execute(
            "SELECT event,count(*) AS n FROM ow.job_events GROUP BY event"
        ).fetchall() == [{"event": "failed", "n": 64}]

    second = worker.run_batch(writer, reader_store, max_jobs=1)
    assert second["attempted"] == second["succeeded"] == 1
    assert second["failed"] == second["superseded"] == 0
    assert second["limit_reached"] and not second["idle_observed"]
    with writer.connect() as conn:
        assert conn.execute(
            "SELECT kind,status,count(*) AS n FROM ow.jobs GROUP BY kind,status "
            "ORDER BY kind,status"
        ).fetchall() == [
            {"kind": "document.accepted", "status": "failed", "n": 64},
            {"kind": "document.accepted", "status": "succeeded", "n": 1},
            {"kind": "document.chunked", "status": "ready", "n": 1},
        ]
        assert conn.execute("SELECT document_id FROM ow.chunks").fetchall() == [
            {"document_id": document}
        ]
        assert conn.execute(
            "SELECT event,count(*) AS n FROM ow.job_events GROUP BY event ORDER BY event"
        ).fetchall() == [
            {"event": "claimed", "n": 1},
            {"event": "failed", "n": 64},
            {"event": "succeeded", "n": 1},
        ]
    assert sorted(str(path.relative_to(store.root)) for path in store.root.rglob("*")) == before
