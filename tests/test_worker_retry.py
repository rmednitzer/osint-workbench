"""Native fenced job retry after temporary lifecycle/store admission failure."""

import pytest

from osint_workbench.database import Database
from osint_workbench.errors import WorkbenchError
from osint_workbench.evidence import EvidenceStore
from osint_workbench.worker import run_once
from tests.test_recovery import _input

pytestmark = pytest.mark.integration


def test_worker_real_lifecycle_lock_contention_retries_then_completes(
    databases, tmp_path, monkeypatch
):
    writer, _, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    document = writer.ingest(_input(), b"synthetic raw", store)
    original = writer.document

    def contended(identifier):
        # The claim has committed before this actual exclusive barrier. The
        # worker's new shared admission must hit its configured lock timeout.
        with Database(roles["admin"]).connect(lifecycle_exclusive=True):
            return original(identifier)

    with monkeypatch.context() as patch:
        patch.setattr(writer, "document", contended)
        result = run_once(writer, store)
    assert result["error"] == "LIFECYCLE_BUSY"
    with writer.connect() as conn:
        job = conn.execute("SELECT * FROM ow.jobs WHERE kind='document.accepted'").fetchone()
        assert job["status"] == "ready" and job["attempt"] == 1
        assert job["fence"] is None and job["lease_until"] is None
        assert conn.execute(
            "SELECT event,code FROM ow.job_events ORDER BY event_id DESC LIMIT 1"
        ).fetchone() == {"event": "retry", "code": "LIFECYCLE_BUSY"}
        assert not conn.execute("SELECT 1 FROM ow.chunks").fetchone()
        conn.execute("UPDATE ow.jobs SET available_at=clock_timestamp()-interval '1 s'")
    assert run_once(writer, store)["status"] == "succeeded"
    with writer.connect() as conn:
        assert (
            conn.execute(
                "SELECT count(*) AS n FROM ow.chunks WHERE document_id=%s", (document,)
            ).fetchone()["n"]
            > 0
        )
        assert (
            conn.execute("SELECT attempt FROM ow.jobs WHERE kind='document.accepted'").fetchone()[
                "attempt"
            ]
            == 2
        )


@pytest.mark.parametrize("attempts,expected", [(2, "ready"), (1, "failed")])
def test_worker_store_busy_uses_existing_retry_budget(
    databases, tmp_path, monkeypatch, attempts, expected
):
    writer, _, _ = databases
    store = EvidenceStore(tmp_path / "objects")
    writer.ingest(_input(), b"synthetic raw", store)
    with writer.connect() as conn:
        conn.execute("UPDATE ow.jobs SET max_attempts=%s", (attempts,))

    def busy(identifier):
        raise WorkbenchError("EVIDENCE_STORE_BUSY")

    monkeypatch.setattr(writer, "document", busy)
    result = run_once(writer, store)
    assert result["error"] == "EVIDENCE_STORE_BUSY"
    with writer.connect() as conn:
        assert conn.execute("SELECT status,last_error FROM ow.jobs").fetchone() == {
            "status": expected,
            "last_error": "EVIDENCE_STORE_BUSY",
        }
        assert not conn.execute("SELECT 1 FROM ow.chunks").fetchone()
