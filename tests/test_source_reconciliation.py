"""Current-source observations differ from generic immutable replay authority."""

import pytest

from osint_workbench.collection import collect
from osint_workbench.database import Database
from osint_workbench.errors import WorkbenchError
from osint_workbench.evidence import EvidenceStore
from tests.test_scheduled_collection import ResponseWire, due, install, source
from tests.test_workflows import FEED

pytestmark = pytest.mark.integration

CHANGED = FEED.replace(b"First evidence", b"Revised first evidence").replace(
    b"Second evidence", b"Revised second evidence"
)


def job_count(writer):
    with writer.connect() as conn:
        return conn.execute(
            "SELECT count(*) AS n FROM ow.jobs WHERE kind='document.accepted'"
        ).fetchone()["n"]


def partial_change(writer, store, monkeypatch):
    """Commit the first changed item, then fail durably before accepting the second."""
    due(writer)
    wire = ResponseWire(body=CHANGED, headers=[(b"etag", b'"changed"')])
    install(monkeypatch, wire)
    original = store.put
    with monkeypatch.context() as patch:

        def fail_second(data):
            if data == b"Revised second evidence":
                raise WorkbenchError("SYNTHETIC_STORE_FAILURE")
            return original(data)

        patch.setattr(store, "put", fail_second)
        with pytest.raises(WorkbenchError, match="SYNTHETIC_STORE_FAILURE"):
            collect(source(), writer, store, due_only=True)
    assert dict(wire.request.headers)[b"if-none-match"] == b'"original"'
    with writer.connect() as conn:
        assert (
            conn.execute(
                "SELECT accepted_documents FROM ow.collection_runs WHERE status='failed'"
            ).fetchone()["accepted_documents"]
            == 1
        )
        assert conn.execute("SELECT etag,failures FROM ow.collection_state").fetchone() == {
            "etag": '"original"',
            "failures": 1,
        }


def test_collection_restores_exact_prior_representation_without_duplicate_jobs(
    databases, tmp_path, monkeypatch
):
    writer, reader, _ = databases
    store = EvidenceStore(tmp_path / "objects")
    install(monkeypatch, ResponseWire(headers=[(b"etag", b'"original"')]))
    original = collect(source(), writer, store, due_only=True)
    due(writer)
    install(monkeypatch, ResponseWire(body=CHANGED, headers=[(b"etag", b'"changed"')]))
    changed = collect(source(), writer, store, due_only=True)
    assert set(original["document_ids"]).isdisjoint(changed["document_ids"])
    assert len(reader.search("Revised")) == 2 and job_count(writer) == 4
    due(writer)
    returned = ResponseWire(headers=[(b"etag", b'"returned"')])
    install(monkeypatch, returned)
    result = collect(source(), writer, store, due_only=True)
    assert dict(returned.request.headers)[b"if-none-match"] == b'"changed"'
    assert result["status"] == "success"
    assert result["document_ids"] == original["document_ids"]
    assert reader.search("Revised") == []
    assert reader.search("First")[0]["document_id"] == original["document_ids"][0]
    assert job_count(writer) == 4


def test_partial_acceptance_forces_full_fetch_and_reconciles_returned_representation(
    databases, tmp_path, monkeypatch
):
    writer, reader, _ = databases
    store = EvidenceStore(tmp_path / "objects")
    install(monkeypatch, ResponseWire(headers=[(b"etag", b'"original"')]))
    original = collect(source(), writer, store, due_only=True)
    partial_change(writer, store, monkeypatch)
    assert len(reader.search("Revised")) == 1 and job_count(writer) == 3
    due(writer)
    returned = ResponseWire(headers=[(b"etag", b'"original"')])
    install(monkeypatch, returned)
    result = collect(source(), writer, store, due_only=True)
    headers = dict(returned.request.headers)
    assert b"if-none-match" not in headers and b"if-modified-since" not in headers
    assert result["status"] == "success"
    assert result["document_ids"] == original["document_ids"]
    assert reader.search("Revised") == [] and job_count(writer) == 3
    with writer.connect() as conn:
        assert conn.execute("SELECT etag,failures FROM ow.collection_state").fetchone() == {
            "etag": '"original"',
            "failures": 0,
        }


def test_dirty_run_refuses_304_without_claiming_success(databases, tmp_path, monkeypatch):
    writer, reader, _ = databases
    store = EvidenceStore(tmp_path / "objects")
    install(monkeypatch, ResponseWire(headers=[(b"etag", b'"original"')]))
    collect(source(), writer, store, due_only=True)
    partial_change(writer, store, monkeypatch)
    due(writer)
    unsolicited = ResponseWire(304, b"", [(b"etag", b'"original"')])
    install(monkeypatch, unsolicited)
    with pytest.raises(WorkbenchError, match="UNSOLICITED_NOT_MODIFIED"):
        collect(source(), writer, store, due_only=True)
    headers = dict(unsolicited.request.headers)
    assert b"if-none-match" not in headers and b"if-modified-since" not in headers
    assert len(reader.search("Revised")) == 1 and job_count(writer) == 3
    with writer.connect() as conn:
        assert conn.execute("SELECT etag,failures FROM ow.collection_state").fetchone() == {
            "etag": '"original"',
            "failures": 2,
        }
        assert conn.execute(
            "SELECT status,error_code FROM ow.collection_runs ORDER BY started_at DESC LIMIT 1"
        ).fetchone() == {"status": "failed", "error_code": "UNSOLICITED_NOT_MODIFIED"}


@pytest.mark.parametrize("identity", ["writer", "collector"])
def test_feed_revision_reuses_unchanged_item_versions(databases, tmp_path, monkeypatch, identity):
    """A changed feed container must not re-version or re-enqueue unchanged items."""
    writer, reader, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    acquirer = writer
    if identity == "collector":
        # The production identity: column-scoped grants, exact history checks.
        acquirer = Database(roles["collector"])
        acquirer.validate_collector()
    install(monkeypatch, ResponseWire(headers=[(b"etag", b'"original"')]))
    original = collect(source(), acquirer, store, due_only=True)
    assert job_count(writer) == 2
    # Channel metadata changes, item 2 is revised and item 3 appears; item 1 is
    # byte-identical in content but arrives inside a different raw feed body.
    window = (
        FEED.replace(b"<title>Fixture</title>", b"<title>Fixture window</title>")
        .replace(b"Second evidence", b"Revised second evidence")
        .replace(
            b"</channel>",
            b"<item><guid>3</guid><title>Three</title>"
            b"<description>Third evidence</description></item></channel>",
        )
    )
    due(writer)
    install(monkeypatch, ResponseWire(body=window, headers=[(b"etag", b'"window"')]))
    revised = collect(source(), acquirer, store, due_only=True)
    assert revised["status"] == "success" and len(revised["document_ids"]) == 3
    assert revised["document_ids"][0] == original["document_ids"][0]
    assert revised["document_ids"][1] != original["document_ids"][1]
    assert job_count(writer) == 4
    with writer.connect() as conn:
        counts = conn.execute(
            "SELECT count(*) AS documents, count(DISTINCT snapshot_id) AS snapshots "
            "FROM ow.documents WHERE source_id='fixture'"
        ).fetchone()
        runs = conn.execute(
            "SELECT count(DISTINCT raw_sha256) AS n FROM ow.collection_runs "
            "WHERE source_id='fixture' AND status='succeeded'"
        ).fetchone()["n"]
    assert counts == {"documents": 4, "snapshots": 4}
    # Both container bodies remain retained run evidence for GC and recovery.
    assert runs == 2
    assert reader.search("First")[0]["document_id"] == original["document_ids"][0]
    assert len(reader.search("evidence")) == 3
    # Returning to older item content inside a new container is a change from
    # the current head: it is recorded as a new version, while unchanged item 1
    # keeps its first identity. Content equal to the head never re-versions.
    due(writer)
    back_feed = FEED.replace(b"<title>Fixture</title>", b"<title>Back</title>")
    install(monkeypatch, ResponseWire(body=back_feed, headers=[(b"etag", b'"back"')]))
    back = collect(source(), acquirer, store, due_only=True)
    assert back["document_ids"][0] == original["document_ids"][0]
    assert back["document_ids"][1] not in (original["document_ids"][1], revised["document_ids"][1])
    assert job_count(writer) == 5
    assert reader.search("Revised") == []
    # The exact first container repeats current content for both items, so the
    # current heads remain and nothing is enqueued.
    due(writer)
    install(monkeypatch, ResponseWire(headers=[(b"etag", b'"exact"')]))
    exact = collect(source(), acquirer, store, due_only=True)
    assert exact["document_ids"] == back["document_ids"]
    assert job_count(writer) == 5
