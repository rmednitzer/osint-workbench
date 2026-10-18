"""Reference HTTP bytes retain one unchanged item under real scoped SQL authority."""

from pathlib import Path

import pytest

from osint_workbench.collection import collect
from osint_workbench.contracts import Source
from osint_workbench.database import Database
from osint_workbench.evidence import EvidenceStore
from osint_workbench.text import digest
from tests.test_scheduled_collection import ResponseWire, due, install

pytestmark = pytest.mark.integration


def test_reference_service_feed_changes_one_version_not_both(databases, tmp_path, monkeypatch):
    # Importing this helper only obtains synthetic bytes; no namespace/service starts.
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    from reference_network import FEED_V1, FEED_V2, ReferenceNetwork

    writer, _, roles = databases
    collector = Database(roles["collector"])
    collector.validate_collector()
    source = Source(source_id="reference-enabled", url=ReferenceNetwork.url, poll_seconds=60)
    store = EvidenceStore(tmp_path / "objects")
    # Exercise actual HTTP framing and parser subprocesses; only the transport
    # backend is an in-memory h11 peer. Database and CAS operations are native.
    install(monkeypatch, ResponseWire(body=FEED_V1))
    first = collect(source, collector, store, due_only=True)
    due(writer)
    install(monkeypatch, ResponseWire(body=FEED_V2))
    changed = collect(source, collector, store, due_only=True)
    assert first["documents"] == changed["documents"] == 2
    assert changed["document_ids"][0] == first["document_ids"][0]
    assert changed["document_ids"][1] != first["document_ids"][1]
    assert len(set(changed["document_ids"]) - set(first["document_ids"])) == 1
    with writer.connect() as conn:
        assert conn.execute("SELECT count(*) AS n FROM ow.documents").fetchone()["n"] == 3
        assert conn.execute("SELECT count(*) AS n FROM ow.jobs").fetchone()["n"] == 3
        runs = conn.execute(
            "SELECT raw_sha256,accepted_documents FROM ow.collection_runs "
            "WHERE source_id=%s AND status='succeeded' ORDER BY started_at",
            (source.source_id,),
        ).fetchall()
        heads = conn.execute(
            "SELECT d.document_id,d.body FROM ow.document_heads h JOIN ow.documents d "
            "USING(document_id) WHERE h.source_id=%s ORDER BY d.title",
            (source.source_id,),
        ).fetchall()
    assert runs == [
        {"raw_sha256": digest(FEED_V1), "accepted_documents": 2},
        {"raw_sha256": digest(FEED_V2), "accepted_documents": 2},
    ]
    assert heads == [
        {"document_id": first["document_ids"][0], "body": "First evidence"},
        {"document_id": changed["document_ids"][1], "body": "Changed evidence"},
    ]
    assert store.get(digest(FEED_V1)) == FEED_V1
    assert store.get(digest(FEED_V2)) == FEED_V2
