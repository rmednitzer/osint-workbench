"""Native TLS -> actual HTTP/feed parser -> scoped PostgreSQL collector.

The disposable fixture routes TCP and adds its authored CA to a test-only trust
context. Production TLS verification/hostname checks and collection code execute.
No public endpoint, private CA, operational source or TLS bypass is used.
"""

from datetime import timedelta

import pytest
from psycopg import sql

from osint_workbench.collection import collect, collect_due
from osint_workbench.contracts import Source
from osint_workbench.database import Database
from osint_workbench.errors import WorkbenchError
from osint_workbench.evidence import EvidenceStore
from osint_workbench.text import digest
from tests.test_workflows import FEED
from tests.tls_fixture import generate_certificates, tls_peer

pytestmark = pytest.mark.integration
ORIGIN = "https://feed.fixture.invalid/feed"


def response(etag):
    return (
        b"HTTP/1.1 200 OK\r\nContent-Length: "
        + str(len(FEED)).encode()
        + b"\r\nConnection: close\r\nETag: "
        + etag.encode()
        + b"\r\n\r\n"
        + FEED
    )


def headers(peer):
    assert len(peer.requests) == 1
    head, separator, _ = peer.requests[0].partition(b"\r\n\r\n")
    assert separator and len(head) <= 8192
    lines = head.decode("ascii").split("\r\n")
    assert lines[0] == "GET /feed HTTP/1.1"
    return {
        name.casefold(): value.strip() for name, value in (line.split(":", 1) for line in lines[1:])
    }


@pytest.fixture
def tls_native(databases, tmp_path):
    _, _, roles = databases
    collector = Database(roles["collector"])
    collector.validate_collector()
    return (
        collector,
        Database(roles["admin"]),
        EvidenceStore(tmp_path / "objects"),
        generate_certificates(tmp_path / "certificates"),
        roles,
    )


def source():
    return Source(source_id="tls-fixture", url=ORIGIN, poll_seconds=60)


def records(admin):
    with admin.connect() as conn:
        return {
            name: conn.execute(
                sql.SQL("SELECT * FROM ow.{} ORDER BY 1").format(sql.Identifier(name))
            ).fetchall()
            for name in ("documents", "document_heads", "snapshots", "jobs")
        }


def status(admin):
    with admin.connect() as conn:
        state = conn.execute(
            "SELECT *,clock_timestamp() AS observed_at,"
            "next_attempt>clock_timestamp() AS future FROM ow.collection_state"
        ).fetchone()
        source_state = conn.execute("SELECT * FROM ow.sources").fetchone()
        runs = conn.execute("SELECT * FROM ow.collection_runs ORDER BY started_at").fetchall()
    return state, source_state, runs


def due(admin):
    with admin.connect() as conn:
        conn.execute("UPDATE ow.collection_state SET next_attempt=clock_timestamp()-interval '1 s'")


def objects(store):
    return {
        str(path.relative_to(store.root)): path.read_bytes()
        for path in store.root.rglob("*")
        if path.is_file()
    }


def accepted_evidence(admin, store):
    retained = records(admin)
    assert len(retained["documents"]) == len(retained["jobs"]) == 2
    assert len(retained["document_heads"]) == 2
    document_map = {row["document_id"]: row for row in retained["documents"]}
    snapshots = {row["snapshot_id"]: row for row in retained["snapshots"]}
    for document in document_map.values():
        snapshot = snapshots[document["snapshot_id"]]
        assert snapshot["raw_sha256"] == digest(FEED)
        assert store.get(snapshot["raw_sha256"]) == FEED
        assert store.get(snapshot["text_sha256"]) == document["body"].encode()
    for job in retained["jobs"]:
        assert job["kind"] == "document.accepted" and job["status"] == "ready"
        assert job["payload"]["document_id"] == job["dedup_key"]
        assert job["payload"]["snapshot_id"] == document_map[job["dedup_key"]]["snapshot_id"]
    return retained


def test_valid_tls_origin_accepts_actual_feed_and_scoped_outbox(tls_native, monkeypatch):
    collector, admin, store, certificates, _ = tls_native
    with tls_peer(monkeypatch, certificates, wire=response('"tls-retained"')) as peer:
        result = collect(source(), collector, store, due_only=True)
    assert result["status"] == "success" and result["documents"] == 2
    assert peer.sni == ["feed.fixture.invalid"]
    assert peer.handshake_failures == 0
    assert len(peer.requests) == 1
    assert headers(peer)["host"] == "feed.fixture.invalid"
    accepted_evidence(admin, store)
    state, source_state, runs = status(admin)
    assert state["etag"] == '"tls-retained"' and state["failures"] == 0
    assert source_state["last_success"] is not None and source_state["last_error"] is None
    assert len(runs) == 1 and runs[0]["http_status"] == 200


@pytest.mark.parametrize(
    "kind,trust_fixture", [("wrong", True), ("expired", True), ("valid", False)]
)
def test_tls_authentication_failure_cannot_accept_http_or_evidence(
    tls_native, monkeypatch, kind, trust_fixture
):
    collector, admin, store, certificates, _ = tls_native
    with tls_peer(
        monkeypatch,
        certificates,
        kind=kind,
        trust_fixture=trust_fixture,
        wire=response('"must-not-be-observed"'),
    ) as peer:
        with pytest.raises(WorkbenchError, match="^SOURCE_UNAVAILABLE$"):
            collect(source(), collector, store, due_only=True)
    assert peer.sni == ["feed.fixture.invalid"]
    assert peer.handshake_failures == 1
    assert peer.requests == []
    state, source_state, runs = status(admin)
    assert state["failures"] == 1 and state["future"]
    assert state["next_attempt"] <= state["observed_at"] + timedelta(seconds=60)
    assert state["etag"] is None and state["raw_sha256"] is None
    assert source_state["last_success"] is None
    assert source_state["last_error"] == "SOURCE_UNAVAILABLE"
    assert len(runs) == 1 and runs[0]["status"] == "failed"
    assert runs[0]["error_code"] == "SOURCE_UNAVAILABLE"
    assert runs[0]["raw_sha256"] is None and runs[0]["accepted_documents"] == 0
    assert all(not rows for rows in records(admin).values()) and objects(store) == {}


def test_tls_failure_preserves_retained_state_and_full_retry_is_unconditional(
    tls_native, monkeypatch
):
    collector, admin, store, certificates, roles = tls_native
    with tls_peer(monkeypatch, certificates, wire=response('"tls-retained"')):
        assert collect(source(), collector, store, due_only=True)["documents"] == 2
    before_state, before_source, _ = status(admin)
    retained_records = accepted_evidence(admin, store)
    retained_objects = objects(store)
    due(admin)
    with tls_peer(
        monkeypatch, certificates, kind="wrong", wire=response('"unverified"')
    ) as rejected:
        with pytest.raises(WorkbenchError, match="^SOURCE_UNAVAILABLE$"):
            collect(source(), collector, store, due_only=True)
        restarted = Database(roles["collector"])
        assert collect_due([source()], restarted, store) == {
            "status": "complete",
            "results": [],
            "deferred_sources": 0,
        }
    assert rejected.requests == [] and rejected.handshake_failures == 1
    failed_state, failed_source, runs = status(admin)
    assert failed_state["failures"] == 1 and failed_state["future"]
    assert all(
        failed_state[key] == before_state[key] for key in ("etag", "last_modified", "raw_sha256")
    )
    assert failed_source["last_success"] == before_source["last_success"]
    assert failed_source["last_error"] == "SOURCE_UNAVAILABLE"
    assert len(runs) == 2 and runs[-1]["error_code"] == "SOURCE_UNAVAILABLE"
    assert records(admin) == retained_records and objects(store) == retained_objects
    due(admin)
    with tls_peer(monkeypatch, certificates, wire=response('"tls-corrected"')) as corrected:
        assert collect(source(), restarted, store, due_only=True)["documents"] == 2
    assert corrected.sni == ["feed.fixture.invalid"] and corrected.handshake_failures == 0
    assert len(corrected.requests) == 1
    assert headers(corrected)["host"] == "feed.fixture.invalid"
    assert headers(corrected).get("if-none-match") is None
    assert headers(corrected).get("if-modified-since") is None
    restored_state, restored_source, runs = status(admin)
    assert restored_state["failures"] == 0 and restored_state["etag"] == '"tls-corrected"'
    assert restored_source["last_error"] is None
    assert restored_source["last_success"] > before_source["last_success"]
    assert len(runs) == 3 and runs[-1]["status"] == "succeeded"
    assert records(admin) == retained_records and objects(store) == retained_objects
