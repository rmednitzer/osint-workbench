import json

import h11
import httpcore
import psycopg
import pytest
from pydantic import ValidationError

from osint_workbench import fetch as acquisition
from osint_workbench import recovery
from osint_workbench.collection import collect, collect_due
from osint_workbench.contracts import Source
from osint_workbench.database import Database
from osint_workbench.errors import WorkbenchError
from osint_workbench.evidence import EvidenceStore
from osint_workbench.text import digest
from tests.test_recovery import destination as destination
from tests.test_recovery import policy_arguments
from tests.test_workflows import FEED

MODIFIED = "Wed, 14 Oct 2026 12:00:00 GMT"


class ResponseWire:
    """Independent actual h11 server on a disposable in-memory transport."""

    def __init__(self, status=200, body=FEED, headers=()):
        self.server = h11.Connection(h11.SERVER)
        self.status, self.body, self.headers = status, body, headers
        self.request, self.response = None, b""

    def write(self, buffer, timeout=None):
        self.server.receive_data(buffer)
        while True:
            event = self.server.next_event()
            if event is h11.NEED_DATA or isinstance(event, h11.ConnectionClosed):
                break
            if isinstance(event, h11.Request):
                self.request = event
            if isinstance(event, h11.EndOfMessage):
                self.response = self.server.send(
                    h11.Response(
                        status_code=self.status,
                        headers=[(b"content-length", str(len(self.body)).encode()), *self.headers],
                    )
                )
                if self.status != 304:
                    self.response += self.server.send(h11.Data(data=self.body))
                self.response += self.server.send(h11.EndOfMessage())
                break

    def read(self, max_bytes, timeout=None):
        result, self.response = self.response[:max_bytes], self.response[max_bytes:]
        return result

    def close(self):
        pass

    def get_extra_info(self, info):
        return None


class ScriptedBackend(httpcore.SyncBackend):
    def __init__(self, wires):
        self.wires = iter(wires)

    def connect_tcp(self, *args, **kwargs):
        return next(self.wires)


def install(monkeypatch, *wires):
    backend = ScriptedBackend(wires)
    monkeypatch.setattr(acquisition, "_PublicBackend", lambda _: backend)


def source(**kwargs):
    return Source(source_id="fixture", url="http://example.invalid/feed", poll_seconds=60, **kwargs)


def due(writer):
    with writer.connect() as conn:
        conn.execute("UPDATE ow.collection_state SET next_attempt=clock_timestamp()-interval '1 s'")


def test_validator_request_bounds_and_actual_304(monkeypatch):
    for etag in ("injected\r\nheader", "*", '"a" "b"', '"' + "a" * 513 + '"'):
        with pytest.raises(WorkbenchError, match="INVALID_HTTP_VALIDATOR"):
            acquisition.fetch_response(source().url, etag=etag)
    with pytest.raises(WorkbenchError, match="INVALID_HTTP_VALIDATOR"):
        acquisition.fetch_response(source().url, last_modified="tomorrow")
    wire = ResponseWire(304, b"", [(b"etag", b'W/"v1"')])
    install(monkeypatch, wire)
    result = acquisition.fetch_response(source().url, etag='"v1"', last_modified=MODIFIED)
    assert result.status == 304 and result.body == b""
    assert dict(wire.request.headers)[b"if-none-match"] == b'"v1"'
    assert b"if-modified-since" not in dict(wire.request.headers)
    wire = ResponseWire(304, b"")
    install(monkeypatch, wire)
    with pytest.raises(WorkbenchError, match="UNSOLICITED_NOT_MODIFIED"):
        acquisition.fetch_response(source().url)


@pytest.mark.parametrize(
    "headers",
    [
        [(b"etag", b'"v2"')],
        [(b"etag", b'"v1"'), (b"etag", b'"v1"')],
    ],
)
def test_mismatched_or_duplicate_validator_refusal(monkeypatch, headers):
    install(monkeypatch, ResponseWire(304, b"", headers))
    with pytest.raises(WorkbenchError, match="VALIDATOR"):
        acquisition.fetch_response(source().url, etag='"v1"')


def test_redirect_does_not_forward_or_store_validators(monkeypatch):
    redirect = ResponseWire(302, b"", [(b"location", b"http://other.invalid/feed")])
    final = ResponseWire(200, headers=[(b"etag", b'"other-resource"')])
    install(monkeypatch, redirect, final)
    result = acquisition.fetch_response(source().url, etag='"configured-resource"')
    assert b"if-none-match" in dict(redirect.request.headers)
    assert b"if-none-match" not in dict(final.request.headers)
    assert result.etag is None and result.last_modified is None and result.body == FEED


def test_schedule_config_and_tick_bounds():
    for value in (0, True, 59, 86401):
        with pytest.raises(ValidationError):
            Source(source_id="fixture", url="http://example.invalid/feed", poll_seconds=value)
    with pytest.raises(WorkbenchError, match="INVALID_COLLECTION_LIMIT"):
        collect_due([], None, None, limit=0)


@pytest.mark.integration
def test_durable_due_conditional_revalidation_and_private_sql(databases, tmp_path, monkeypatch):
    writer, reader, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    first = ResponseWire(headers=[(b"etag", b'"v1"'), (b"last-modified", MODIFIED.encode())])
    install(monkeypatch, first)
    assert collect(source(), writer, store, due_only=True)["documents"] == 2
    assert collect(source(), writer, store, due_only=True)["status"] == "not_due"
    # A new Database instance represents a restarted collector, not an in-process cache.
    restarted = Database(roles["writer"])
    due(restarted)
    unchanged = ResponseWire(304, b"", [(b"etag", b'"v1"')])
    install(monkeypatch, unchanged)
    result = collect(source(), restarted, store, due_only=True)
    assert result["status"] == "not_modified" and result["documents"] == 0
    assert dict(unchanged.request.headers)[b"if-none-match"] == b'"v1"'
    assert reader.status()["documents"] == 2
    with writer.connect() as conn:
        state = conn.execute("SELECT * FROM ow.collection_state").fetchone()
        assert state["failures"] == 0 and state["etag"] == '"v1"'
        assert conn.execute(
            "SELECT http_status,raw_sha256 FROM ow.collection_runs ORDER BY started_at DESC LIMIT 1"
        ).fetchone() == {"http_status": 304, "raw_sha256": digest(FEED)}
    with reader.connect() as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("SELECT etag FROM ow.collection_state")
    assert state["resource_sha256"] != digest(source().url.encode())  # Profile-bound too.


@pytest.mark.integration
def test_partial_failure_does_not_advance_validator(databases, tmp_path, monkeypatch):
    writer, _, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    install(monkeypatch, ResponseWire(headers=[(b"etag", b'"old"')]))
    collect(source(), writer, store, due_only=True)
    due(writer)
    changed = FEED.replace(b"Second evidence", b"Changed evidence")
    install(monkeypatch, ResponseWire(body=changed, headers=[(b"etag", b'"new"')]))
    put = store.put
    with monkeypatch.context() as patch:

        def fail(data):
            if data == b"Changed evidence":
                raise WorkbenchError("SYNTHETIC_STORE_FAILURE")
            return put(data)

        patch.setattr(store, "put", fail)
        with pytest.raises(WorkbenchError, match="SYNTHETIC_STORE_FAILURE"):
            collect(source(), writer, store, due_only=True)
    with writer.connect() as conn:
        state = conn.execute("SELECT * FROM ow.collection_state").fetchone()
        assert state["etag"] == '"old"' and state["failures"] == 1
        assert (
            conn.execute(
                "SELECT accepted_documents FROM ow.collection_runs WHERE status='failed'"
            ).fetchone()["accepted_documents"]
            == 1
        )
    due(writer)
    replay = ResponseWire(body=changed, headers=[(b"etag", b'"new"')])
    install(monkeypatch, replay)
    assert collect(source(), writer, store, due_only=True)["documents"] == 2
    assert b"if-none-match" not in dict(replay.request.headers)


@pytest.mark.integration
def test_changed_resource_and_lost_cache_force_full_fetch(databases, tmp_path, monkeypatch):
    writer, _, _ = databases
    store = EvidenceStore(tmp_path / "objects")
    install(monkeypatch, ResponseWire(headers=[(b"etag", b'"v1"')]))
    collect(source(), writer, store, due_only=True)
    moved = source().model_copy(update={"url": "http://example.invalid/new-feed"})
    wire = ResponseWire(headers=[(b"etag", b'"v2"')])
    install(monkeypatch, wire)
    assert collect(moved, writer, store, due_only=True)["status"] == "success"
    assert b"if-none-match" not in dict(wire.request.headers)
    (store.root / digest(FEED)[:2] / digest(FEED)).unlink()
    due(writer)
    wire = ResponseWire(headers=[(b"etag", b'"v2"')])
    install(monkeypatch, wire)
    assert collect(moved, writer, store, due_only=True)["status"] == "success"
    assert b"if-none-match" not in dict(wire.request.headers)


@pytest.mark.integration
def test_tick_isolates_failure_and_caps_dispatch_fairly(databases, tmp_path, monkeypatch):
    writer, _, _ = databases
    store = EvidenceStore(tmp_path / "objects")
    sources = [
        Source(source_id=str(i), url="http://example.invalid/feed", poll_seconds=60)
        for i in range(3)
    ]
    install(monkeypatch, ResponseWire(503, b""), ResponseWire())
    result = collect_due(sources, writer, store, limit=2)
    assert [r["status"] for r in result["results"]] == ["failed", "success"]
    assert result["deferred_sources"] == 1
    install(monkeypatch, ResponseWire())
    result = collect_due(sources, writer, store, limit=2)
    assert [r["source_id"] for r in result["results"]] == ["2"]
    with writer.connect() as conn:
        row = conn.execute(
            "SELECT next_attempt-clock_timestamp() AS wait,failures FROM "
            "ow.collection_state WHERE source_id='0'"
        ).fetchone()
        assert row["failures"] == 1 and 30 < row["wait"].total_seconds() <= 60
    due(writer)
    install(monkeypatch, ResponseWire(503, b""))
    with pytest.raises(WorkbenchError):
        collect(sources[0], writer, store, due_only=True)
    with writer.connect() as conn:
        wait = conn.execute(
            "SELECT next_attempt-clock_timestamp() AS wait FROM "
            "ow.collection_state WHERE source_id='0'"
        ).fetchone()["wait"]
        assert 90 < wait.total_seconds() <= 120


@pytest.mark.integration
def test_restore_resets_http_state_and_adopts_known_v4_layout(
    databases,
    destination,
    tmp_path,
    monkeypatch,
):
    writer, _, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    install(monkeypatch, ResponseWire(headers=[(b"etag", b'"private-validator"')]))
    collect(source(), writer, store, due_only=True)
    path = tmp_path / "backup.owcp"
    receipt = recovery.checkpoint(Database(roles["admin"]), store, path)
    policy = policy_arguments(roles, path)
    target = Database(destination["admin"])
    result = recovery.restore(target, path, receipt["sha256"], tmp_path / "restored", **policy)
    assert not result["adopted_core_v4"]
    with target.connect() as conn:
        state = conn.execute("SELECT * FROM ow.collection_state").fetchone()
        assert state["etag"] is None and state["raw_sha256"] is None and state["failures"] == 0
        assert not conn.execute("SELECT enabled FROM ow.sources").fetchone()["enabled"]
    # Reconstruct the exact published v4 table/column contract with its original hashes.
    bundle = json.loads(path.read_text())
    bundle["payload"]["migrations"].pop("5")
    bundle["payload"]["migrations"].pop("6")
    bundle["payload"]["migrations"].pop("7")
    bundle["payload"]["migrations"].pop("8")
    bundle["payload"]["migrations"].pop("retrieval/3", None)
    bundle["payload"]["tables"].pop("collection_state")
    for row in bundle["payload"]["tables"]["collection_runs"]:
        row.pop("http_status")
    old = tmp_path / "v4.owcp"
    sha = digest(recovery._json(bundle["payload"]))
    old.write_bytes(recovery._json({"payload": bundle["payload"], "sha256": sha}))
    # Another genuinely empty target is required for adoption.
    from tests.test_recovery import isolated

    with isolated(roles, retrieval=bool(bundle["payload"]["database"]["pgvector"])) as fresh:
        result = recovery.restore(
            Database(fresh["admin"]), old, sha, tmp_path / "adopted", **policy
        )
        assert result["adopted_core_v4"] and result["objects"] > 0
        with Database(fresh["admin"]).connect() as conn:
            assert (
                conn.execute("SELECT count(*) AS n FROM ow.collection_state").fetchone()["n"] == 0
            )


def test_last_modified_fallback_and_unsolicited_redirect_304(monkeypatch):
    wire = ResponseWire(304, b"", [(b"last-modified", MODIFIED.encode())])
    install(monkeypatch, wire)
    assert acquisition.fetch_response(source().url, last_modified=MODIFIED).status == 304
    assert dict(wire.request.headers)[b"if-modified-since"] == MODIFIED.encode()
    redirect = ResponseWire(302, b"", [(b"location", b"http://other.invalid/feed")])
    final = ResponseWire(304, b"")
    install(monkeypatch, redirect, final)
    with pytest.raises(WorkbenchError, match="UNSOLICITED_NOT_MODIFIED"):
        acquisition.fetch_response(source().url, etag='"v1"')


@pytest.mark.integration
def test_killed_collector_keeps_retry_reservation_and_reconciles(databases, tmp_path, monkeypatch):
    import os
    import subprocess
    import sys

    writer, _, roles = databases
    root = tmp_path / "objects"
    code = """
import os,sys,httpcore
from pathlib import Path
from osint_workbench import fetch as acquisition
from osint_workbench.collection import collect
from osint_workbench.contracts import Source
from osint_workbench.database import Database
from osint_workbench.evidence import EvidenceStore
class Killed(httpcore.SyncBackend):
    def connect_tcp(self,*args,**kwargs):
        os._exit(73)
acquisition._PublicBackend = lambda deadline: Killed()
collect(Source(source_id="fixture",url="http://example.invalid/feed",poll_seconds=60),
        Database(os.environ["OW_WRITER_DSN"]),EvidenceStore(Path(sys.argv[1])),due_only=True)
"""
    killed = subprocess.run(
        [sys.executable, "-c", code, str(root)],
        env={**os.environ, "OW_WRITER_DSN": roles["writer"]},
        capture_output=True,
        text=True,
    )
    assert killed.returncode == 73
    store = EvidenceStore(root)
    assert collect(source(), writer, store, due_only=True)["status"] == "not_due"
    with writer.connect() as conn:
        row = conn.execute(
            "SELECT failures,next_attempt>clock_timestamp() AS delayed FROM ow.collection_state"
        ).fetchone()
        assert row == {"failures": 1, "delayed": True}
        assert conn.execute("SELECT status,error_code FROM ow.collection_runs").fetchone() == {
            "status": "interrupted",
            "error_code": "COLLECTOR_LOST",
        }
    due(writer)
    install(monkeypatch, ResponseWire())
    assert collect(source(), writer, store, due_only=True)["documents"] == 2


@pytest.mark.integration
def test_reader_rejects_accidental_validator_column_grant(databases):
    _, reader, roles = databases
    try:
        with Database(roles["admin"]).connect() as conn:
            conn.execute("GRANT SELECT(etag) ON ow.collection_state TO ow_reader")
        with pytest.raises(WorkbenchError, match="UNSAFE_READER_IDENTITY"):
            reader.validate_reader()
    finally:
        with Database(roles["admin"]).connect() as conn:
            conn.execute("REVOKE SELECT(etag) ON ow.collection_state FROM ow_reader")


@pytest.mark.integration
def test_cached_body_is_a_gc_and_checkpoint_reference(databases, tmp_path):
    from osint_workbench import garbage_collection as gc
    from tests.test_garbage_collection import orphan

    writer, _, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    sha, retained = orphan(store, b"independently retained cached body")
    with writer.connect() as conn:
        conn.execute("INSERT INTO ow.sources(source_id) VALUES ('fixture')")
        conn.execute(
            "INSERT INTO ow.collection_state(source_id,resource_sha256,raw_sha256) "
            "VALUES ('fixture',%s,%s)",
            ("a" * 64, sha),
        )
    operator = Database(roles["admin"])
    plan = gc.plan(operator, store, tmp_path / "plan.owgc", operation_id="cache")
    assert plan["objects"] == 0 and retained.exists()
    path = tmp_path / "cache.owcp"
    receipt = recovery.checkpoint(operator, store, path)
    assert receipt["objects"] == 1
    assert set(json.loads(path.read_text())["payload"]["objects"]) == {sha}


@pytest.mark.integration
def test_native_http_server_to_postgresql_revalidation(databases, tmp_path, monkeypatch):
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    writer, reader, _ = databases
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.headers.get("If-None-Match"))
            if requests[-1] == '"native"':
                self.send_response(304)
                self.send_header("ETag", '"native"')
                self.end_headers()
            else:
                self.send_response(200)
                self.send_header("ETag", '"native"')
                self.send_header("Content-Length", str(len(FEED)))
                self.end_headers()
                self.wfile.write(FEED)

        def log_message(self, *args):
            pass

    # Fixture routing only: actual sockets/framing/deadlines/parser/database;
    # production DNS/TLS/address policy is deliberately not asserted by this test.
    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        class RoutedBackend(acquisition._PublicBackend):
            def connect_tcp(self, host, port, timeout=None, **kwargs):
                stream = httpcore.SyncBackend.connect_tcp(
                    self,
                    "127.0.0.1",
                    server.server_port,
                    timeout=timeout,
                )
                return acquisition._Stream(stream, self.deadline)

        monkeypatch.setattr(acquisition, "_PublicBackend", RoutedBackend)
        try:
            store = EvidenceStore(tmp_path / "objects")
            assert collect(source(), writer, store, due_only=True)["documents"] == 2
            due(writer)
            assert collect(source(), writer, store, due_only=True)["status"] == "not_modified"
            assert requests == [None, '"native"'] and reader.status()["documents"] == 2
        finally:
            server.shutdown()
            thread.join(timeout=5)


@pytest.mark.integration
def test_checkpoint_and_restore_reject_row_filtered_schema(databases, destination, tmp_path):
    writer, _, roles = databases
    from tests.test_recovery import _input

    store = EvidenceStore(tmp_path / "objects")
    writer.ingest(_input(), b"raw", store)
    operator = Database(roles["admin"])
    path = tmp_path / "backup.owcp"
    receipt = recovery.checkpoint(operator, store, path)
    policy = policy_arguments(roles, path)
    try:
        with operator.connect() as conn:
            conn.execute("ALTER TABLE ow.collection_state ENABLE ROW LEVEL SECURITY")
        with pytest.raises(WorkbenchError, match="RECOVERY_ROW_SECURITY_UNSUPPORTED"):
            recovery.checkpoint(operator, store, tmp_path / "filtered.owcp")
        assert not (tmp_path / "filtered.owcp").exists()
    finally:
        with operator.connect() as conn:
            conn.execute("ALTER TABLE ow.collection_state DISABLE ROW LEVEL SECURITY")
    target = Database(destination["admin"])
    with target.connect() as conn:
        conn.execute("ALTER TABLE ow.collection_state ENABLE ROW LEVEL SECURITY")
    with pytest.raises(WorkbenchError, match="RECOVERY_ROW_SECURITY_UNSUPPORTED"):
        recovery.restore(target, path, receipt["sha256"], tmp_path / "restored", **policy)
    assert not (tmp_path / "restored").exists()


@pytest.mark.integration
@pytest.mark.parametrize("due_only", [True, False])
def test_new_body_cannot_mask_missing_retained_evidence(databases, tmp_path, monkeypatch, due_only):
    writer, _, _ = databases
    store = EvidenceStore(tmp_path / "objects")
    install(monkeypatch, ResponseWire(headers=[(b"etag", b'"old"')]))
    collect(source(), writer, store, due_only=True)
    (store.root / digest(FEED)[:2] / digest(FEED)).unlink()
    due(writer)
    changed = FEED.replace(b"Second evidence", b"Different new evidence")
    wire = ResponseWire(body=changed, headers=[(b"etag", b'"new"')])
    install(monkeypatch, wire)
    with pytest.raises(WorkbenchError, match="EVIDENCE_UNAVAILABLE"):
        collect(source(), writer, store, due_only=due_only)
    assert b"if-none-match" not in dict(wire.request.headers)
    with writer.connect() as conn:
        row = conn.execute("SELECT etag,raw_sha256 FROM ow.collection_state").fetchone()
        assert row == {"etag": '"old"', "raw_sha256": digest(FEED)}
        assert conn.execute("SELECT last_error FROM ow.sources").fetchone()["last_error"] == (
            "EVIDENCE_UNAVAILABLE"
        )
        assert (
            conn.execute(
                "SELECT accepted_documents FROM ow.collection_runs WHERE status='failed'"
            ).fetchone()["accepted_documents"]
            == 0
        )
