"""Native HTTP -> scoped collector -> PostgreSQL Retry-After scheduling evidence.

Only destination routing is injected. HTTP framing, Retry-After parsing, feed
parsing, scoped grants, durable scheduling and immutable objects are real.
"""

import threading
from datetime import UTC, timedelta
from email.utils import format_datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpcore
import pytest
from psycopg import sql

from osint_workbench import fetch as acquisition
from osint_workbench.collection import collect, collect_due
from osint_workbench.contracts import Source
from osint_workbench.database import Database
from osint_workbench.errors import WorkbenchError
from osint_workbench.evidence import EvidenceStore
from tests.test_workflows import FEED

pytestmark = pytest.mark.integration


@pytest.fixture
def native(databases, tmp_path, monkeypatch):
    _, _, roles = databases
    collector = Database(roles["collector"])
    collector.validate_collector()
    admin = Database(roles["admin"])
    store = EvidenceStore(tmp_path / "objects")
    fixture = {
        "response": (200, [("ETag", '"retained"')], FEED),
        "requests": [],
        "before_response": None,
        "routes": {},
    }

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            fixture["requests"].append(
                {
                    "path": self.path,
                    "etag": self.headers.get("If-None-Match"),
                    "modified": self.headers.get("If-Modified-Since"),
                }
            )
            if fixture["before_response"] is not None:
                fixture["before_response"]()
            status, headers, body = fixture["routes"].get(self.path, fixture["response"])
            self.send_response(status)
            for name, value in headers:
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if body:
                self.wfile.write(body)

        def log_message(self, *args):
            pass

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
            yield collector, admin, store, fixture, roles
        finally:
            server.shutdown()
            thread.join(timeout=5)


def source(identifier="fixture"):
    return Source(source_id=identifier, url=f"http://feed.invalid/{identifier}", poll_seconds=60)


def due(admin, identifier="fixture"):
    with admin.connect() as conn:
        conn.execute(
            "UPDATE ow.collection_state SET next_attempt=clock_timestamp()-interval '1 s' "
            "WHERE source_id=%s",
            (identifier,),
        )


def state(admin, identifier="fixture"):
    with admin.connect() as conn:
        return conn.execute(
            "SELECT *,clock_timestamp() AS observed_at,"
            "next_attempt>clock_timestamp() AS future "
            "FROM ow.collection_state WHERE source_id=%s",
            (identifier,),
        ).fetchone()


def now(admin):
    with admin.connect() as conn:
        return conn.execute("SELECT clock_timestamp() AS instant").fetchone()["instant"]


def static_records(admin):
    with admin.connect() as conn:
        return {
            table: conn.execute(
                sql.SQL("SELECT * FROM ow.{} ORDER BY 1").format(sql.Identifier(table))
            ).fetchall()
            for table in ("snapshots", "documents", "document_heads", "jobs")
        }


def files(store):
    return {
        str(path.relative_to(store.root)): path.read_bytes()
        for path in store.root.rglob("*")
        if path.is_file()
    }


def run_count(admin, identifier="fixture"):
    with admin.connect() as conn:
        return conn.execute(
            "SELECT count(*) AS n FROM ow.collection_runs WHERE source_id=%s", (identifier,)
        ).fetchone()["n"]


def latest_run(admin, identifier="fixture"):
    with admin.connect() as conn:
        return conn.execute(
            "SELECT * FROM ow.collection_runs WHERE source_id=%s ORDER BY started_at DESC LIMIT 1",
            (identifier,),
        ).fetchone()


@pytest.mark.parametrize("status,date_hint", [(429, False), (503, False), (429, True), (503, True)])
def test_retry_after_durable_db_clock_restart_and_unconditional_retry(native, status, date_hint):
    collector, admin, store, fixture, roles = native
    assert collect(source(), collector, store, due_only=True)["documents"] == 2
    initial = state(admin)
    retained_records, retained_files = static_records(admin), files(store)
    due(admin)
    before = now(admin)
    retry_date = (before + timedelta(seconds=300)).replace(microsecond=0)
    hint = format_datetime(retry_date.astimezone(UTC), usegmt=True) if date_hint else "300"
    fixture["response"] = (status, [("Retry-After", hint)], b"")
    with pytest.raises(WorkbenchError, match="^SOURCE_HTTP_ERROR$"):
        collect(source(), collector, store, due_only=True)
    failed = state(admin)
    assert failed["failures"] == 1 and failed["future"]
    if date_hint:
        assert failed["next_attempt"] == retry_date
    else:
        assert before + timedelta(seconds=300) <= failed["next_attempt"]
        assert failed["next_attempt"] <= failed["observed_at"] + timedelta(seconds=300)
    assert all(failed[name] == initial[name] for name in ("etag", "last_modified", "raw_sha256"))
    assert latest_run(admin)["error_code"] == "SOURCE_HTTP_ERROR"
    assert latest_run(admin)["accepted_documents"] == 0
    assert run_count(admin) == 2
    with admin.connect() as conn:
        assert conn.execute("SELECT last_error FROM ow.sources").fetchone()["last_error"] == (
            "SOURCE_HTTP_ERROR"
        )
    assert static_records(admin) == retained_records and files(store) == retained_files
    request_count = len(fixture["requests"])
    # A new connection-owning instance has no in-memory scheduler state.
    restarted = Database(roles["collector"])
    tick = collect_due([source()], restarted, store)
    assert tick == {"status": "complete", "results": [], "deferred_sources": 0}
    assert len(fixture["requests"]) == request_count
    assert run_count(admin) == 2
    assert latest_run(admin)["error_code"] == "SOURCE_HTTP_ERROR"
    assert static_records(admin) == retained_records and files(store) == retained_files
    # Explicit fixture clock advancement by changing only due time: failed state
    # must prevent forwarding the previously successful representation validator.
    due(admin)
    fixture["response"] = (200, [("ETag", '"revalidated"')], FEED)
    assert collect(source(), restarted, store, due_only=True)["documents"] == 2
    assert fixture["requests"][-1]["etag"] is None
    assert fixture["requests"][-1]["modified"] is None
    assert state(admin)["failures"] == 0
    assert run_count(admin) == 3
    assert static_records(admin) == retained_records and files(store) == retained_files


@pytest.mark.parametrize(
    "headers,code",
    [
        ([("Retry-After", "1")], "SOURCE_HTTP_ERROR"),
        ([("Retry-After", "0")], "SOURCE_HTTP_ERROR"),
        ([("Retry-After", "Sat, 01 Jan 2000 00:00:00 GMT")], "SOURCE_HTTP_ERROR"),
        ([("Retry-After", "tomorrow")], "INVALID_RETRY_AFTER"),
        ([("Retry-After", "300"), ("Retry-After", "600")], "INVALID_RETRY_AFTER"),
    ],
)
def test_short_zero_past_and_invalid_retry_hints_cannot_reduce_local_backoff(native, headers, code):
    collector, admin, store, fixture, _ = native
    fixture["response"] = (503, headers, b"")
    before = now(admin)
    with pytest.raises(WorkbenchError, match=f"^{code}$"):
        collect(source(), collector, store, due_only=True)
    failed = state(admin)
    assert before + timedelta(seconds=60) <= failed["next_attempt"]
    assert failed["next_attempt"] <= failed["observed_at"] + timedelta(seconds=60)
    assert failed["failures"] == 1 and failed["future"]
    assert latest_run(admin)["status"] == "failed"
    assert latest_run(admin)["error_code"] == code
    assert files(store) == {} and all(not rows for rows in static_records(admin).values())


@pytest.mark.parametrize("date_hint", [False, True])
def test_long_numeric_and_date_retry_hints_have_observable_seven_day_cap(native, date_hint):
    collector, admin, store, fixture, _ = native
    before = now(admin)
    hint = (
        format_datetime((before + timedelta(days=30)).astimezone(UTC), usegmt=True)
        if date_hint
        else "99999999999999999999999999999999999999999999999999"
    )
    fixture["response"] = (429, [("Retry-After", hint)], b"")
    with pytest.raises(WorkbenchError, match="^SOURCE_RETRY_AFTER_CAPPED$"):
        collect(source(), collector, store, due_only=True)
    failed = state(admin)
    assert before + timedelta(days=7) <= failed["next_attempt"]
    assert failed["next_attempt"] <= failed["observed_at"] + timedelta(days=7)
    assert latest_run(admin)["error_code"] == "SOURCE_RETRY_AFTER_CAPPED"
    with admin.connect() as conn:
        assert conn.execute("SELECT last_error FROM ow.sources").fetchone()["last_error"] == (
            "SOURCE_RETRY_AFTER_CAPPED"
        )
    assert files(store) == {} and failed["failures"] == 1


@pytest.mark.parametrize("short_hint", [False, True])
def test_failed_manual_override_preserves_prior_wait_but_success_can_reset_it(native, short_hint):
    collector, admin, store, fixture, _ = native
    fixture["response"] = (429, [("Retry-After", "3600")], b"")
    with pytest.raises(WorkbenchError, match="^SOURCE_HTTP_ERROR$"):
        collect(source(), collector, store, due_only=True)
    promised_due = state(admin)["next_attempt"]
    fixture["response"] = (503, [("Retry-After", "1")] if short_hint else [], b"")
    with pytest.raises(WorkbenchError, match="^SOURCE_HTTP_ERROR$"):
        collect(source(), collector, store, due_only=False)
    assert state(admin)["next_attempt"] >= promised_due
    assert state(admin)["failures"] == 2
    assert files(store) == {} and all(not rows for rows in static_records(admin).values())
    fixture["response"] = (200, [("ETag", '"operator-refreshed"')], FEED)
    before = now(admin)
    assert collect(source(), collector, store, due_only=False)["documents"] == 2
    successful = state(admin)
    assert before + timedelta(seconds=60) <= successful["next_attempt"] < promised_due
    assert successful["failures"] == 0
    assert len(static_records(admin)["jobs"]) == 2


def test_rate_limited_source_does_not_block_independent_due_source(native):
    collector, admin, store, fixture, _ = native
    fixture["routes"] = {
        "/bad": (503, [("Retry-After", "300")], b""),
        "/good": (200, [("ETag", '"independent"')], FEED),
    }
    result = collect_due([source("bad"), source("good")], collector, store)
    assert result["status"] == "failed"
    assert [(row["source_id"], row["status"]) for row in result["results"]] == [
        ("bad", "failed"),
        ("good", "success"),
    ]
    assert result["results"][0]["error"] == "SOURCE_HTTP_ERROR"
    assert result["results"][1]["documents"] == 2
    assert [row["path"] for row in fixture["requests"]] == ["/bad", "/good"]
    assert state(admin, "bad")["failures"] == 1
    assert state(admin, "good")["failures"] == 0
    records = static_records(admin)
    assert len(records["jobs"]) == 2
    assert all(row["source_id"] == "good" for row in records["documents"])


def test_lost_pg_connection_cannot_claim_retry_after_was_persisted(native, caplog):
    collector, admin, store, fixture, roles = native
    with collector.connect() as conn:
        login = conn.execute("SELECT current_user AS login").fetchone()["login"]
    terminated = []

    def sever_collector_connection():
        with admin.connect() as conn:
            rows = conn.execute(
                "SELECT pid FROM pg_stat_activity WHERE datname=current_database() "
                "AND usename=%s AND state='idle' AND pid<>pg_backend_pid()",
                (login,),
            ).fetchall()
            if len(rows) == 1:
                terminated.append(
                    conn.execute(
                        "SELECT pg_terminate_backend(%s,1000) AS terminated", (rows[0]["pid"],)
                    ).fetchone()["terminated"]
                )
            else:
                terminated.append(False)

    fixture["before_response"] = sever_collector_connection
    fixture["response"] = (429, [("Retry-After", "3600")], b"")
    with pytest.raises(WorkbenchError, match="^COLLECTION_STATE_PERSIST_FAILED$"):
        collect(source(), collector, store, due_only=True)
    assert terminated == [True]
    assert "error ignored in rollback" not in caplog.text
    failed = state(admin)
    assert failed["failures"] == 1 and failed["future"]
    assert failed["next_attempt"] < failed["observed_at"] + timedelta(seconds=60)
    assert latest_run(admin)["status"] == "running"
    fixture["before_response"] = None
    restarted = Database(roles["collector"])
    # Direct due-only admission reconciles an interrupted receipt before refusing
    # its still-reserved delay; no new HTTP request or hinted-wait claim is made.
    assert collect(source(), restarted, store, due_only=True) == {
        "status": "not_due",
        "documents": 0,
    }
    assert len(fixture["requests"]) == 1
    assert latest_run(admin)["status"] == "interrupted"
    assert latest_run(admin)["error_code"] == "COLLECTOR_LOST"
    assert files(store) == {} and all(not rows for rows in static_records(admin).values())
