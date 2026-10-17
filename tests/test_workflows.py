import concurrent.futures
import json
import os
import select
import subprocess
import sys
import threading

import psycopg
import pytest
from psycopg import sql

from osint_workbench.collection import collect
from osint_workbench.contracts import DocumentInput, Source
from osint_workbench.database import migrate
from osint_workbench.errors import WorkbenchError
from osint_workbench.evidence import EvidenceStore
from osint_workbench.jobs import Jobs, bounded_json
from osint_workbench.worker import run_once

pytestmark = pytest.mark.integration


def document(text):
    return DocumentInput(source_id="fixture", external_id="one", title="Storage", text=text)


def due(roles, job_id, *, expire=False):
    with psycopg.connect(roles["admin"]) as conn:
        column = "lease_until" if expire else "available_at"
        conn.execute(
            sql.SQL(
                "UPDATE ow.jobs SET {}=clock_timestamp()-interval '1 second' WHERE job_id=%s"
            ).format(sql.Identifier(column)),
            (job_id,),
        )


def test_retry_budget_cancellation_and_late_completion(databases):
    writer, _, roles = databases
    jobs = Jobs(writer)
    identifier = writer.enqueue("fixture", "retry", {})
    first = jobs.claim(kinds=["fixture"])
    jobs.renew(identifier, first["fence"], 40)
    jobs.fail(identifier, first["fence"], "TEMPORARY_FAILURE")
    assert jobs.claim(kinds=["fixture"]) is None
    assert jobs.inspect(identifier)["status"] == "ready"
    due(roles, identifier)
    second = jobs.claim(kinds=["fixture"])
    assert second["attempt"] == 2
    cancelled = jobs.cancel(identifier)
    assert cancelled["acceptance_revoked"] and not cancelled["execution_stopped"]
    with pytest.raises(WorkbenchError, match="STALE"):
        jobs.finish(identifier, second["fence"], {})
    assert jobs.claim(kinds=["fixture"]) is None
    assert jobs.cancel(identifier)["status"] == "cancelled"
    assert [e["event"] for e in jobs.inspect(identifier)["events"]] == [
        "claimed",
        "retry",
        "claimed",
        "cancelled",
    ]
    exhausted = writer.enqueue("fixture", "exhausted", {})
    with psycopg.connect(roles["admin"]) as conn:
        conn.execute("UPDATE ow.jobs SET max_attempts=1 WHERE job_id=%s", (exhausted,))
    jobs.claim(kinds=["fixture"])
    due(roles, exhausted, expire=True)
    assert jobs.claim(kinds=["fixture"]) is None
    assert jobs.inspect(exhausted)["last_error"] == "ATTEMPTS_EXHAUSTED"
    for value in [{"n": float("nan")}, {"n": "a" * 70000}]:
        with pytest.raises(WorkbenchError, match="INVALID_JOB_PAYLOAD"):
            bounded_json(value)


def test_parallel_claims_are_exclusive(databases):
    writer, _, _ = databases
    identifiers = {writer.enqueue("fixture", str(i), {}) for i in range(12)}
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        claimed = list(pool.map(lambda _: Jobs(writer).claim(kinds=["fixture"]), range(12)))
    assert {str(row["job_id"]) for row in claimed} == identifiers
    assert all(row["attempt"] == 1 for row in claimed)


def test_killed_claimant_is_recovered_with_new_fence(databases):
    writer, _, roles = databases
    identifier = writer.enqueue("fixture", "crash", {})
    script = """import json,os,time
from osint_workbench.database import Database
from osint_workbench.jobs import Jobs
job=Jobs(Database(os.environ['OW_WRITER_DSN'])).claim(kinds=['fixture'])
print(json.dumps({'job_id':str(job['job_id']),'fence':str(job['fence'])}),flush=True)
time.sleep(60)
"""
    child = subprocess.Popen(
        [sys.executable, "-c", script],
        stdout=subprocess.PIPE,
        env={**os.environ, "OW_WRITER_DSN": roles["writer"]},
        text=True,
    )
    try:
        assert select.select([child.stdout], [], [], 10)[0]
        original = json.loads(child.stdout.readline())
    finally:
        child.kill()
        child.wait(timeout=5)
    due(roles, identifier, expire=True)
    recovered = Jobs(writer).claim(kinds=["fixture"])
    assert str(recovered["job_id"]) == identifier
    assert str(recovered["fence"]) != original["fence"]
    assert recovered["attempt"] == 2
    with pytest.raises(WorkbenchError, match="STALE"):
        Jobs(writer).finish(identifier, original["fence"], {})


def test_atomic_chunks_replay_and_rollback(databases, tmp_path, monkeypatch):
    writer, reader, roles = databases
    store = EvidenceStore(tmp_path / "evidence")
    text = "Straße storage evidence. " * 200
    identifier = writer.ingest(document(text), b"source", store)
    result = run_once(writer, store)
    assert result["status"] == "succeeded" and result["chunks"] > 1
    with reader.connect() as conn:
        parts = conn.execute("SELECT * FROM ow.visible_chunks ORDER BY ordinal").fetchall()
    assert all(text[p["start_offset"] : p["end_offset"]] == p["body"] for p in parts)
    assert run_once(writer, store)["status"] == "idle"
    assert writer.ingest(document(text), b"source", store) == identifier
    assert run_once(writer, store)["status"] == "idle"
    second = writer.ingest(document("Different content."), b"source 2", store)

    def crash(self, conn, row, result):
        raise WorkbenchError("INJECTED_BEFORE_COMMIT")

    monkeypatch.setattr(Jobs, "finish_locked", crash)
    assert run_once(writer, store)["status"] == "failed"
    with reader.connect() as conn:
        assert (
            conn.execute(
                "SELECT count(*) AS n FROM ow.visible_chunks WHERE document_id=%s", (second,)
            ).fetchone()["n"]
            == 0
        )
    with psycopg.connect(roles["admin"]) as conn:
        assert (
            conn.execute("SELECT count(*) FROM ow.jobs WHERE kind='document.chunked'").fetchone()[0]
            == 1
        )


FEED = b"""<rss version="2.0"><channel><title>Fixture</title>
<link>https://example.invalid/</link><description>Fixture</description>
<item><guid>1</guid><title>One</title><description>First evidence</description></item>
<item><guid>2</guid><title>Two</title><description>Second evidence</description></item>
</channel></rss>"""


def test_collection_exclusion_replay_and_disabled_state(databases, tmp_path, monkeypatch):
    writer, reader, roles = databases
    store = EvidenceStore(tmp_path / "evidence")
    source = Source(source_id="fixture", url="https://example.invalid/feed")
    entered, release = threading.Event(), threading.Event()

    def blocked_fetch(url):
        entered.set()
        assert release.wait(10)
        return FEED

    monkeypatch.setattr("osint_workbench.collection.fetch", blocked_fetch)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(collect, source, writer, store)
        assert entered.wait(10)
        try:
            assert collect(source, writer, store)["status"] == "busy"
        finally:
            release.set()
        assert future.result(timeout=15)["documents"] == 2
    monkeypatch.setattr("osint_workbench.collection.fetch", lambda _: FEED)
    assert collect(source, writer, store)["documents"] == 2
    assert reader.status()["documents"] == 2
    assert (
        collect(source.model_copy(update={"enabled": False}), writer, store)["status"] == "disabled"
    )
    assert reader.sources()[0]["freshness"] == "disabled"
    with psycopg.connect(roles["admin"]) as conn:
        rows = conn.execute("SELECT status,accepted_documents FROM ow.collection_runs").fetchall()
        assert rows == [("succeeded", 2), ("succeeded", 2)]


def test_partial_collection_records_failure_and_replays(databases, tmp_path, monkeypatch):
    writer, reader, roles = databases
    store = EvidenceStore(tmp_path / "evidence")
    source = Source(source_id="fixture", url="https://example.invalid/feed")
    monkeypatch.setattr("osint_workbench.collection.fetch", lambda _: FEED)
    put = store.put

    def failing(data):
        if data == b"Second evidence":
            raise WorkbenchError("INJECTED_STORE_FAILURE")
        return put(data)

    monkeypatch.setattr(store, "put", failing)
    with pytest.raises(WorkbenchError, match="INJECTED_STORE_FAILURE"):
        collect(source, writer, store)
    assert reader.status()["documents"] == 1
    with psycopg.connect(roles["admin"]) as conn:
        assert conn.execute(
            "SELECT status,accepted_documents FROM ow.collection_runs"
        ).fetchone() == ("failed", 1)
    monkeypatch.setattr(store, "put", put)
    assert collect(source, writer, store)["documents"] == 2
    assert reader.status()["documents"] == 2
    assert reader.sources()[0]["last_error"] is None


def test_migration_tamper_and_future_schema_refused(databases):
    _, _, roles = databases
    with psycopg.connect(roles["admin"]) as conn:
        digest = conn.execute("SELECT sha256 FROM ow.migrations WHERE version=2").fetchone()[0]
        conn.execute("UPDATE ow.migrations SET sha256='tampered' WHERE version=2")
    try:
        with pytest.raises(WorkbenchError, match="DIGEST_MISMATCH"):
            migrate(roles["admin"])
    finally:
        with psycopg.connect(roles["admin"]) as conn:
            conn.execute("UPDATE ow.migrations SET sha256=%s WHERE version=2", (digest,))
    with psycopg.connect(roles["admin"]) as conn:
        conn.execute("INSERT INTO ow.migrations(version,sha256) VALUES (99,'future')")
    try:
        with pytest.raises(WorkbenchError, match="UNSUPPORTED_MIGRATION"):
            migrate(roles["admin"])
    finally:
        with psycopg.connect(roles["admin"]) as conn:
            conn.execute("DELETE FROM ow.migrations WHERE version=99")
