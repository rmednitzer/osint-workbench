import json
import subprocess
import sys
import tempfile
import uuid
from contextlib import contextmanager
from datetime import timedelta

from pydantic import TypeAdapter

from .contracts import DocumentInput, Identifier, Source
from .database import Database
from .errors import SourceHTTPError, WorkbenchError
from .evidence import EvidenceStore
from .feed_parser import MAX_FEED, MAX_RESULT
from .fetch import (
    MAX_RETRY_AFTER_SECONDS,
    FetchResult,
    fetch,
    fetch_response,
    validate_url,
    validators,
)
from .lifecycle import assert_key_visible
from .text import digest


def feed_documents(raw: bytes, source_id: str) -> list[DocumentInput]:
    """Parse hostile input outside the long-lived collector with bounded resources."""
    if len(raw) > MAX_FEED:
        raise WorkbenchError("SOURCE_TOO_LARGE")
    try:
        TypeAdapter(Identifier).validate_python(source_id)
    except ValueError:
        raise WorkbenchError("INVALID_SOURCE_ID") from None
    with tempfile.TemporaryFile() as output:
        try:
            # Reviewed: fixed interpreter/module argv, validated ID, no shell; raw feed is stdin.
            result = subprocess.run(  # noqa: S603
                [sys.executable, "-I", "-m", "osint_workbench.feed_parser", source_id],
                input=raw,
                stdout=output,
                stderr=subprocess.DEVNULL,
                env={"PYTHONIOENCODING": "utf-8"},
                timeout=8,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise WorkbenchError("FEED_PARSE_TIMEOUT") from None
        output.seek(0)
        data = output.read(MAX_RESULT + 1)
    if len(data) > MAX_RESULT:
        raise WorkbenchError("FEED_RESULT_LIMIT")
    try:
        decoded = json.loads(data)
        if result.returncode != 0:
            if isinstance(decoded, dict) and decoded.get("error") in {
                "FEED_PARSE_FAILED",
                "FEED_ENTRY_LIMIT",
                "FEED_INVALID_ENTRY",
                "FEED_INVALID_DATE",
                "FEED_RESULT_LIMIT",
                "SOURCE_TOO_LARGE",
            }:
                raise WorkbenchError(decoded["error"])
            raise WorkbenchError("FEED_PARSER_UNAVAILABLE")
        if not isinstance(decoded, list) or len(decoded) > 10000:
            raise ValueError
        documents = [DocumentInput.model_validate_json(json.dumps(row)) for row in decoded]
        if any(document.source_id != source_id for document in documents):
            raise ValueError
        return documents
    except (ValueError, TypeError):
        raise WorkbenchError("FEED_PARSE_FAILED") from None


@contextmanager
def _collection_connection(db, store=None):
    """Normalize failures before run admission as well as inside acquisition."""
    try:
        admission = store.transaction(db) if store is not None else db.connect()
        with admission as conn:
            try:
                yield conn
            except WorkbenchError:
                raise
            except Exception:
                # Closing rolls back the uncommitted setup without a second
                # driver rollback warning containing a private connection identity.
                conn.close()
                raise WorkbenchError("COLLECT_BACKEND_FAILURE") from None
    except WorkbenchError:
        raise
    except Exception:
        raise WorkbenchError("COLLECT_BACKEND_FAILURE") from None


def collect(source: Source, db: Database, store: EvidenceStore, *, due_only=False) -> dict:
    # Hold the session lock on the same connection that accepts records. If it
    # disconnects, acceptance fails rather than continuing after lock loss.
    with _collection_connection(db, store) as conn:
        locked = conn.execute(
            "SELECT pg_try_advisory_lock(hashtextextended(%s,418287406)) AS locked",
            (source.source_id,),
        ).fetchone()["locked"]
        conn.commit()
        if not locked:
            return {"status": "busy", "documents": 0}
        conn.execute(
            """INSERT INTO ow.sources(source_id,enabled,freshness_seconds)
            VALUES (%s,%s,%s) ON CONFLICT(source_id) DO UPDATE
            SET enabled=excluded.enabled,freshness_seconds=excluded.freshness_seconds""",
            (source.source_id, source.enabled, source.freshness_seconds),
        )
        # A previous crashed collector cannot still hold this session lock.
        conn.execute(
            """UPDATE ow.collection_runs SET status='interrupted',error_code='COLLECTOR_LOST',
            finished_at=clock_timestamp() WHERE source_id=%s AND status='running'""",
            (source.source_id,),
        )
        if not source.enabled:
            conn.commit()
            return {"status": "disabled", "documents": 0}
        resource = digest(
            json.dumps(
                [source.url, "feedparser-html/2", "identity", "osint-workbench/0.1"]
            ).encode()
        )
        previous = conn.execute(
            "SELECT resource_sha256 FROM ow.collection_state WHERE source_id=%s",
            (source.source_id,),
        ).fetchone()
        if previous and previous["resource_sha256"] != resource:
            conn.execute(
                "UPDATE ow.collection_state SET resource_sha256=%s,"
                "next_attempt=clock_timestamp(),failures=0,etag=NULL,last_modified=NULL,"
                "raw_sha256=NULL WHERE source_id=%s",
                (resource, source.source_id),
            )
            conn.execute(
                "UPDATE ow.sources SET last_success=NULL,last_error=NULL WHERE source_id=%s",
                (source.source_id,),
            )
        conn.execute(
            "INSERT INTO ow.collection_state(source_id,resource_sha256) VALUES (%s,%s) "
            "ON CONFLICT(source_id) DO NOTHING",
            (source.source_id, resource),
        )
        state = conn.execute(
            "SELECT *,next_attempt<=clock_timestamp() AS due FROM ow.collection_state "
            "WHERE source_id=%s",
            (source.source_id,),
        ).fetchone()
        if due_only and not state["due"]:
            conn.commit()
            return {"status": "not_due", "documents": 0}
        # Reserve before external dispatch. A killed collector leaves a bounded
        # delay and an unconfirmed attempt, not an immediate retry storm.
        delay = min(86400, source.poll_seconds * 2 ** min(state["failures"], 16))
        conn.execute(
            "UPDATE ow.collection_state SET failures=least(failures+1,32),"
            "next_attempt=greatest(next_attempt,clock_timestamp()+make_interval(secs=>%s)) "
            "WHERE source_id=%s",
            (delay, source.source_id),
        )
        run_id = uuid.uuid4()
        conn.execute(
            "UPDATE ow.sources SET last_attempt=clock_timestamp() WHERE source_id=%s",
            (source.source_id,),
        )
        conn.execute(
            "INSERT INTO ow.collection_runs(run_id,source_id,status) VALUES (%s,%s,'running')",
            (run_id, source.source_id),
        )
        conn.commit()
        ids = []
        suppressed = 0
        try:
            validate_url(source.url)
            lost_cache = None
            if state["raw_sha256"] is not None:
                try:
                    store.get(state["raw_sha256"])
                except WorkbenchError:
                    # Neither scheduled nor manual refresh may hide an observed
                    # gap in retained evidence behind a different new body.
                    lost_cache = state["raw_sha256"]
                    state.update(etag=None, last_modified=None, raw_sha256=None)
            if due_only:
                validators(state["etag"], state["last_modified"])
                response = fetch_response(
                    source.url,
                    etag=state["etag"] if state["failures"] == 0 else None,
                    last_modified=state["last_modified"] if state["failures"] == 0 else None,
                )
            else:
                response = FetchResult(200, fetch(source.url))
            if response.status == 304:
                if not state["raw_sha256"] or not (state["etag"] or state["last_modified"]):
                    raise WorkbenchError("UNSOLICITED_NOT_MODIFIED")
                store.get(state["raw_sha256"])
                raw_sha, documents = state["raw_sha256"], []
                etag = response.etag if response.etag is not None else state["etag"]
                modified = (
                    response.last_modified
                    if response.last_modified is not None
                    else state["last_modified"]
                )
            else:
                documents = feed_documents(response.body, source.source_id)
                raw_sha = store.put(response.body)  # Once per feed, not once per item.
                if lost_cache is not None:
                    # A different new representation does not repair the known gap
                    # in retained historical evidence. Never clear its failure silently.
                    store.get(lost_cache)
                etag, modified = response.etag, response.last_modified
            for document in documents:
                try:
                    assert_key_visible(
                        conn, document.source_id, digest(document.external_id.encode())
                    )
                    text_sha = store.put(document.text.encode())
                    identifier = db.ingest_stored(
                        conn,
                        document,
                        raw_sha,
                        text_sha,
                        "feedparser-html/2",
                        store=store,
                        observed_current=True,
                    )
                except WorkbenchError as exc:
                    if exc.code != "DOCUMENT_RETIRED_OR_EXPIRED":
                        raise
                    conn.execute(
                        "UPDATE ow.collection_runs SET suppressed_documents="
                        "suppressed_documents+1,raw_sha256=%s WHERE run_id=%s",
                        (raw_sha, run_id),
                    )
                    conn.commit()
                    suppressed += 1
                    continue
                conn.execute(
                    """UPDATE ow.collection_runs SET accepted_documents=accepted_documents+1,
                    raw_sha256=%s WHERE run_id=%s""",
                    (raw_sha, run_id),
                )
                conn.commit()  # Item and run count agree even across a crash.
                ids.append(identifier)
            conn.execute(
                """UPDATE ow.collection_runs SET status='succeeded',raw_sha256=%s,http_status=%s,
                finished_at=clock_timestamp() WHERE run_id=%s""",
                (raw_sha, response.status, run_id),
            )
            conn.execute(
                "UPDATE ow.collection_state SET failures=0,etag=%s,last_modified=%s,raw_sha256=%s,"
                "next_attempt=clock_timestamp()+make_interval(secs=>%s) WHERE source_id=%s",
                (etag, modified, raw_sha, source.poll_seconds, source.source_id),
            )
            conn.execute(
                """UPDATE ow.sources SET last_success=clock_timestamp(),last_error=NULL
                WHERE source_id=%s""",
                (source.source_id,),
            )
            conn.commit()
            return {
                "status": "not_modified" if response.status == 304 else "success",
                "documents": len(ids),
                "document_ids": ids,
                "suppressed_documents": suppressed,
                "run_id": str(run_id),
            }
        except Exception as exc:
            code = exc.code if isinstance(exc, WorkbenchError) else "COLLECT_BACKEND_FAILURE"
            try:
                conn.rollback()
                retry_at = None
                if isinstance(exc, SourceHTTPError):
                    # Use the database clock for both absolute-date comparison
                    # and relative waits. Persistence later than receipt is a
                    # conservative extension; never trust an origin Date clock.
                    now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
                    if exc.retry_after_seconds is not None:
                        retry_at = now + timedelta(seconds=exc.retry_after_seconds)
                    elif exc.retry_after_at is not None:
                        retry_at = exc.retry_after_at
                    if retry_at is not None:
                        limit = now + timedelta(seconds=MAX_RETRY_AFTER_SECONDS)
                        if retry_at > limit:
                            retry_at = limit
                            code = "SOURCE_RETRY_AFTER_CAPPED"
                conn.execute(
                    """UPDATE ow.collection_runs SET status='failed',error_code=%s,
                    finished_at=clock_timestamp() WHERE run_id=%s""",
                    (code, run_id),
                )
                # Validators advance only in the same transaction as successful
                # completion; failed or unconfirmed work requires a full unconditional replay.
                conn.execute(
                    "UPDATE ow.collection_state SET next_attempt=greatest(next_attempt,"
                    "clock_timestamp()+make_interval(secs=>%s),%s::timestamptz) "
                    "WHERE source_id=%s",
                    (delay, retry_at, source.source_id),
                )
                conn.execute(
                    "UPDATE ow.sources SET last_error=%s WHERE source_id=%s",
                    (code, source.source_id),
                )
                conn.commit()
            except Exception:
                # Reservation remains, but the observed server hint/failed run
                # could not be committed. Never report that persistence succeeded.
                # Avoid a second rollback in the driver context manager, whose
                # warning can include the private connection identity.
                conn.close()
                raise WorkbenchError("COLLECTION_STATE_PERSIST_FAILED") from None
            raise WorkbenchError(code) from None


def collect_due(sources, db, store, *, limit=32):
    """One bounded tick; earliest durable due times first, external sources stay external."""
    if type(limit) is not int or not 1 <= limit <= 128 or len(sources) > 1000:
        raise WorkbenchError("INVALID_COLLECTION_LIMIT")
    if len({s.source_id for s in sources}) != len(sources):
        raise WorkbenchError("DUPLICATE_SOURCE_ID")
    with _collection_connection(db) as conn:
        rows = conn.execute(
            "SELECT source_id,resource_sha256,next_attempt,"
            "next_attempt<=clock_timestamp() AS due FROM ow.collection_state "
            "WHERE source_id=ANY(%s::text[]) ORDER BY next_attempt,source_id",
            ([s.source_id for s in sources],),
        ).fetchall()
    states = {row["source_id"]: row for row in rows}
    sources_by_id = {s.source_id: s for s in sources}
    unknown, due, disabled = [], [], []
    for source in sources:
        if not source.enabled:
            disabled.append(source)
        elif source.source_id not in states or states[source.source_id]["resource_sha256"] != (
            digest(
                json.dumps(
                    [source.url, "feedparser-html/2", "identity", "osint-workbench/0.1"]
                ).encode()
            )
        ):
            unknown.append(source)
    for row in rows:
        source = sources_by_id[row["source_id"]]
        if source.enabled and row["due"] and source not in unknown:
            due.append(source)
    selected = (unknown + due)[:limit]
    results = []
    for source in disabled + selected:
        try:
            result = collect(source, db, store, due_only=True)
            results.append({"source_id": source.source_id, **result})
        except WorkbenchError as exc:
            results.append({"source_id": source.source_id, "status": "failed", "error": exc.code})
    return {
        "status": "failed" if any(r["status"] == "failed" for r in results) else "complete",
        "results": results,
        "deferred_sources": max(0, len(unknown) + len(due) - limit),
    }
