import json
import re
import subprocess
import sys
import tempfile
import uuid

from .contracts import DocumentInput, Source
from .database import Database
from .errors import WorkbenchError
from .evidence import EvidenceStore
from .feed_parser import MAX_FEED, MAX_RESULT
from .fetch import fetch, validate_url


def feed_documents(raw: bytes, source_id: str) -> list[DocumentInput]:
    """Parse hostile input outside the long-lived collector with bounded resources."""
    if len(raw) > MAX_FEED:
        raise WorkbenchError("SOURCE_TOO_LARGE")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", source_id):
        raise WorkbenchError("INVALID_SOURCE_ID")
    with tempfile.TemporaryFile() as output:
        try:
            result = subprocess.run(
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
        return [DocumentInput.model_validate_json(json.dumps(row)) for row in decoded]
    except (ValueError, TypeError):
        raise WorkbenchError("FEED_PARSE_FAILED") from None


def collect(source: Source, db: Database, store: EvidenceStore) -> dict:
    # Hold the session lock on the same connection that accepts records. If it
    # disconnects, acceptance fails rather than continuing after lock loss.
    with db.connect() as conn:
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
        try:
            validate_url(source.url)
            raw = fetch(source.url)
            documents = feed_documents(raw, source.source_id)
            raw_sha = store.put(raw)  # Once per feed, not once per item.
            for document in documents:
                text_sha = store.put(document.text.encode())
                identifier = db.ingest_stored(
                    conn, document, raw_sha, text_sha, "feedparser-html/2"
                )
                conn.execute(
                    """UPDATE ow.collection_runs SET accepted_documents=accepted_documents+1,
                    raw_sha256=%s WHERE run_id=%s""",
                    (raw_sha, run_id),
                )
                conn.commit()  # Item and run count agree even across a crash.
                ids.append(identifier)
            conn.execute(
                """UPDATE ow.collection_runs SET status='succeeded',raw_sha256=%s,
                finished_at=clock_timestamp() WHERE run_id=%s""",
                (raw_sha, run_id),
            )
            conn.execute(
                """UPDATE ow.sources SET last_success=clock_timestamp(),last_error=NULL
                WHERE source_id=%s""",
                (source.source_id,),
            )
            conn.commit()
            return {
                "status": "success",
                "documents": len(ids),
                "document_ids": ids,
                "run_id": str(run_id),
            }
        except Exception as exc:
            code = exc.code if isinstance(exc, WorkbenchError) else "COLLECT_BACKEND_FAILURE"
            try:
                conn.rollback()
                conn.execute(
                    """UPDATE ow.collection_runs SET status='failed',error_code=%s,
                    finished_at=clock_timestamp() WHERE run_id=%s""",
                    (code, run_id),
                )
                conn.execute(
                    "UPDATE ow.sources SET last_error=%s WHERE source_id=%s",
                    (code, source.source_id),
                )
                conn.commit()
            except Exception:
                # Leave an interrupted run to reconcile after the connection returns.
                pass
            raise WorkbenchError(code) from None
