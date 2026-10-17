import calendar
from datetime import UTC, datetime

import feedparser

from .contracts import DocumentInput, Source
from .database import Database
from .errors import WorkbenchError
from .evidence import EvidenceStore
from .fetch import fetch, validate_url
from .text import html_text


def feed_documents(raw: bytes, source_id: str) -> list[DocumentInput]:
    if len(raw) > 10 * 1024 * 1024:
        raise WorkbenchError("SOURCE_TOO_LARGE")
    parsed = feedparser.parse(raw)
    if not parsed.version or parsed.bozo:
        raise WorkbenchError("FEED_PARSE_FAILED")
    if len(parsed.entries) > 10000:
        raise WorkbenchError("FEED_ENTRY_LIMIT")
    documents = []
    for entry in parsed.entries:
        title = html_text(str(entry.get("title", "")))
        content = entry.get("content") or []
        text = html_text(str(content[0].get("value", "") if content else entry.get("summary", "")))
        identity = str(entry.get("id") or entry.get("link") or "")
        if not title or not text or not identity:
            continue
        published = None
        if entry.get("published_parsed"):
            try:
                published = datetime.fromtimestamp(calendar.timegm(entry.published_parsed), UTC)
            except (ValueError, OverflowError, OSError):
                pass
        documents.append(
            DocumentInput(
                source_id=source_id,
                external_id=identity,
                title=title[:2000],
                text=text,
                published_at=published,
            )
        )
    return documents


def collect(source: Source, db: Database, store: EvidenceStore) -> dict:
    if not source.enabled:
        return {"status": "disabled", "documents": 0}
    validate_url(source.url)
    with db.connect() as conn:
        conn.execute(
            """INSERT INTO ow.sources(source_id,enabled,freshness_seconds,last_attempt)
          VALUES (%s,true,%s,clock_timestamp()) ON CONFLICT(source_id) DO UPDATE
          SET enabled=true,freshness_seconds=excluded.freshness_seconds,
              last_attempt=clock_timestamp()""",
            (source.source_id, source.freshness_seconds),
        )
    try:
        raw = fetch(source.url)
        documents = feed_documents(raw, source.source_id)
        ids = [
            db.ingest(document, raw, store, extractor="feedparser-html/1") for document in documents
        ]
        with db.connect() as conn:
            conn.execute(
                "UPDATE ow.sources SET last_success=clock_timestamp(),last_error=NULL "
                "WHERE source_id=%s",
                (source.source_id,),
            )
        return {"status": "success", "documents": len(ids), "document_ids": ids}
    except WorkbenchError as exc:
        with db.connect() as conn:
            conn.execute(
                "UPDATE ow.sources SET last_error=%s WHERE source_id=%s",
                (exc.code, source.source_id),
            )
        raise
