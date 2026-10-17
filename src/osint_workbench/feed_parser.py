"""Disposable feed parser process. Receives bytes, returns a bounded typed document list."""

import calendar
import json
import sys
from datetime import UTC, datetime
from io import BytesIO

from .contracts import DocumentInput
from .errors import WorkbenchError
from .text import html_text

MAX_FEED = 10 * 1024 * 1024
MAX_RESULT = 16 * 1024 * 1024


def parse(raw: bytes, source_id: str) -> list[DocumentInput]:
    import feedparser

    if not isinstance(raw, bytes):
        raise WorkbenchError("FEED_PARSE_FAILED")
    if len(raw) > MAX_FEED:
        raise WorkbenchError("SOURCE_TOO_LARGE")
    # feedparser overloads strings/bytes as URLs or filenames. An in-memory
    # stream makes fetched content data even when it resembles another resource.
    parsed = feedparser.parse(BytesIO(raw))
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
        # A malformed item makes acquisition visibly fail; do not silently drop evidence.
        if not title or not text or not identity:
            raise WorkbenchError("FEED_INVALID_ENTRY")
        published = None
        if entry.get("published_parsed"):
            try:
                published = datetime.fromtimestamp(calendar.timegm(entry.published_parsed), UTC)
            except (ValueError, OverflowError, OSError):
                raise WorkbenchError("FEED_INVALID_DATE") from None
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


def main():
    try:
        import resource

        # These are process resource bounds, not a network/filesystem sandbox.
        resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_RESULT,) * 2)
        resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
        documents = parse(sys.stdin.buffer.read(MAX_FEED + 1), sys.argv[1])
        result = json.dumps([d.model_dump(mode="json") for d in documents]).encode()
        if len(result) > MAX_RESULT:
            raise WorkbenchError("FEED_RESULT_LIMIT")
        sys.stdout.buffer.write(result)
    except WorkbenchError as exc:
        # Distinct bounded status, never parser exception text.
        sys.stdout.write(json.dumps({"error": exc.code}))
        raise SystemExit(1) from None
    except Exception:
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
