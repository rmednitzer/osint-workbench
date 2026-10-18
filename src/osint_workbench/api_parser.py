"""Data-only JSON page parser for the explicitly configured synthetic API profile.

This process has resource limits, not a filesystem or network sandbox. It never
interprets response text as a path, URL, script or instruction.
"""

import json
import sys

from pydantic import TypeAdapter, ValidationError

from .advisory import UtcDatetime
from .contracts import DocumentInput, Identifier
from .errors import WorkbenchError

MAX_INPUT = 10 * 1024 * 1024
MAX_RESULT = 16 * 1024 * 1024
MAX_ITEMS = 1000
MAX_DEPTH = 32
_IDENTIFIER = TypeAdapter(Identifier)
_TIMESTAMP = TypeAdapter(UtcDatetime)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("nonfinite number")


def _bounded_depth(value: str) -> None:
    depth = 0
    quoted = False
    escaped = False
    for character in value:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise ValueError("nesting limit")
        elif character in "]}":
            depth -= 1


def _string(value, maximum: int) -> str:
    if type(value) is not str or not 1 <= len(value) <= maximum:
        raise ValueError("invalid string")
    # JSON escape sequences can represent lone surrogates. They are not UTF-8
    # evidence and must not escape into storage or the parser wire response.
    value.encode("utf-8")
    return value


def _serialize(documents: list[DocumentInput], cursor: str | None) -> bytes:
    result = json.dumps(
        {"documents": [d.model_dump(mode="json") for d in documents], "next_cursor": cursor},
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(result) > MAX_RESULT:
        raise WorkbenchError("API_RESULT_LIMIT")
    return result


def parse(raw: bytes, source_id: str) -> tuple[list[DocumentInput], str | None]:
    """Validate one strict page; reject malformed records without partial admission."""
    if type(raw) is not bytes:
        raise WorkbenchError("API_PARSE_FAILED")
    if len(raw) > MAX_INPUT:
        raise WorkbenchError("SOURCE_TOO_LARGE")
    try:
        source_id = _IDENTIFIER.validate_python(source_id, strict=True)
        text = raw.decode("utf-8")
        _bounded_depth(text)
        page = json.loads(text, object_pairs_hook=_object, parse_constant=_reject_constant)
        if type(page) is not dict or set(page) != {"items", "next_cursor"}:
            raise ValueError("invalid envelope")
        items = page["items"]
        if type(items) is not list or len(items) > MAX_ITEMS:
            raise ValueError("invalid items")
        cursor = page["next_cursor"]
        if cursor is not None and (
            type(cursor) is not str
            or len(cursor) > 1024
            or any(not 0x20 <= ord(c) <= 0x7E for c in cursor)
        ):
            raise ValueError("invalid cursor")
        documents = []
        identities = set()
        for item in items:
            if type(item) is not dict or set(item) not in (
                {"id", "title", "text"},
                {"id", "title", "text", "published_at"},
            ):
                raise ValueError("invalid item")
            identity = _string(item["id"], 1024)
            if identity in identities:
                raise ValueError("duplicate item")
            identities.add(identity)
            published = item.get("published_at")
            if published is not None:
                published = _TIMESTAMP.validate_json(json.dumps(published), strict=True)
            documents.append(
                DocumentInput(
                    source_id=source_id,
                    external_id=identity,
                    title=_string(item["title"], 2000),
                    text=_string(item["text"], 1_000_000),
                    published_at=published,
                )
            )
        _serialize(documents, cursor)
        return documents, cursor
    except (ValueError, TypeError, ValidationError, RecursionError, OverflowError):
        raise WorkbenchError("API_INVALID_PAGE") from None


def main():
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_RESULT,) * 2)
        resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
        if len(sys.argv) != 2:
            raise WorkbenchError("API_INVALID_PAGE")
        documents, cursor = parse(sys.stdin.buffer.read(MAX_INPUT + 1), sys.argv[1])
        sys.stdout.buffer.write(_serialize(documents, cursor))
    except WorkbenchError as exc:
        sys.stdout.write(json.dumps({"error": exc.code}))
        raise SystemExit(1) from None
    except Exception:
        sys.stdout.write(json.dumps({"error": "API_PARSE_FAILED"}))
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
