"""Strict page admission and sanitized disposable-parser wire behavior."""

import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from osint_workbench import api_parser
from osint_workbench.errors import WorkbenchError

ITEM = {"id": "record-1", "title": "Fixture title", "text": "Original <script>data</script>"}


def page(items=None, cursor=None):
    return json.dumps({"items": [ITEM] if items is None else items, "next_cursor": cursor}).encode()


def test_page_preserves_source_text_and_opaque_cursor():
    item = dict(ITEM, published_at="2026-10-18T20:00:00+02:00")
    documents, cursor = api_parser.parse(page([item], "a +/%?&=#"), "fixture")
    assert cursor == "a +/%?&=#"
    assert len(documents) == 1
    assert documents[0].source_id == "fixture"
    assert documents[0].external_id == ITEM["id"]
    assert documents[0].text == ITEM["text"]
    assert documents[0].published_at == datetime(2026, 10, 18, 18, tzinfo=UTC)


@pytest.mark.parametrize("cursor", [None, "", "next"])
def test_empty_pages_are_explicit_and_source_is_still_validated(cursor):
    assert api_parser.parse(page([], cursor), "fixture") == ([], cursor)
    with pytest.raises(WorkbenchError, match="^API_INVALID_PAGE$"):
        api_parser.parse(page([], cursor), "../private-canary")


@pytest.mark.parametrize(
    "raw",
    [
        b'{"items":[],"next_cursor":null,"items":[]}',
        b'{"items":[{"id":"a","id":"b","title":"x","text":"y"}],"next_cursor":null}',
        b'{"items":[],"next_cursor":NaN}',
        b'{"items":[],"next_cursor":Infinity}',
        b'{"items":[],"next_cursor":-Infinity}',
        b'{"items":[],"next_cursor":1e999}',
        b'{"items":[]}',
        b'{"items":[],"next_cursor":null,"extra":0}',
        b"[]",
        b'{"items":{},"next_cursor":null}',
        b'{"items":[],"next_cursor":"\\ud800"}',
        b"\xff",
        b'{"items":[],"next_cursor":null} trailing',
        b"[" * 33 + b"0" + b"]" * 33,
    ],
)
def test_malformed_page_is_sanitized(raw):
    with pytest.raises(WorkbenchError) as caught:
        api_parser.parse(raw, "fixture")
    assert caught.value.args == ("API_INVALID_PAGE",)


@pytest.mark.parametrize(
    "item",
    [
        dict(ITEM, id=""),
        dict(ITEM, id="x" * 1025),
        dict(ITEM, title=""),
        dict(ITEM, title="x" * 2001),
        dict(ITEM, title=1),
        dict(ITEM, text=""),
        dict(ITEM, text="x" * 1_000_001),
        dict(ITEM, text="\udfff"),
        dict(ITEM, extra="private-canary"),
        {"id": "a", "title": "missing-text"},
    ],
)
def test_invalid_record_rejects_entire_page(item):
    with pytest.raises(WorkbenchError, match="^API_INVALID_PAGE$"):
        api_parser.parse(page([dict(ITEM, id="first-record"), item]), "fixture")


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-10-18T12:00:00",
        "2026-10-18T24:00:00Z",
        "2026-10-18T12:00:00+24:00",
        "2026-10-18T12:00:00+00:60",
        "2026-02-30T12:00:00Z",
        "2026-10-18 12:00:00Z",
        "2026-10-18T12:00:60Z",
        "2026-10-18T12:00:00.1234567Z",
        1792324800,
    ],
)
def test_timestamp_uses_existing_strict_rfc3339_contract(timestamp):
    with pytest.raises(WorkbenchError, match="^API_INVALID_PAGE$"):
        api_parser.parse(page([dict(ITEM, published_at=timestamp)]), "fixture")


def test_null_publication_and_quoted_brackets_are_data():
    documents, _ = api_parser.parse(
        page([dict(ITEM, text='["\\' * 100, published_at=None)]), "fixture"
    )
    assert documents[0].published_at is None


@pytest.mark.parametrize("cursor", ["\r", "\n", "\t", "\x00", "\x7f", "é", "x" * 1025, 1])
def test_cursor_is_bounded_printable_ascii(cursor):
    with pytest.raises(WorkbenchError, match="^API_INVALID_PAGE$"):
        api_parser.parse(page(cursor=cursor), "fixture")


def test_record_limits_and_duplicate_identity():
    with pytest.raises(WorkbenchError, match="^API_INVALID_PAGE$"):
        api_parser.parse(page([ITEM, ITEM]), "fixture")
    with pytest.raises(WorkbenchError, match="^API_INVALID_PAGE$"):
        api_parser.parse(page([ITEM] * 1001), "fixture")
    documents, _ = api_parser.parse(
        page([dict(ITEM, id=str(number)) for number in range(1000)]), "fixture"
    )
    assert len(documents) == 1000


def test_input_and_expanded_result_byte_limits(monkeypatch):
    with pytest.raises(WorkbenchError, match="^SOURCE_TOO_LARGE$"):
        api_parser.parse(b" " * (api_parser.MAX_INPUT + 1), "fixture")
    with pytest.raises(WorkbenchError, match="^API_PARSE_FAILED$"):
        api_parser.parse("not-bytes", "fixture")
    monkeypatch.setattr(api_parser, "MAX_RESULT", 10)
    with pytest.raises(WorkbenchError, match="^API_RESULT_LIMIT$"):
        api_parser.parse(page(), "fixture")


def child(raw):
    source = Path(api_parser.__file__).resolve().parent.parent
    script = (
        "import runpy,sys; "
        f"sys.path.insert(0,{str(source)!r}); "
        "sys.argv=['api_parser','fixture']; "
        "runpy.run_module('osint_workbench.api_parser',run_name='__main__')"
    )
    environment = {key: value for key, value in os.environ.items() if key in {"PATH", "LANG"}}
    return subprocess.run(
        [sys.executable, "-I", "-c", script],
        input=raw,
        capture_output=True,
        timeout=10,
        env=environment,
        check=False,
    )


def test_disposable_process_returns_typed_envelope_and_fixed_failures(tmp_path):
    result = child(page())
    assert result.returncode == 0
    assert result.stderr == b""
    output = json.loads(result.stdout)
    assert set(output) == {"documents", "next_cursor"}
    assert output["documents"][0]["text"] == ITEM["text"]
    outside = tmp_path / "private-canary.json"
    outside.write_bytes(page())
    for data in (str(outside).encode(), outside.as_uri().encode(), b"https://fixture.invalid/"):
        rejected = child(data)
        assert rejected.returncode == 1
        assert rejected.stderr == b""
        assert json.loads(rejected.stdout) == {"error": "API_INVALID_PAGE"}
        assert b"canary" not in rejected.stdout
