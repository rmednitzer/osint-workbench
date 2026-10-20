"""Static HTML extraction and native collection boundaries; synthetic inputs only."""

import asyncio
import json
import os
import sys

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from pydantic import ValidationError

from osint_workbench import lifecycle
from osint_workbench.collection import collect, collect_due, html_documents, resource_identity
from osint_workbench.contracts import Source
from osint_workbench.database import Database
from osint_workbench.errors import WorkbenchError
from osint_workbench.evidence import EvidenceStore
from osint_workbench.html_parser import parse
from osint_workbench.service import ReadService
from osint_workbench.text import digest
from osint_workbench.worker import run_once
from tests.test_scheduled_collection import ResponseWire, due, install
from tests.test_workflows import FEED
from tests.tls_fixture import generate_certificates, tls_peer

URL = "https://feed.fixture.invalid/feed"
HTML = b"""<!doctype html><html><head><title>Synthetic page</title>
<meta name="date" content="2099-01-01"><link rel="canonical" href="https://other.invalid/">
<script>never request https://private.invalid/</script></head><body>
<h1>Evidence</h1><p>First &amp; second.</p><template>hidden</template>
<style>hidden</style><iframe>hidden</iframe><object>hidden</object>
<script>hidden</script></body></html>"""
TEXT = "Evidence\nFirst & second."


def source(**changes):
    return Source.model_validate(
        {
            "source_id": "html-fixture",
            "url": URL,
            "adapter": "static-html/1",
            "poll_seconds": 60,
            "rights": "all-existing-uses-permitted",
            "request_billing": "unmetered",
            **changes,
        }
    )


def test_static_config_opt_in_and_exact_legacy_resource_identity():
    rss = Source(source_id="rss", url=URL)
    assert rss.adapter == "rss-atom/1"
    assert resource_identity(rss) == digest(
        json.dumps([URL, "feedparser-html/2", "identity", "osint-workbench/0.1"]).encode()
    )
    assert resource_identity(source()) != resource_identity(rss)
    for change in ({"rights": None}, {"request_billing": None}, {"adapter": "javascript"}):
        with pytest.raises(ValidationError):
            source(**change)
    bypassed = source().model_copy(update={"rights": None})
    with pytest.raises(WorkbenchError, match="SOURCE_CONFIGURATION_INVALID"):
        collect(bypassed, None, None)
    with pytest.raises(WorkbenchError, match="SOURCE_CONFIGURATION_INVALID"):
        collect_due([bypassed], None, None)


def test_parser_extracts_syntactic_text_without_metadata_or_hidden_content():
    assert parse(HTML) == {"title": "Synthetic page", "text": TEXT}
    assert parse(HTML.replace(b"First", "Straße".encode()))["text"] == "Evidence\nStraße & second."


@pytest.mark.parametrize(
    "raw,code",
    [
        (HTML.replace(b"First", b"\xff"), "HTML_ENCODING_UNSUPPORTED"),
        (HTML.replace(b"First", b"\x00"), "HTML_PARSE_FAILED"),
        (
            HTML.replace(b"<!doctype html>", b'<!DOCTYPE html SYSTEM "file:///private">'),
            "HTML_STRUCTURE_UNSUPPORTED",
        ),
        (HTML.replace(b"</head>", b"<title>second</title></head>"), "HTML_STRUCTURE_UNSUPPORTED"),
        (HTML.replace(b"</body>", b""), "HTML_STRUCTURE_UNSUPPORTED"),
        (
            b"<head><title>T</title></head><body><script>only hidden</script></body>",
            "HTML_EMPTY_DOCUMENT",
        ),
        (b"<head><title>T</title></head><body>" + b"x" * 1_000_001 + b"</body>", "HTML_TEXT_LIMIT"),
        (b"x" * (10 * 1024 * 1024 + 1), "SOURCE_TOO_LARGE"),
    ],
)
def test_parser_refuses_unsupported_or_unbounded_input(raw, code):
    with pytest.raises(WorkbenchError, match="^" + code + "$"):
        parse(raw)


def test_isolated_html_child_binds_operator_identity_and_safe_errors():
    (document,) = html_documents(HTML, source())
    assert document.external_id == URL and document.source_id == "html-fixture"
    assert document.title == "Synthetic page" and document.text == TEXT
    assert document.published_at is None
    with pytest.raises(WorkbenchError, match="^HTML_ENCODING_UNSUPPORTED$"):
        html_documents(HTML.replace(b"First", b"\xff"), source())


def test_parser_refuses_self_closing_hidden_container_and_accepts_void_marker():
    raw = b"<head><title>T</title></head><body><script/>secret</script><p>Visible</p></body>"
    with pytest.raises(WorkbenchError, match="^HTML_STRUCTURE_UNSUPPORTED$"):
        parse(raw)
    assert parse(b"<head><title>T</title></head><body>One<br/>Two<img src='ignored'/></body>") == {
        "title": "T",
        "text": "One\nTwo",
    }


def test_isolated_child_refuses_self_closing_hidden_container():
    raw = b"<head><title>T</title></head><body><script/>secret</script><p>Visible</p></body>"
    with pytest.raises(WorkbenchError, match="^HTML_STRUCTURE_UNSUPPORTED$"):
        html_documents(raw, source())
    (document,) = html_documents(
        b"<head><title>T</title></head><body>One<br/>Two<img src='ignored'/></body>", source()
    )
    assert document.text == "One\nTwo"


@pytest.mark.integration
def test_native_html_collection_versions_304_failure_and_retirement(
    databases, tmp_path, monkeypatch
):
    writer, reader, roles = databases
    configured = source(url="http://example.invalid/page")
    collector = Database(roles["collector"])
    store = EvidenceStore(tmp_path / "objects")
    install(monkeypatch, ResponseWire(200, HTML, [(b"etag", b'"v1"')]))
    first = collect(configured, collector, store, due_only=True)
    assert first["status"] == "success" and first["documents"] == 1
    first_id = first["document_ids"][0]
    service = ReadService(reader, EvidenceStore(store.root, read_only=True))
    original = service.document(first_id)
    assert original["text"] == TEXT and original["published_at"] is None
    evidence = service.evidence(original["snapshot_id"])
    assert evidence["extractor"] == "static-html/1"
    assert evidence["raw_sha256"] == digest(HTML) and store.get(evidence["raw_sha256"]) == HTML
    assert run_once(writer, store)["status"] == "succeeded"
    with writer.connect() as conn:
        chunk = conn.execute("SELECT * FROM ow.chunks WHERE document_id=%s", (first_id,)).fetchone()
    assert chunk["body"] == TEXT[chunk["start_offset"] : chunk["end_offset"]]
    assert chunk["text_sha256"] == digest(chunk["body"].encode())
    due(writer)
    unchanged = ResponseWire(304, b"", [(b"etag", b'"v1"')])
    install(monkeypatch, unchanged)
    assert collect_due([configured], collector, store)["results"][0]["documents"] == 0
    assert dict(unchanged.request.headers)[b"if-none-match"] == b'"v1"'
    due(writer)
    alternate = HTML.replace(b"<meta name=", b"<!-- raw changed --><meta name=")
    install(monkeypatch, ResponseWire(200, alternate))
    assert collect(configured, collector, store, due_only=True)["document_ids"] == [first_id]
    due(writer)
    changed = HTML.replace(b"First", b"Changed")
    install(monkeypatch, ResponseWire(200, changed))
    new_id = collect(configured, collector, store, due_only=True)["document_ids"][0]
    assert new_id != first_id and service.document(first_id)["text"] == TEXT
    due(writer)
    install(monkeypatch, ResponseWire(200, b"not an HTML document"))
    with pytest.raises(WorkbenchError, match="^HTML_STRUCTURE_UNSUPPORTED$"):
        collect(configured, collector, store, due_only=True)
    with writer.connect() as conn:
        failed = conn.execute(
            "SELECT status,error_code FROM ow.collection_runs ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        state = conn.execute(
            "SELECT raw_sha256,failures FROM ow.collection_state WHERE source_id=%s",
            (configured.source_id,),
        ).fetchone()
    assert failed == {"status": "failed", "error_code": "HTML_STRUCTURE_UNSUPPORTED"}
    assert state["raw_sha256"] == digest(changed) and state["failures"] == 1
    assert reader.search("Changed")[0]["document_id"] == new_id
    lifecycle.apply(
        Database(roles["lifecycle"]),
        lifecycle.Change(
            action="retire",
            document_id=new_id,
            operation_id="html-retire",
            actor="fixture",
            rationale="Synthetic suppression",
        ),
    )
    due(writer)
    install(monkeypatch, ResponseWire(200, changed.replace(b"Changed", b"Later")))
    suppressed = collect(configured, collector, store, due_only=True)
    assert suppressed["documents"] == 0 and suppressed["suppressed_documents"] == 1
    assert reader.search("Later") == []


@pytest.mark.integration
def test_native_tls_html_to_actual_mcp(databases, tmp_path, monkeypatch):
    writer, reader, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    certificates = generate_certificates(tmp_path / "certificates")
    wire = (
        b"HTTP/1.1 200 OK\r\nContent-Length: "
        + str(len(HTML)).encode()
        + b"\r\nConnection: close\r\n\r\n"
        + HTML
    )
    with tls_peer(monkeypatch, certificates, wire=wire) as peer:
        result = collect(source(), Database(roles["collector"]), store)
    assert result["status"] == "success" and result["documents"] == 1
    assert peer.sni == ["feed.fixture.invalid"] and len(peer.requests) == 1
    identifier = result["document_ids"][0]
    assert run_once(writer, store)["status"] == "succeeded"

    async def read():
        params = StdioServerParameters(
            command=sys.executable,
            args=["-I", "-m", "osint_workbench.cli", "mcp"],
            env={
                "PATH": os.environ.get("PATH", ""),
                "OW_READER_DSN": roles["reader"],
                "OW_EVIDENCE_ROOT": str(store.root),
            },
        )
        async with (
            stdio_client(params) as (incoming, outgoing),
            ClientSession(incoming, outgoing) as client,
        ):
            await client.initialize()
            response = await client.call_tool("get_document", {"document_id": identifier})
            assert not response.is_error
            document = json.loads(response.content[0].text)
            assert document["text"] == TEXT and document["integrity"] == "verified"
            evidence = await client.call_tool(
                "get_evidence", {"snapshot_id": document["snapshot_id"]}
            )
            assert not evidence.is_error
            assert json.loads(evidence.content[0].text)["raw_sha256"] == digest(HTML)

    asyncio.run(read())


@pytest.mark.integration
def test_native_adapter_switch_resets_validators_and_restores_legacy_identity(
    databases, tmp_path, monkeypatch
):
    writer, reader, roles = databases
    collector = Database(roles["collector"])
    store = EvidenceStore(tmp_path / "objects")
    rss = Source(source_id="switch-fixture", url="http://example.invalid/feed", poll_seconds=60)
    static = source(source_id=rss.source_id, url=rss.url)
    original_hash = digest(
        json.dumps([rss.url, "feedparser-html/2", "identity", "osint-workbench/0.1"]).encode()
    )
    first = ResponseWire(200, FEED, [(b"etag", b'"rss"')])
    install(monkeypatch, first)
    assert collect_due([rss], collector, store)["results"][0]["documents"] == 2
    # Both switches must be selected immediately despite a future next_attempt;
    # their validators and body pointers belong to a different representation.
    for configured, raw, expected_hash in (
        (static, HTML, resource_identity(static)),
        (rss, FEED, original_hash),
    ):
        response = ResponseWire(200, raw, [(b"etag", b'"new"')])
        install(monkeypatch, response)
        result = collect_due([configured], collector, store)
        assert result["results"][0]["status"] == "success"
        assert b"if-none-match" not in dict(response.request.headers)
        with writer.connect() as conn:
            state = conn.execute(
                "SELECT resource_sha256,raw_sha256 FROM ow.collection_state WHERE source_id=%s",
                (rss.source_id,),
            ).fetchone()
        assert state == {"resource_sha256": expected_hash, "raw_sha256": digest(raw)}
    assert resource_identity(rss) == original_hash != resource_identity(static)
