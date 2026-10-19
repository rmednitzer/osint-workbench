"""Byte-aware MCP projections; synthetic records, no database or live model calls."""

import asyncio
import hashlib
import json

import pytest
from mcp import Client

from osint_workbench import mcp_server
from osint_workbench.database import Database
from osint_workbench.errors import WorkbenchError


def assertion(index):
    return {
        "assertion_id": f"{index:064x}",
        "document_id": "d" * 64,
        "subject": "\x01" * 200,
        "object": "🧭" * 200,
        "statement": "\x01" * 1000,
        "quote": "\x01" * 4000,
        "start_offset": index,
        "end_offset": index + 4000,
        "polarity": "uncertain",
        "predicate": "mentions",
        "review_state": "accepted",
    }


class Records:
    reranker = index = None

    def __init__(self, count=100, origin=0):
        self.db = self
        self.origin = origin
        self.rows = [assertion(i) for i in range(origin, origin + count)]
        self.body = ('🧭\x01"\\é' * 6000)[:25000]
        self.sources_rows = [
            {
                "source_id": f"synthetic-{i:04}" + "x" * 80,
                "last_error": "SOURCE_HTTP_ERROR",
                "freshness_seconds": 31536000,
                "last_attempt": "2026-10-18T00:00:00+00:00",
                "last_success": "2026-10-18T00:00:00+00:00",
                "enabled": True,
            }
            for i in range(1000)
        ]
        self.full_briefing = {
            "schema_version": 1,
            "kind": "reviewed_assertion_digest",
            "corpus_cutoff": "2026-10-18T00:00:00+00:00",
            "selected_documents": ["d" * 64],
            "diversity": "not_assessed",
            "degraded": False,
            "omission_reason": None,
            "items": [
                {
                    key: value
                    for key, value in row.items()
                    if key not in {"subject", "object", "predicate", "review_state"}
                }
                for row in self.rows
            ],
        }
        self.briefing_id = hashlib.sha256(
            json.dumps(self.full_briefing, sort_keys=True).encode()
        ).hexdigest()

    def search(self, query, limit=20, offset=0):
        rows = self.rows[offset - self.origin : offset - self.origin + limit]
        return {
            "strategy": "lexical",
            "degraded": False,
            "results": [
                {
                    "document_id": row["assertion_id"],
                    "snapshot_id": "b" * 64,
                    "source_id": "synthetic",
                    "title": "\x01" * 2000,
                    "excerpt": "🧭" * 1000,
                    "rank": 1.0,
                }
                for row in rows
            ],
        }

    def assertions(self, document_id=None, subject=None, limit=20, offset=0):
        return {
            "ontology_version": "assertion-proposals/2",
            "entity_resolution": "not-performed",
            "results": self.rows[offset - self.origin : offset - self.origin + limit],
        }

    def document(self, document_id, offset=0, size=8000):
        text = self.body[offset : offset + size]
        end = offset + len(text)
        return {
            "document_id": document_id,
            "snapshot_id": "b" * 64,
            "title": "\x01" * 2000,
            "text": text,
            "total_characters": len(self.body),
            "next_offset": end if end < len(self.body) else None,
            "integrity": "verified",
        }

    def briefing(self, briefing_id):
        return {"briefing_id": briefing_id, **self.full_briefing}

    def sources(self):
        return self.sources_rows

    def status(self):
        return {"documents": len(self.rows)}

    def evidence(self, snapshot_id):
        return {"snapshot_id": snapshot_id, "integrity": "verified"}


def read(service, name, arguments):
    raw = mcp_server._bounded_read(service, name, arguments)
    assert len(raw.encode("utf-8")) <= 65536
    return json.loads(raw)


@pytest.mark.parametrize("tool", ["search_documents", "list_assertions"])
def test_worst_case_records_fit_and_continuations_preserve_order_and_every_field(tool):
    service = Records()
    arguments = {"query": "synthetic"} if tool == "search_documents" else {"subject": "x"}
    arguments["limit"] = 100
    expected = getattr(service, "search" if tool == "search_documents" else "assertions")(
        **arguments
    )["results"]
    assert len(json.dumps(expected, ensure_ascii=False).encode()) > 65536
    rows = []
    for _ in range(110):
        page = read(service, tool, arguments)
        assert page["results"]
        rows.extend(page["results"])
        if page["pagination"]["next_page"] is None:
            assert page["pagination"]["state"] == "complete"
            break
        arguments.update(page["pagination"]["next_page"])
    else:
        pytest.fail("continuation did not terminate")
    assert rows == expected


def test_offset_ceiling_retains_access_to_byte_split_last_window():
    service = Records(origin=10000)
    args = {"query": "synthetic", "offset": 10000, "limit": 100}
    rows = []
    for _ in range(110):
        page = read(service, "search_documents", args)
        assert page["results"]
        rows.extend(page["results"])
        if page["pagination"]["state"] == "window_limit":
            assert "next_page" not in page["pagination"]
            break
        next_page = page["pagination"]["next_page"]
        assert next_page["offset"] == 10000 and next_page["page_offset"] > args.get(
            "page_offset", 0
        )
        args.update(next_page)
    else:
        pytest.fail("bounded result window did not terminate")
    assert [row["document_id"] for row in rows] == [f"{i:064x}" for i in range(10000, 10100)]


def test_exact_full_window_is_a_probe_not_a_false_exhaustion_claim():
    service = Records(count=1)
    first = read(service, "search_documents", {"query": "synthetic", "limit": 1})
    assert first["pagination"]["state"] == "probe"
    following = read(
        service, "search_documents", {"query": "synthetic", **first["pagination"]["next_page"]}
    )
    assert following["results"] == []
    assert following["pagination"]["state"] == "complete"
    assert following["pagination"]["next_page"] is None


def test_source_and_briefing_pages_are_complete_projections_not_truncated_evidence():
    service = Records()
    for tool, key, arguments, expected in [
        ("list_sources", "results", {}, service.sources_rows),
        (
            "get_briefing",
            "items",
            {"briefing_id": service.briefing_id, "limit": 100},
            service.full_briefing["items"],
        ),
    ]:
        assert len(json.dumps(expected, ensure_ascii=False).encode()) > 65536
        collected = []
        for _ in range(110):
            page = read(service, tool, arguments)
            collected.extend(page[key])
            if tool == "get_briefing":
                assert page["briefing_id"] == service.briefing_id
                assert page["content_scope"] == "briefing_item_page"
                assert page["selected_documents"] == service.full_briefing["selected_documents"]
            if page["pagination"]["next_page"] is None:
                break
            arguments.update(page["pagination"]["next_page"])
        else:
            pytest.fail("item pagination did not terminate")
        assert collected == expected


@pytest.mark.parametrize("character", ["🧭", "\x01", '"\\'])
def test_document_byte_prefix_uses_codepoint_offsets_without_loss(character):
    service = Records(count=0)
    service.body = character * 20000
    args = {"document_id": "a" * 64, "size": 16000}
    observed = ""
    for _ in range(20):
        page = read(service, "get_document", args)
        assert page["snapshot_id"] == "b" * 64 and page["integrity"] == "verified"
        assert page["total_characters"] == len(service.body)
        observed += page["text"]
        if page["next_offset"] is None:
            break
        assert page["next_offset"] == len(observed) > args.get("offset", 0)
        args["offset"] = page["next_offset"]
    else:
        pytest.fail("document pages did not terminate")
    assert observed == service.body


def test_one_oversized_record_fails_without_clipping_quote_or_claiming_empty_success():
    service = Records(count=1)
    service.rows[0]["quote"] = "🧭" * 20000  # Corrupt/out-of-contract backend fixture.
    with pytest.raises(WorkbenchError, match="^RESULT_ITEM_TOO_LARGE$"):
        read(service, "list_assertions", {})


@pytest.mark.parametrize("mode", ["2026-07-28", "legacy"])
def test_actual_sdk_paginates_all_large_reads_and_preserves_seven_tools(mode):
    async def run():
        service = Records()
        async with Client(mcp_server.make_server(service), mode=mode) as client:
            assert len((await client.list_tools()).tools) == 7
            for name, args in [
                ("search_documents", {"query": "synthetic", "limit": 100}),
                ("list_assertions", {"limit": 100}),
                ("list_sources", {"limit": 100}),
                ("get_document", {"document_id": "a" * 64, "size": 16000}),
                ("get_briefing", {"briefing_id": service.briefing_id, "limit": 100}),
            ]:
                result = await client.call_tool(name, args)
                assert not result.is_error
                assert len(result.content[0].text.encode("utf-8")) <= 65536
                assert json.loads(result.content[0].text)

    asyncio.run(run())


def test_continuation_resets_a_consumed_within_window_offset():
    service = Records(count=100)
    page = read(service, "search_documents", {"query": "synthetic", "limit": 100, "page_offset": 1})
    assert page["results"][0]["document_id"] == f"{1:064x}"
    assert page["pagination"]["next_page"]["page_offset"] == 0
    args = {"query": "synthetic", "page_offset": 1, **page["pagination"]["next_page"]}
    following = read(service, "search_documents", args)
    assert int(following["results"][0]["document_id"], 16) == len(page["results"]) + 1


def test_unpageable_document_metadata_is_not_silently_removed():
    service = Records(count=1)
    original = service.document

    def corrupted(**arguments):
        return {**original(**arguments), "title": "🧭" * 20000}

    service.document = corrupted
    with pytest.raises(WorkbenchError, match="^RESULT_ITEM_TOO_LARGE$"):
        read(service, "get_document", {"document_id": "a" * 64})


@pytest.mark.parametrize(
    "profile,limit,offset", [("lexical", 100, 10000), ("hybrid", 100, 200), ("rerank", 32, 32)]
)
def test_advertised_search_limits_match_configured_profile(profile, limit, offset):
    async def run():
        service = Records(count=0)
        service.index = object() if profile == "hybrid" else None
        service.reranker = object() if profile == "rerank" else None
        async with Client(mcp_server.make_server(service)) as client:
            tool = next(
                tool
                for tool in (await client.list_tools()).tools
                if tool.name == "search_documents"
            )
            assert tool.input_schema["properties"]["limit"]["maximum"] == limit
            assert tool.input_schema["properties"]["offset"]["maximum"] == offset

    asyncio.run(run())


@pytest.mark.integration
@pytest.mark.parametrize("mode", ["2026-07-28", "legacy"])
def test_native_reader_pages_valid_large_evidence_and_rechecks_full_briefing(
    databases, tmp_path, mode
):
    from osint_workbench import intelligence
    from osint_workbench.contracts import DocumentInput
    from osint_workbench.evidence import EvidenceStore
    from osint_workbench.service import ReadService
    from tests.test_intelligence import FixtureGenerator

    writer, reader, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    quotes = ["\x01" * 3999 + letter for letter in "ABC"]
    body = "storage " + "".join(quotes)
    documents = [
        writer.ingest(
            DocumentInput(
                source_id="fixture", external_id=f"large-{i}", title="\x01" * 2000, text=body
            ),
            body.encode(),
            store,
        )
        for i in range(4)
    ]
    claims = [
        {
            "subject": "\x01" * 200,
            "predicate": "mentions",
            "object": "🧭" * 200,
            "statement": "\x01" * 1000,
            "polarity": "uncertain",
            "quote": quote,
        }
        for quote in quotes
    ]
    generator = FixtureGenerator(claims)
    intelligence.enqueue(writer, generator, documents[0])
    assert intelligence.enrich_once(writer, store, generator)["proposals"] == 3
    for row in intelligence.assertions(reader)["results"]:
        intelligence.review(
            Database(roles["reviewer"]),
            row["assertion_id"],
            "accept",
            "fixture",
            "synthetic review",
        )
    briefing = intelligence.create_briefing(writer, [documents[0]])
    service = ReadService(reader, EvidenceStore(store.root, read_only=True))

    async def run():
        async with Client(mcp_server.make_server(service), mode=mode) as client:

            async def page(name, args):
                result = await client.call_tool(name, args)
                assert not result.is_error
                assert len(result.content[0].text.encode()) <= 65536
                return json.loads(result.content[0].text)

            for name, args, expected in [
                (
                    "search_documents",
                    {"query": "storage", "limit": 100},
                    service.search("storage", 100)["results"],
                ),
                (
                    "list_assertions",
                    {"document_id": documents[0], "limit": 100},
                    service.assertions(document_id=documents[0], limit=100)["results"],
                ),
            ]:
                assert len(json.dumps(expected, default=str, ensure_ascii=False).encode()) > 65536
                collected = []
                for _ in range(10):
                    value = await page(name, args)
                    collected.extend(value["results"])
                    if value["pagination"]["next_page"] is None:
                        break
                    args.update(value["pagination"]["next_page"])
                else:
                    pytest.fail("native pages did not terminate")
                assert collected == expected
            text = ""
            args = {"document_id": documents[0], "size": 16000}
            for _ in range(10):
                value = await page("get_document", args)
                assert value["integrity"] == "verified"
                text += value["text"]
                if value["next_offset"] is None:
                    break
                assert value["next_offset"] == len(text)
                args["offset"] = value["next_offset"]
            assert text == body
            first = await page(
                "get_briefing", {"briefing_id": briefing["briefing_id"], "limit": 100}
            )
            assert 0 < len(first["items"]) < 3
            assert first["content_scope"] == "briefing_item_page"
            intelligence.review(
                Database(roles["reviewer"]),
                first["items"][0]["assertion_id"],
                "reject",
                "fixture",
                "withdraw",
            )
            stale = await client.call_tool(
                "get_briefing",
                {"briefing_id": briefing["briefing_id"], **first["pagination"]["next_page"]},
            )
            assert stale.is_error and json.loads(stale.content[0].text) == {
                "error": "BRIEFING_STALE"
            }

    asyncio.run(run())
