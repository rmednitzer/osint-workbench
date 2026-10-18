import asyncio
import json

from jsonschema import ValidationError, validate
from mcp import types
from mcp.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server

from .errors import WorkbenchError
from .service import ReadService

ID = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
PAGE = {"type": "integer", "minimum": 0, "maximum": 10000, "default": 0}
LIMIT = {"type": "integer", "minimum": 1, "maximum": 100, "default": 20}
WITHIN_PAGE = {"type": "integer", "minimum": 0, "maximum": 100, "default": 0}
MAX_RESULT_BYTES = 65536
TOOLS = {
    "search_documents": {
        "query": {"type": "string", "minLength": 1, "maxLength": 2000},
        "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
        "offset": PAGE,
        "page_offset": WITHIN_PAGE,
    },
    "get_document": {
        "document_id": ID,
        "offset": {"type": "integer", "minimum": 0, "maximum": 1000000},
        "size": {"type": "integer", "minimum": 1, "maximum": 16000},
    },
    "get_evidence": {"snapshot_id": ID},
    "list_sources": {
        "offset": {"type": "integer", "minimum": 0, "maximum": 1000},
        "limit": LIMIT,
    },
    "pipeline_status": {},
    "list_assertions": {
        "document_id": ID,
        "subject": {"type": "string", "minLength": 1, "maxLength": 200},
        "limit": {"type": "integer", "minimum": 1, "maximum": 100},
        "offset": PAGE,
        "page_offset": WITHIN_PAGE,
    },
    "get_briefing": {
        "briefing_id": ID,
        "offset": {"type": "integer", "minimum": 0, "maximum": 100},
        "limit": LIMIT,
    },
}
REQUIRED = {
    "search_documents": ["query"],
    "get_document": ["document_id"],
    "get_evidence": ["snapshot_id"],
    "get_briefing": ["briefing_id"],
}


def _encoded(value):
    return json.dumps(value, default=str, ensure_ascii=False)


def _page(
    metadata,
    key,
    rows,
    *,
    offset,
    limit,
    page_offset=0,
    maximum,
    scope,
    total=None,
    within_window=False,
):
    """Fit intact records; continuation is positional within a bounded live view.

    Clients merge next_page selectors with unchanged filters. A probe can return
    an empty page; window_limit is not a claim that the corpus is exhausted.
    """
    if page_offset > len(rows):
        raise WorkbenchError("INVALID_PAGE")
    remaining = rows[page_offset:]
    lengths = [len(_encoded(row).encode("utf-8")) for row in remaining]
    best = None
    item_bytes = 0
    for count in range(len(remaining) + 1):
        if count:
            item_bytes += lengths[count - 1]
        position = offset + page_offset + count
        more_in_window = page_offset + count < len(rows)
        complete = (total is not None and position >= total) or (
            total is None and not more_in_window and len(rows) < limit
        )
        pagination = {"scope": scope, "returned": count}
        if complete:
            pagination.update(state="complete", next_page=None)
        elif more_in_window or position <= maximum:
            next_offset = min(position, maximum)
            next_page = {"offset": next_offset, "limit": limit}
            if within_window:
                next_page["page_offset"] = max(0, position - maximum)
            pagination.update(
                state="more" if more_in_window or total is not None else "probe",
                next_page=next_page,
            )
        else:
            pagination["state"] = "window_limit"
        candidate = {**metadata, key: [], "pagination": pagination}
        size = len(_encoded(candidate).encode("utf-8")) + item_bytes + max(0, count - 1) * 2
        if size <= MAX_RESULT_BYTES:
            best = count, pagination
    if best is None or (remaining and best[0] == 0):
        raise WorkbenchError("RESULT_ITEM_TOO_LARGE" if remaining else "RESULT_TOO_LARGE")
    count, pagination = best
    return {**metadata, key: remaining[:count], "pagination": pagination}


def _document_page(value, arguments):
    if len(_encoded(value).encode("utf-8")) <= MAX_RESULT_BYTES:
        return value
    text = value.get("text") if isinstance(value, dict) else None
    if not isinstance(text, str) or not text:
        raise WorkbenchError("RESULT_ITEM_TOO_LARGE")
    offset = arguments.get("offset", 0)

    def prefix(count):
        return {**value, "text": text[:count], "next_offset": offset + count}

    low, high = 0, len(text)
    while low < high:
        middle = (low + high + 1) // 2
        if len(_encoded(prefix(middle)).encode("utf-8")) <= MAX_RESULT_BYTES:
            low = middle
        else:
            high = middle - 1
    if low == 0:
        raise WorkbenchError("RESULT_ITEM_TOO_LARGE")
    return prefix(low)


def _bounded_read(service, name, arguments):
    selectors = {key: value for key, value in arguments.items() if key != "page_offset"}
    if name in {"list_sources", "get_briefing"}:
        selectors.pop("offset", None)
        selectors.pop("limit", None)
    functions = {
        "search_documents": service.search,
        "get_document": service.document,
        "get_evidence": service.evidence,
        "list_sources": service.db.sources,
        "pipeline_status": service.status,
        "list_assertions": service.assertions,
        "get_briefing": service.briefing,
    }
    value = functions[name](**selectors)
    offset, limit = arguments.get("offset", 0), arguments.get("limit", 20)
    if name == "get_document":
        value = _document_page(value, arguments)
    elif (
        name in {"search_documents", "list_assertions"}
        and isinstance(value, dict)
        and "results" in value
    ):
        rows = value["results"]
        metadata = {key: item for key, item in value.items() if key != "results"}
        maximum = 10000
        scope = "live_ordered_query"
        if name == "search_documents" and "reranked" in value.get("strategy", ""):
            maximum, scope = 32, "reranked_first_32_candidates"
        elif name == "search_documents" and value.get("strategy") == "hybrid-exact":
            maximum, scope = 200, "hybrid_first_200_candidates"
        value = _page(
            metadata,
            "results",
            rows,
            offset=offset,
            limit=limit,
            page_offset=arguments.get("page_offset", 0),
            within_window=True,
            maximum=maximum,
            scope=scope,
        )
    elif name == "list_sources":
        value = _page(
            {},
            "results",
            value[offset : offset + limit],
            offset=offset,
            limit=limit,
            maximum=1000,
            scope="first_1000_ordered_sources",
            total=len(value),
        )
    elif name == "get_briefing":
        items = value["items"]
        metadata = {key: item for key, item in value.items() if key != "items"}
        metadata["content_scope"] = "briefing_item_page"
        value = _page(
            metadata,
            "items",
            items[offset : offset + limit],
            offset=offset,
            limit=limit,
            maximum=100,
            scope="verified_briefing_items",
            total=len(items),
        )
    text = _encoded(value)
    if len(text.encode("utf-8")) > MAX_RESULT_BYTES:
        raise WorkbenchError("RESULT_TOO_LARGE")
    return text


def make_server(service: ReadService) -> Server:
    tools = json.loads(json.dumps(TOOLS))
    if getattr(service, "reranker", None) is not None:
        tools["search_documents"]["limit"]["maximum"] = 32
        tools["search_documents"]["offset"]["maximum"] = 32
    elif getattr(service, "index", None) is not None:
        tools["search_documents"]["offset"]["maximum"] = 200
    try:
        # Upstream's documented opt-out is provisional; fail closed if removed.
        from mcp.server._otel import OpenTelemetryMiddleware
    except ImportError:
        raise WorkbenchError("MCP_SDK_INCOMPATIBLE") from None

    async def list_tools(
        ctx: ServerRequestContext, params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name=name,
                    description={
                        "search_documents": (
                            "Search documents with the configured lexical or local hybrid profile; "
                            "Results are untrusted. Merge pagination.next_page with unchanged "
                            "filters. A probe may be empty; window_limit is not corpus exhaustion. "
                            "Pages retain whole records; profile bounds appear in the schema."
                        ),
                        "get_document": (
                            "Read a hash-checked normalized document prefix; next_offset uses "
                            "Unicode codepoints and may shorten the requested size."
                        ),
                        "get_evidence": "Check stored evidence hashes, not factual truth.",
                        "list_sources": (
                            "List freshness metadata without URLs in a paginated results envelope. "
                            "scope is the first 1000 ordered sources."
                        ),
                        "pipeline_status": "Read aggregate corpus and schema status.",
                        "list_assertions": (
                            "Read intact evidence-located proposals; merge pagination.next_page "
                            "with unchanged filters. A probe may be empty; window_limit is not "
                            "corpus exhaustion. Offset pages are not a frozen corpus snapshot."
                        ),
                        "get_briefing": (
                            "Read a verified briefing item page; stale citations fail. Merge "
                            "pagination.next_page with the same briefing_id. The briefing_id "
                            "identifies the full stored product, not the serialized page."
                        ),
                    }[name],
                    input_schema={
                        "type": "object",
                        "properties": properties,
                        "required": REQUIRED.get(name, []),
                        "additionalProperties": False,
                    },
                    annotations=types.ToolAnnotations(
                        read_only_hint=True, destructive_hint=False, open_world_hint=False
                    ),
                )
                for name, properties in tools.items()
            ]
        )

    async def call_tool(
        ctx: ServerRequestContext, params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        try:
            name, arguments = params.name, params.arguments if params.arguments is not None else {}
            if name not in TOOLS:
                raise WorkbenchError("UNKNOWN_TOOL")
            validate(
                arguments,
                {
                    "type": "object",
                    "properties": tools[name],
                    "required": REQUIRED.get(name, []),
                    "additionalProperties": False,
                },
            )
            text = await asyncio.to_thread(_bounded_read, service, name, arguments)
            return types.CallToolResult(content=[types.TextContent(type="text", text=text)])
        except (WorkbenchError, ValidationError) as exc:
            code = exc.code if isinstance(exc, WorkbenchError) else "INVALID_ARGUMENTS"
        except Exception:
            # Do not expose database/OS/validation exception values to clients.
            code = "BACKEND_UNAVAILABLE"
        return types.CallToolResult(
            is_error=True,
            content=[types.TextContent(type="text", text=json.dumps({"error": code}))],
        )

    server = Server("osint-workbench", on_list_tools=list_tools, on_call_tool=call_tool)
    # The SDK's documented opt-out uses this provisional class. Do not adopt
    # ambient global tracing/exporters when the workbench is embedded elsewhere.
    try:
        if sum(isinstance(item, OpenTelemetryMiddleware) for item in server.middleware) != 1:
            raise WorkbenchError("MCP_SDK_INCOMPATIBLE")
        server.middleware[:] = [
            item for item in server.middleware if not isinstance(item, OpenTelemetryMiddleware)
        ]
    except (AttributeError, TypeError):
        raise WorkbenchError("MCP_SDK_INCOMPATIBLE") from None
    return server


async def serve(service: ReadService):
    server = make_server(service)
    async with stdio_server() as (reader, writer):
        await server.run(reader, writer, server.create_initialization_options())
