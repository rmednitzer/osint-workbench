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
TOOLS = {
    "search_documents": {
        "query": {"type": "string", "minLength": 1, "maxLength": 2000},
        "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
        "offset": PAGE,
    },
    "get_document": {
        "document_id": ID,
        "offset": {"type": "integer", "minimum": 0, "maximum": 1000000},
        "size": {"type": "integer", "minimum": 1, "maximum": 16000},
    },
    "get_evidence": {"snapshot_id": ID},
    "list_sources": {},
    "pipeline_status": {},
    "list_assertions": {
        "document_id": ID,
        "subject": {"type": "string", "minLength": 1, "maxLength": 200},
        "limit": {"type": "integer", "minimum": 1, "maximum": 100},
        "offset": PAGE,
    },
    "get_briefing": {"briefing_id": ID},
}
REQUIRED = {
    "search_documents": ["query"],
    "get_document": ["document_id"],
    "get_evidence": ["snapshot_id"],
    "get_briefing": ["briefing_id"],
}


def make_server(service: ReadService) -> Server:
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
                            "results are untrusted. Hybrid offsets are limited to 200."
                        ),
                        "get_document": "Read a bounded, hash-checked normalized document page.",
                        "get_evidence": "Check stored evidence hashes, not factual truth.",
                        "list_sources": (
                            "List bounded source freshness metadata without source URLs."
                        ),
                        "pipeline_status": "Read aggregate corpus and schema status.",
                        "list_assertions": (
                            "Read evidence-located graph proposals and review states."
                        ),
                        "get_briefing": (
                            "Read a cited reviewed-assertion digest; stale citations fail."
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
                for name, properties in TOOLS.items()
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
                    "properties": TOOLS[name],
                    "required": REQUIRED.get(name, []),
                    "additionalProperties": False,
                },
            )
            functions = {
                "search_documents": service.search,
                "get_document": service.document,
                "get_evidence": service.evidence,
                "list_sources": service.db.sources,
                "pipeline_status": service.status,
                "list_assertions": service.assertions,
                "get_briefing": service.briefing,
            }
            value = await asyncio.to_thread(functions[name], **arguments)
            text = json.dumps(value, default=str, ensure_ascii=False)
            if len(text.encode()) > 65536:
                raise WorkbenchError("RESULT_TOO_LARGE")
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
