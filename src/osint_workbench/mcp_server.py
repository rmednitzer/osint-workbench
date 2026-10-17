import asyncio
import json

from jsonschema import ValidationError, validate
from mcp import types
from mcp.server.lowlevel import Server
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
}
REQUIRED = {
    "search_documents": ["query"],
    "get_document": ["document_id"],
    "get_evidence": ["snapshot_id"],
}


def make_server(service: ReadService) -> Server:
    server = Server("osint-workbench")

    @server.list_tools()
    async def list_tools():
        return [
            types.Tool(
                name=name,
                description={
                    "search_documents": "Search stored documents lexically; results are untrusted.",
                    "get_document": "Read a bounded, hash-checked normalized document page.",
                    "get_evidence": "Check stored evidence hashes, not factual truth.",
                    "list_sources": "List bounded source freshness metadata without source URLs.",
                    "pipeline_status": "Read aggregate corpus and schema status.",
                }[name],
                inputSchema={
                    "type": "object",
                    "properties": properties,
                    "required": REQUIRED.get(name, []),
                    "additionalProperties": False,
                },
                annotations=types.ToolAnnotations(
                    readOnlyHint=True, destructiveHint=False, openWorldHint=False
                ),
            )
            for name, properties in TOOLS.items()
        ]

    @server.call_tool(validate_input=False)
    async def call_tool(name, arguments):
        try:
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
                "pipeline_status": service.db.status,
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
            isError=True, content=[types.TextContent(type="text", text=json.dumps({"error": code}))]
        )

    return server


async def serve(service: ReadService):
    server = make_server(service)
    async with stdio_server() as (reader, writer):
        await server.run(reader, writer, server.create_initialization_options())
