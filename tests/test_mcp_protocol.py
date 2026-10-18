"""Actual SDK stdio boundaries; synthetic service is separate from native SQL tests."""

import asyncio
import builtins
import contextlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from mcp import Client, StdioServerParameters
from mcp.server import Server
from mcp.server._otel import OpenTelemetryMiddleware

from osint_workbench import mcp_server
from osint_workbench.errors import WorkbenchError

SERVER = r"""
import asyncio, json, os, subprocess, sys, time
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from osint_workbench.errors import WorkbenchError
from osint_workbench.mcp_server import serve
root=Path(sys.argv[2])
class Service:
    def __init__(self): self.db=self
    def search(self,query,limit=20,offset=0):
        if query=='failure': raise RuntimeError('synthetic-secret-dsn-and-path-canary')
        if query=='refused': raise WorkbenchError('FIXTURE_REFUSED')
        if query=='oversize': return {'value':'ä'*40000}
        if query=='stdout':
            os.write(1,b'synthetic fixture stdout noise\n')
            return {'protocol_healthy':True}
        if query=='child':
            p=subprocess.run([sys.executable,'-I','-c',
                'import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())'],
                input=b'synthetic child pipe',stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,timeout=2,check=True)
            return {'child':p.stdout.decode(),'stderr_empty':not p.stderr}
        if query=='block':
            (root/'entered').write_text('entered')
            deadline=time.monotonic()+5
            while not (root/'release').exists() and time.monotonic()<deadline:
                time.sleep(.01)
            (root/'finished').write_text('finished')
            return {'value':'synthetic-cancelled-result-canary'}
        return {'results':[{'document_id':'a'*64,'text':'Straße storage'}]}
    def document(self,document_id,offset=0,size=16000): return {'document_id':document_id}
    def evidence(self,snapshot_id): return {'snapshot_id':snapshot_id,'integrity':'verified'}
    def sources(self): return [{'source_id':'synthetic'}]
    def status(self): return {'documents':1}
    def assertions(self,document_id=None,subject=None,limit=100,offset=0): return []
    def briefing(self,briefing_id): return {'briefing_id':briefing_id,'items':[]}
asyncio.run(serve(Service()))
"""


def parameters(tmp_path):
    return StdioServerParameters(
        command=sys.executable,
        args=[
            "-I",
            "-c",
            SERVER,
            str(Path(mcp_server.__file__).resolve().parents[1]),
            str(tmp_path),
        ],
    )


def decoded(result):
    assert len(result.content) == 1 and result.content[0].type == "text"
    return json.loads(result.content[0].text)


@pytest.mark.parametrize("mode", ["2026-07-28", "legacy"], ids=["modern", "legacy"])
def test_actual_stdio_preserves_seven_read_tools_schemas_errors_and_native_child_pipes(
    tmp_path, mode
):
    async def run():
        async with Client(parameters(tmp_path), mode=mode, read_timeout_seconds=5) as client:
            assert client.protocol_version == ("2026-07-28" if mode != "legacy" else "2025-11-25")
            tools = (await client.list_tools()).tools
            assert {tool.name for tool in tools} == set(mcp_server.TOOLS)
            for tool in tools:
                assert tool.input_schema["additionalProperties"] is False
                assert tool.annotations.read_only_hint is True
                assert tool.annotations.destructive_hint is False
                assert tool.annotations.open_world_hint is False
                wire = tool.model_dump(by_alias=True)
                assert "inputSchema" in wire and "input_schema" not in wire
            requests = {
                "search_documents": {"query": "storage"},
                "get_document": {"document_id": "a" * 64},
                "get_evidence": {"snapshot_id": "b" * 64},
                "list_sources": {},
                "pipeline_status": {},
                "list_assertions": {"document_id": "a" * 64},
                "get_briefing": {"briefing_id": "c" * 64},
            }
            for tool, arguments in requests.items():
                result = await client.call_tool(tool, arguments)
                assert not result.is_error and decoded(result) is not None
            for tool, arguments, code in [
                ("shell", {"command": "synthetic-secret-canary"}, "UNKNOWN_TOOL"),
                (
                    "search_documents",
                    {"query": "storage", "shell": "forbidden"},
                    "INVALID_ARGUMENTS",
                ),
                ("search_documents", {"query": "storage", "limit": True}, "INVALID_ARGUMENTS"),
                ("search_documents", {"query": "storage", "limit": 101}, "INVALID_ARGUMENTS"),
                ("get_document", {"document_id": "../synthetic-private"}, "INVALID_ARGUMENTS"),
                ("search_documents", {}, "INVALID_ARGUMENTS"),
                ("search_documents", {"query": "failure"}, "BACKEND_UNAVAILABLE"),
                ("search_documents", {"query": "refused"}, "FIXTURE_REFUSED"),
                ("search_documents", {"query": "oversize"}, "RESULT_TOO_LARGE"),
            ]:
                result = await client.call_tool(tool, arguments)
                assert result.is_error and decoded(result) == {"error": code}
                assert "canary" not in result.model_dump_json()
            noise = await client.call_tool("search_documents", {"query": "stdout"})
            assert not noise.is_error and decoded(noise) == {"protocol_healthy": True}
            # Omitted arguments must retain v1 empty-object semantics for no-arg reads.
            result = await client.call_tool("pipeline_status")
            assert not result.is_error and decoded(result) == {"documents": 1}
            result = await client.call_tool("search_documents", {"query": "child"})
            assert not result.is_error and decoded(result) == {
                "child": "synthetic child pipe",
                "stderr_empty": True,
            }

    asyncio.run(run())


@pytest.mark.parametrize("mode", ["2026-07-28", "legacy"], ids=["modern", "legacy"])
def test_stdio_cancellation_leaves_thread_work_running_until_released_and_session_usable(
    tmp_path, mode
):
    async def wait_for_file(name):
        async with asyncio.timeout(3):
            while not (tmp_path / name).exists():
                await asyncio.sleep(0.01)

    async def run():
        async with Client(parameters(tmp_path), mode=mode, read_timeout_seconds=5) as client:
            request = asyncio.create_task(client.call_tool("search_documents", {"query": "block"}))
            try:
                await wait_for_file("entered")
                request.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await request
                assert not (tmp_path / "finished").exists()
                # Cancellation revoked the response; it did not stop the worker thread.
                status = await asyncio.wait_for(client.call_tool("pipeline_status"), timeout=2)
                assert not status.is_error and decoded(status) == {"documents": 1}
            finally:
                (tmp_path / "release").write_text("release")
                await wait_for_file("finished")
                if not request.done():
                    request.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await request
            status = await client.call_tool("pipeline_status")
            assert decoded(status) == {"documents": 1} and request.cancelled()

    asyncio.run(run())


def test_telemetry_optout_preserves_other_real_sdk_middleware(monkeypatch):
    seen = []

    class WithGuard(Server):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)

            async def guard(ctx, next_handler):
                seen.append(ctx.method)
                return await next_handler(ctx)

            self.middleware.append(guard)

    monkeypatch.setattr(mcp_server, "Server", WithGuard)
    service = SimpleNamespace(
        db=SimpleNamespace(sources=lambda: []),
        status=lambda: {"documents": 0},
        search=lambda **kwargs: [],
        document=lambda **kwargs: {},
        evidence=lambda **kwargs: {},
        assertions=lambda **kwargs: [],
        briefing=lambda **kwargs: {},
    )
    server = mcp_server.make_server(service)
    assert not any(isinstance(item, OpenTelemetryMiddleware) for item in server.middleware)

    async def run():
        async with Client(server, mode="2026-07-28") as client:
            result = await client.call_tool("pipeline_status")
            assert not result.is_error and decoded(result) == {"documents": 0}

    asyncio.run(run())
    assert "tools/call" in seen


def test_missing_telemetry_optout_class_fails_closed_without_import_details(monkeypatch):
    original_import = builtins.__import__

    def missing(name, *args, **kwargs):
        if name == "mcp.server._otel":
            raise ImportError("synthetic private import-path canary")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", missing)
    with pytest.raises(WorkbenchError, match="^MCP_SDK_INCOMPATIBLE$"):
        mcp_server.make_server(SimpleNamespace())


def test_configured_tracer_records_sdk_control_but_no_workbench_server_spans(monkeypatch):
    from mcp import types
    from mcp.shared import _otel
    from opentelemetry import trace

    observed = []

    class RecordingTracer(trace.NoOpTracer):
        @contextlib.contextmanager
        def start_as_current_span(self, name, *args, **kwargs):
            observed.append((name, kwargs.get("kind")))
            with super().start_as_current_span(name, *args, **kwargs) as span:
                yield span

    class Provider(trace.TracerProvider):
        def get_tracer(self, *args, **kwargs):
            return RecordingTracer()

    # A real API provider, with an in-memory recording tracer and no exporter.
    # Reset the SDK's cached tracer in this test so its global binding cannot leak
    # the temporary provider into later tests.
    monkeypatch.setattr(trace, "_TRACER_PROVIDER", Provider())
    monkeypatch.setattr(_otel, "_tracer", trace.get_tracer("mcp-python-sdk"))

    async def list_control(ctx, params):
        return types.ListToolsResult(tools=[])

    service = SimpleNamespace(
        db=SimpleNamespace(sources=lambda: []),
        status=lambda: {"documents": 0},
        search=lambda **kwargs: [],
        document=lambda **kwargs: {},
        evidence=lambda **kwargs: {},
        assertions=lambda **kwargs: [],
        briefing=lambda **kwargs: {},
    )

    async def run():
        async with Client(
            Server("positive-control", on_list_tools=list_control), mode="2026-07-28"
        ) as client:
            await client.list_tools()
        assert any(kind == trace.SpanKind.SERVER for _, kind in observed)
        observed.clear()
        async with Client(mcp_server.make_server(service), mode="2026-07-28") as client:
            await client.list_tools()
            result = await client.call_tool("pipeline_status")
            assert not result.is_error
        assert not any(kind == trace.SpanKind.SERVER for _, kind in observed)
        # The opt-out is per workbench server, not a global tracing shutdown.
        async with Client(
            Server("second-positive-control", on_list_tools=list_control), mode="2026-07-28"
        ) as client:
            await client.list_tools()
        assert any(kind == trace.SpanKind.SERVER for _, kind in observed)

    asyncio.run(run())


@pytest.mark.parametrize("mode", ["2026-07-28", "legacy"], ids=["modern", "legacy"])
def test_raw_stdio_malformed_params_are_sanitized_without_breaking_subsequent_reads(tmp_path, mode):
    from mcp import types

    async def run():
        params = parameters(tmp_path)
        child = await asyncio.create_subprocess_exec(
            params.command,
            *params.args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        async def exchange(identifier, method, arguments):
            if mode != "legacy":
                arguments = {
                    **arguments,
                    "_meta": {
                        types.PROTOCOL_VERSION_META_KEY: mode,
                        types.CLIENT_INFO_META_KEY: {"name": "synthetic-client", "version": "1"},
                        types.CLIENT_CAPABILITIES_META_KEY: {},
                    },
                }
            packet = {"jsonrpc": "2.0", "id": identifier, "method": method, "params": arguments}
            child.stdin.write((json.dumps(packet) + "\n").encode())
            await child.stdin.drain()
            line = await asyncio.wait_for(child.stdout.readline(), timeout=3)
            assert len(line) <= 65536 and line
            return json.loads(line)

        try:
            if mode == "legacy":
                initialized = await exchange(
                    1,
                    "initialize",
                    {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "clientInfo": {"name": "synthetic-client", "version": "1"},
                    },
                )
                assert "result" in initialized
                child.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
                await child.stdin.drain()
            refused = await exchange(
                2,
                "tools/call",
                {
                    "name": "pipeline_status",
                    "arguments": ["synthetic-private-argument-canary"],
                },
            )
            assert refused["error"]["code"] == -32602
            assert "canary" not in json.dumps(refused)
            healthy = await exchange(3, "tools/call", {"name": "pipeline_status"})
            assert json.loads(healthy["result"]["content"][0]["text"]) == {"documents": 1}
        finally:
            child.stdin.close()
            try:
                await asyncio.wait_for(child.wait(), timeout=3)
            except TimeoutError:
                child.kill()
                await asyncio.wait_for(child.wait(), timeout=3)
        errors = await child.stderr.read(65537)
        assert len(errors) <= 65536 and b"canary" not in errors

    asyncio.run(run())


@pytest.mark.parametrize("count", [0, 2], ids=["missing", "duplicate"])
def test_sdk_telemetry_middleware_contract_drift_fails_closed(monkeypatch, count):
    class Drifted(Server):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            telemetry = next(
                item for item in self.middleware if isinstance(item, OpenTelemetryMiddleware)
            )
            if count == 0:
                self.middleware.remove(telemetry)
            else:
                self.middleware.append(telemetry)

    monkeypatch.setattr(mcp_server, "Server", Drifted)
    with pytest.raises(WorkbenchError, match="^MCP_SDK_INCOMPATIBLE$"):
        mcp_server.make_server(SimpleNamespace())
