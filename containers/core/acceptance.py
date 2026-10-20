"""Synthetic core checks. Invoked only by the explicit host profile harness."""

import asyncio
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import psycopg
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from psycopg import sql

from osint_workbench.database import Database, migrate
from osint_workbench.errors import WorkbenchError
from osint_workbench.evidence import EvidenceStore
from osint_workbench.service import ReadService

ROLE_KEYS = {
    "writer": "OW_WRITER_DSN",
    "worker": "OW_WRITER_DSN",
    "reader": "OW_READER_DSN",
    "lifecycle": "OW_LIFECYCLE_DSN",
    "recovery": "OW_RECOVERY_DSN",
    "migration": "OW_MIGRATION_DSN",
}
TOOLS = {
    "search_documents",
    "get_document",
    "get_evidence",
    "list_sources",
    "pipeline_status",
    "list_assertions",
    "get_briefing",
}


def require(value, code):
    if not value:
        raise RuntimeError(code)


def cli(*args, error=None):
    result = subprocess.run(
        [sys.executable, "-I", "-m", "osint_workbench.cli", *args],
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )
    if result.returncode:
        try:
            code = json.loads(result.stderr)["error"]
        except (ValueError, KeyError):
            raise RuntimeError("PROFILE_CLI_DIAGNOSTIC") from None
        if error is not None:
            require(code == error, "PROFILE_CLI_WRONG_REFUSAL")
            return {"refused": code}
        require(
            isinstance(code, str) and re.fullmatch("[A-Z_]{1,80}", code), "PROFILE_CLI_DIAGNOSTIC"
        )
        raise RuntimeError("PROFILE_CLI_" + code)
    require(error is None, "PROFILE_CLI_REFUSAL_MISSING")
    return json.loads(result.stdout)


def db():
    return Database(os.environ[ROLE_KEYS[os.environ["PROFILE_ROLE"]]])


async def mcp_checks(document, briefing, retired=None):
    env = {
        name: value
        for name, value in os.environ.items()
        if name in {"PATH", "OW_READER_DSN", "OW_EVIDENCE_ROOT", "PYTHONDONTWRITEBYTECODE"}
    }
    params = StdioServerParameters(
        command=sys.executable,
        args=["-I", "-m", "osint_workbench.cli", "mcp"],
        env=env,
    )
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        require(
            {tool.name for tool in (await session.list_tools()).tools} == TOOLS, "PROFILE_MCP_TOOLS"
        )
        calls = {
            "search_documents": {"query": "synthetic"},
            "get_document": {"document_id": document["document_id"]},
            "get_evidence": {"snapshot_id": document["snapshot_id"]},
            "list_sources": {},
            "pipeline_status": {},
            "list_assertions": {},
            "get_briefing": {"briefing_id": briefing},
        }
        for name, arguments in calls.items():
            result = await session.call_tool(name, arguments)
            require(not result.is_error, "PROFILE_MCP_RESULT")
        invalid = await session.call_tool(
            "search_documents", {"query": "synthetic", "url": "https://example.invalid"}
        )
        require(invalid.is_error, "PROFILE_MCP_SELECTOR")
        if retired:
            result = await session.call_tool("get_document", {"document_id": retired})
            require(result.is_error, "PROFILE_MCP_RETIRED")


def main():
    phase = sys.argv[1]
    payload = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    role = os.environ["PROFILE_ROLE"]
    require(
        set(Path("/run").glob("credential*")) == {Path("/run/credential")},
        "PROFILE_CREDENTIAL_MOUNTS",
    )
    if phase == "provision":
        dsn = os.environ["OW_MIGRATION_DSN"]
        with psycopg.connect(dsn, autocommit=True) as conn:
            for database in ("workbench", "restored"):
                if database == "restored":
                    conn.execute("CREATE DATABASE restored")
                target = psycopg.conninfo.make_conninfo(dsn, dbname=database)
                migrate(target)
            for name, group in (
                ("writer", "ow_writer"),
                ("worker", "ow_writer"),
                ("reader", "ow_reader"),
                ("lifecycle", "ow_lifecycle"),
                ("recovery", None),
            ):
                password = Path(f"/provision/{name}").read_text().strip()
                conn.execute(
                    sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
                        sql.Identifier("profile_" + name), sql.Literal(password)
                    )
                )
                if group:
                    conn.execute(
                        sql.SQL("GRANT {} TO {}").format(
                            sql.Identifier(group), sql.Identifier("profile_" + name)
                        )
                    )
            for database in ("workbench", "restored"):
                with psycopg.connect(
                    psycopg.conninfo.make_conninfo(dsn, dbname=database)
                ) as target:
                    target.execute("GRANT USAGE ON SCHEMA ow TO profile_recovery")
                    target.execute("GRANT ALL ON ALL TABLES IN SCHEMA ow TO profile_recovery")
                    target.execute("GRANT ALL ON ALL SEQUENCES IN SCHEMA ow TO profile_recovery")
        try:
            db().validate_reader()
        except WorkbenchError as exc:
            require(exc.code == "UNSAFE_READER_IDENTITY", "PROFILE_ADMIN_READER_REFUSAL")
        else:
            raise RuntimeError("PROFILE_ADMIN_READER_AUTHORITY")
        result = {"status": "provisioned"}
    elif phase == "import":
        results = []
        for name in ("one", "two"):
            path = Path("/tmp") / (name + ".txt")
            path.write_text("Synthetic evidence " + name)
            results.append(
                cli("import-text", "--file", str(path), "--source-id", "synthetic", "--title", name)
            )
        selected = db().search("synthetic")[0]["document_id"]
        briefing = cli("briefing", "create", "--document-id", selected)
        require(briefing["items"] == [] and briefing["degraded"], "PROFILE_BRIEFING_SCOPE")
        result = {"imports": results, "briefing": briefing["briefing_id"]}
    elif phase == "work":
        result = cli("work", "--max-jobs", "4")
        require(
            result["succeeded"] == result["attempted"] == 2
            and result["failed"] == result["superseded"] == 0,
            "PROFILE_WORKER_COMPLETION",
        )
    elif phase == "read":
        status = cli("status")
        require(status["documents"] == status["chunks"] == 2, "PROFILE_COUNTS")
        found = cli("search", "synthetic")["results"]
        require(len(found) == (1 if payload.get("retired") else 2), "PROFILE_VISIBLE_COUNT")
        service = ReadService(db(), EvidenceStore(Path("/evidence"), read_only=True))
        document = service.document(found[0]["document_id"])
        require(document["integrity"] == "verified", "PROFILE_EVIDENCE")
        asyncio.run(mcp_checks(document, payload["briefing"], payload.get("retired")))
        result = {"documents": found, "status": status}
    elif phase == "negative":
        root = Path("/evidence")
        try:
            (root / "forbidden").write_text("no")
        except OSError:
            pass
        else:
            raise RuntimeError("PROFILE_CAS_WRITABLE")
        existing = next(root.glob("[0-9a-f][0-9a-f]/*"))
        try:
            existing.unlink()
        except OSError:
            pass
        else:
            raise RuntimeError("PROFILE_CAS_UNLINK_ALLOWED")
        for other in ROLE_KEYS:
            require(not Path("/provision", other).exists(), "PROFILE_FOREIGN_CREDENTIAL")
        if role == "reader":
            with db().connect() as conn:
                try:
                    conn.execute("INSERT INTO ow.sources(source_id) VALUES ('forbidden')")
                except psycopg.errors.InsufficientPrivilege:
                    pass
                else:
                    raise RuntimeError("PROFILE_READER_WRITE")
        elif role == "worker":
            try:
                db().validate_reader()
            except WorkbenchError as exc:
                require(exc.code == "UNSAFE_READER_IDENTITY", "PROFILE_WRITER_READER_REFUSAL")
            else:
                raise RuntimeError("PROFILE_WRITER_READER_AUTHORITY")
        result = {"status": "refused"}
    elif phase == "policy-old":
        result = cli("lifecycle", "export-policy", "--file", "/policy/old.owpolicy")
    elif phase == "retire":
        cli(
            "lifecycle",
            "retire",
            "--document-id",
            payload["retired"],
            "--operation-id",
            "synthetic-retirement",
            "--actor",
            "synthetic-operator",
            "--rationale",
            "Synthetic acceptance after checkpoint",
        )
        result = cli("lifecycle", "export-policy", "--file", "/policy/current.owpolicy")
    elif phase == "checkpoint":
        result = cli("checkpoint", "--file", "/backup/core.owcp")
    elif phase == "restore":
        args = [
            "restore",
            "--file",
            "/backup/core.owcp",
            "--sha256",
            payload["checkpoint"],
            "--policy-file",
            "/backup/current.owpolicy",
            "--policy-sha256",
            payload["policy"],
            "--minimum-policy-revision",
            str(payload["revision"]),
        ]
        bad = args.copy()
        bad[bad.index("--sha256") + 1] = "0" * 64
        cli(*bad, error="RECOVERY_DIGEST_MISMATCH")
        bad = args.copy()
        bad[bad.index("--policy-sha256") + 1] = "0" * 64
        cli(*bad, error="RECOVERY_DIGEST_MISMATCH")
        bad = args.copy()
        bad[bad.index("--policy-file") + 1] = "/backup/old.owpolicy"
        bad[bad.index("--policy-sha256") + 1] = payload["old_policy"]
        cli(*bad, error="LIFECYCLE_POLICY_STALE_OR_WRONG_DATASET")
        with db().connect() as conn:
            require(
                conn.execute("SELECT count(*) AS n FROM ow.documents").fetchone()["n"] == 0,
                "PROFILE_FAILED_RESTORE_ROWS",
            )
        require(not Path("/restore/objects").exists(), "PROFILE_FAILED_RESTORE_STORE")
        result = cli(*args)
        require(
            result["status"] == "restored_requires_operator_reconciliation",
            "PROFILE_RESTORE_STATUS",
        )
        require(result["sources_enabled"] is False, "PROFILE_RESTORE_SOURCES")
        require(result["quarantined_jobs"] == 2, "PROFILE_RESTORE_QUARANTINE")
        with db().connect() as conn:
            require(
                conn.execute(
                    "SELECT count(*) AS n FROM ow.jobs WHERE status IN ('ready','running')"
                ).fetchone()["n"]
                == 0,
                "PROFILE_RESTORE_JOBS",
            )
    else:
        raise RuntimeError("PROFILE_PHASE_INVALID")
    print(json.dumps(result, default=str))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        code = str(exc) if isinstance(exc, RuntimeError) else "PROFILE_ACCEPTANCE_FAILED"
        if not re.fullmatch("[A-Z_]{1,120}", code):
            code = "PROFILE_ACCEPTANCE_FAILED"
        print(code, file=sys.stderr)
        raise SystemExit(1) from None
