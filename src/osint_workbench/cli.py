import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from pydantic import ValidationError

from .collection import collect
from .contracts import DocumentInput, SourceConfig
from .database import SCHEMA_VERSION, Database, migrate
from .errors import WorkbenchError
from .evidence import EvidenceStore
from .jobs import Jobs
from .mcp_server import serve
from .service import ReadService
from .worker import run_once


def _dsn(name):
    value = os.environ.get(name)
    if not value:
        raise WorkbenchError("DATABASE_CONFIGURATION_REQUIRED")
    return value


def main():
    parser = argparse.ArgumentParser(prog="osint-workbench")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("migrate")
    imp = sub.add_parser("import-text")
    imp.add_argument("--file", type=Path, required=True)
    imp.add_argument("--source-id", required=True)
    imp.add_argument("--title", required=True)
    scan = sub.add_parser("collect")
    scan.add_argument("--config", type=Path, required=True)
    sub.add_parser("status")
    search = sub.add_parser("search")
    search.add_argument("query")
    sub.add_parser("mcp")
    sub.add_parser("work-once")
    job = sub.add_parser("job")
    job.add_argument("action", choices=["inspect", "cancel"])
    job.add_argument("job_id")
    args = parser.parse_args()
    try:
        if args.command == "migrate":
            migrate(_dsn("OW_MIGRATION_DSN"))
            value = {"schema_version": SCHEMA_VERSION}
        elif args.command == "work-once":
            db = Database(_dsn("OW_WRITER_DSN"))
            store = EvidenceStore(Path(os.environ["OW_EVIDENCE_ROOT"]))
            value = run_once(db, store)
        elif args.command == "job":
            jobs = Jobs(Database(_dsn("OW_WRITER_DSN")))
            value = getattr(jobs, args.action)(args.job_id)
        elif args.command == "import-text":
            raw = args.file.read_bytes()
            document = DocumentInput(
                source_id=args.source_id,
                external_id=args.file.name,
                title=args.title,
                text=raw.decode("utf-8"),
            )
            store = EvidenceStore(Path(os.environ["OW_EVIDENCE_ROOT"]))
            identifier = Database(_dsn("OW_WRITER_DSN")).ingest(document, raw, store)
            value = {"document_id": identifier}
        elif args.command == "collect":
            config = SourceConfig.model_validate_json(args.config.read_bytes())
            if not config.sources:
                value = {"status": "unconfigured", "sources": 0}
            else:
                db = Database(_dsn("OW_WRITER_DSN"))
                store = EvidenceStore(Path(os.environ["OW_EVIDENCE_ROOT"]))
                value = [collect(source, db, store) for source in config.sources]
        else:
            db = Database(_dsn("OW_READER_DSN"))
            service = ReadService(
                db, EvidenceStore(Path(os.environ["OW_EVIDENCE_ROOT"]), read_only=True)
            )
            if args.command == "mcp":
                asyncio.run(serve(service))
                return
            value = service.search(args.query) if args.command == "search" else db.status()
        print(json.dumps(value, default=str, ensure_ascii=False))
    except WorkbenchError as exc:
        print(json.dumps({"error": exc.code}), file=sys.stderr)
        raise SystemExit(1) from None
    except (ValidationError, ValueError, KeyError, OSError):
        print(json.dumps({"error": "INVALID_CONFIGURATION_OR_INPUT"}), file=sys.stderr)
        raise SystemExit(1) from None
    except Exception:
        print(json.dumps({"error": "BACKEND_UNAVAILABLE"}), file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
