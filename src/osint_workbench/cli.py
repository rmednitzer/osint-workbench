import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from pydantic import ValidationError

from . import intelligence
from .collection import collect
from .contracts import DocumentInput, SourceConfig
from .database import SCHEMA_VERSION, Database, migrate
from .errors import WorkbenchError
from .evidence import EvidenceStore
from .jobs import Jobs
from .local_encoder import EncoderManifest, LocalEncoder
from .local_generation import GeneratorManifest, LocalGenerator
from .local_reranker import LocalReranker, RerankerManifest
from .mcp_server import serve
from .service import ReadService
from .vector_index import VectorIndex, migrate_retrieval
from .worker import run_once


def _dsn(name):
    value = os.environ.get(name)
    if not value:
        raise WorkbenchError("DATABASE_CONFIGURATION_REQUIRED")
    return value


def _encoder(path):
    with Path(path).open("rb") as stream:
        data = stream.read(65537)
    if len(data) > 65536:
        raise WorkbenchError("ENCODER_CONFIGURATION_TOO_LARGE")
    return LocalEncoder(EncoderManifest.model_validate_json(data))


def main():
    parser = argparse.ArgumentParser(prog="osint-workbench")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("migrate")
    sub.add_parser("migrate-retrieval")
    enrich = sub.add_parser("enrich")
    enrich.add_argument("action", choices=["enqueue", "work-once", "reconcile"])
    enrich.add_argument("--manifest", type=Path, required=True)
    enrich.add_argument("--document-id")
    rev = sub.add_parser("review")
    rev.add_argument("assertion_id")
    rev.add_argument("--decision", choices=["accept", "reject"], required=True)
    rev.add_argument("--actor", required=True)
    rev.add_argument("--rationale", required=True)
    brief = sub.add_parser("briefing")
    brief.add_argument("action", choices=["create", "show"])
    brief.add_argument("--document-id", action="append")
    brief.add_argument("--briefing-id")
    index = sub.add_parser("index")
    index.add_argument("action", choices=["build", "activate"])
    index.add_argument("--manifest", type=Path, required=True)
    index.add_argument("--generation")
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
        elif args.command == "migrate-retrieval":
            migrate_retrieval(_dsn("OW_MIGRATION_DSN"))
            value = {"schema_version": SCHEMA_VERSION, "retrieval_schema_version": 1}
        elif args.command == "enrich":
            data = args.manifest.read_bytes()
            if len(data) > 65536:
                raise WorkbenchError("INVALID_GENERATOR_CONFIGURATION")
            generator = LocalGenerator(GeneratorManifest.model_validate_json(data))
            if args.action == "reconcile":
                value = generator.reconcile()
            else:
                db = Database(_dsn("OW_WRITER_DSN"))
                if args.action == "enqueue":
                    if not args.document_id:
                        raise WorkbenchError("DOCUMENT_ID_REQUIRED")
                    value = {"job_id": intelligence.enqueue(db, generator, args.document_id)}
                else:
                    value = intelligence.enrich_once(
                        db,
                        EvidenceStore(Path(os.environ["OW_EVIDENCE_ROOT"]), read_only=True),
                        generator,
                    )
        elif args.command == "review":
            value = intelligence.review(
                Database(_dsn("OW_WRITER_DSN")),
                args.assertion_id,
                args.decision,
                args.actor,
                args.rationale,
            )
        elif args.command == "briefing" and args.action == "create":
            value = intelligence.create_briefing(Database(_dsn("OW_WRITER_DSN")), args.document_id)
        elif args.command == "index":
            index = VectorIndex(Database(_dsn("OW_WRITER_DSN")), _encoder(args.manifest))
            if args.action == "activate":
                if args.generation is None:
                    raise WorkbenchError("GENERATION_REQUIRED")
                value = index.activate(args.generation)
            else:
                if args.generation is not None:
                    raise WorkbenchError("UNEXPECTED_GENERATION")
                value = index.build(
                    EvidenceStore(Path(os.environ["OW_EVIDENCE_ROOT"]), read_only=True)
                )
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
                db,
                EvidenceStore(Path(os.environ["OW_EVIDENCE_ROOT"]), read_only=True),
                encoder=_encoder(os.environ["OW_ENCODER_MANIFEST"])
                if os.environ.get("OW_ENCODER_MANIFEST")
                else None,
                reranker=LocalReranker(
                    RerankerManifest.model_validate_json(
                        Path(os.environ["OW_RERANKER_MANIFEST"]).read_bytes()
                    )
                )
                if os.environ.get("OW_RERANKER_MANIFEST")
                else None,
            )
            if args.command == "briefing":
                value = service.briefing(args.briefing_id)
                print(json.dumps(value, ensure_ascii=False))
                return
            if args.command == "mcp":
                asyncio.run(serve(service))
                return
            value = service.search(args.query) if args.command == "search" else service.status()
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
