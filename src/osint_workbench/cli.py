import argparse
import asyncio
import json
import os
import stat
import sys
from pathlib import Path

from pydantic import ValidationError

from . import (
    cloud,
    evaluation,
    garbage_collection,
    intelligence,
    lifecycle,
    quality,
    record_purge,
    recovery,
)
from .collection import collect, collect_due
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


def _manifest(path, model):
    data = _operator_bytes(path)
    try:
        return model.model_validate_json(data)
    except (ValidationError, ValueError):
        # Retain the CLI's existing malformed-configuration error contract.
        raise WorkbenchError("INVALID_CONFIGURATION_OR_INPUT") from None


def _operator_bytes(path):
    # The operator selects configuration paths; MCP/source/model text does not.
    # Refuse final symlinks, devices and FIFOs before reading, avoiding special-file
    # waits before inference deadlines apply. Regular-file I/O has no application deadline.
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise WorkbenchError("MODEL_CONFIGURATION_INVALID")
        if info.st_size > 65536:
            raise WorkbenchError("MODEL_CONFIGURATION_TOO_LARGE")
        with os.fdopen(fd, "rb") as stream:
            fd = None  # The stream owns the descriptor after successful wrapping.
            data = stream.read(65537)
    except OSError:
        raise WorkbenchError("MODEL_CONFIGURATION_UNAVAILABLE") from None
    finally:
        if fd is not None:
            os.close(fd)
    if len(data) > 65536:
        raise WorkbenchError("MODEL_CONFIGURATION_TOO_LARGE")
    return data


def _generator(args, db=None):
    # Exactly one of a local manifest or an explicit remote route; never both,
    # and a local configuration never implies a remote fallback.
    if (args.manifest is None) == (args.route is None):
        raise WorkbenchError("GENERATOR_SELECTION_REQUIRED")
    if args.manifest is not None:
        return LocalGenerator(_manifest(args.manifest, GeneratorManifest))
    if args.cloud_policy is None or db is None:
        raise WorkbenchError("CLOUD_POLICY_REQUIRED")
    policy, policy_sha = cloud.load_policy(_operator_bytes(args.cloud_policy))
    return cloud.GovernedGenerator(db, policy, policy_sha, args.route)


def _encoder(path):
    return LocalEncoder(_manifest(path, EncoderManifest))


def _evaluation_input(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > evaluation.MAX_INPUT_BYTES:
            raise WorkbenchError("EVALUATION_INPUT_INVALID")
        data = stream.read(evaluation.MAX_INPUT_BYTES + 1)
    if len(data) > evaluation.MAX_INPUT_BYTES:
        raise WorkbenchError("EVALUATION_INPUT_INVALID")
    return data


def main():
    parser = argparse.ArgumentParser(prog="osint-workbench")
    sub = parser.add_subparsers(dest="command", required=True)
    assess = sub.add_parser("evaluate")
    modes = assess.add_subparsers(dest="mode", required=True)
    replay = modes.add_parser("replay")
    replay.add_argument("--suite", type=Path, required=True)
    replay.add_argument("--predictions", type=Path, required=True)
    replay.add_argument("--file", type=Path, required=True)
    local = modes.add_parser("local")
    local.add_argument("--suite", type=Path, required=True)
    local.add_argument("--output", type=Path, required=True)
    local.add_argument("--encoder-manifest", type=Path)
    local.add_argument("--budget-seconds", type=float, default=120)
    local.add_argument("--source-revision")
    sub.add_parser("migrate")
    sub.add_parser("migrate-retrieval")
    backup = sub.add_parser("checkpoint")
    backup.add_argument("--file", type=Path, required=True)
    recovered = sub.add_parser("restore")
    recovered.add_argument("--file", type=Path, required=True)
    recovered.add_argument("--sha256", required=True)
    recovered.add_argument("--policy-file", type=Path, required=True)
    recovered.add_argument("--policy-sha256", required=True)
    recovered.add_argument("--minimum-policy-revision", type=int, required=True)
    purge = sub.add_parser("purge")
    purge.add_argument("action", choices=["plan", "apply"])
    purge.add_argument("--file", type=Path, required=True)
    purge.add_argument("--document-id")
    purge.add_argument("--operation-id")
    purge.add_argument("--actor")
    purge.add_argument("--rationale")
    purge.add_argument("--sha256")
    gc = sub.add_parser("gc")
    gc.add_argument("action", choices=["plan", "apply"])
    gc.add_argument("--file", type=Path, required=True)
    gc.add_argument("--operation-id")
    gc.add_argument("--minimum-age-seconds", type=int, default=86400)
    gc.add_argument("--sha256")
    gc.add_argument("--journal", type=Path)
    life = sub.add_parser("lifecycle")
    life.add_argument(
        "action", choices=["inspect", "retention", "hold", "release", "retire", "export-policy"]
    )
    life.add_argument("--document-id")
    life.add_argument("--operation-id")
    life.add_argument("--actor")
    life.add_argument("--rationale")
    life.add_argument("--retention-class")
    life.add_argument("--retain-until")
    life.add_argument("--hold-id")
    life.add_argument("--file", type=Path)
    enrich = sub.add_parser("enrich")
    enrich.add_argument("action", choices=["enqueue", "work-once", "reconcile"])
    enrich.add_argument("--manifest", type=Path)
    enrich.add_argument("--route")
    enrich.add_argument("--cloud-policy", type=Path)
    enrich.add_argument("--data-class", choices=["public", "internal", "personal", "special"])
    enrich.add_argument("--document-id")
    enrich.add_argument("--operation-id", default="initial")
    exposure = sub.add_parser("cloud-exposure")
    exposure.add_argument("--cloud-policy", type=Path, required=True)
    ledger = sub.add_parser("cloud-ledger")
    ledger.add_argument("action", choices=["unsettled", "settle"])
    ledger.add_argument("--route")
    ledger.add_argument("--include-estimated", action="store_true")
    ledger.add_argument("--attempt-id")
    ledger.add_argument(
        "--basis", choices=["invoice", "usage_export", "provider_statement", "not_dispatched"]
    )
    ledger.add_argument("--cost")
    ledger.add_argument("--currency")
    ledger.add_argument("--evidence", type=Path)
    ledger.add_argument("--actor")
    ledger.add_argument("--rationale")
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
    scan.add_argument("--due-only", action="store_true")
    scan.add_argument("--max-sources", type=int)
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
        if args.command == "evaluate":
            suite = evaluation.parse_suite(_evaluation_input(args.suite))
            if args.mode == "replay":
                predictions = evaluation.parse_predictions(_evaluation_input(args.predictions))
                value = evaluation.evaluate(suite, predictions)
                recovery._write_new(args.file, evaluation._canonical(value))
                passed = all(s["all_targets_met"] for s in value["payload"]["splits"].values())
                print(
                    json.dumps(
                        {
                            "sha256": value["sha256"],
                            "all_targets_met": passed,
                            "semantic_acceptance": "not_established",
                        }
                    )
                )
                if not passed:
                    raise SystemExit(2)
                return
            value = quality.run(
                suite,
                args.output,
                encoder=_encoder(args.encoder_manifest) if args.encoder_manifest else None,
                budget_seconds=args.budget_seconds,
                source_revision=args.source_revision,
            )
            print(json.dumps(value, ensure_ascii=False))
            if value["status"] != "completed":
                raise SystemExit(1)
            if not value["all_targets_met"]:
                raise SystemExit(2)
            return
        elif args.command == "purge":
            db = Database(_dsn("OW_PURGE_DSN"))
            if args.action == "plan":
                value = record_purge.plan(
                    db,
                    args.file,
                    document_id=args.document_id,
                    operation_id=args.operation_id,
                    actor=args.actor,
                    rationale=args.rationale,
                )
            else:
                if args.sha256 is None:
                    raise WorkbenchError("PURGE_PLAN_DIGEST_REQUIRED")
                value = record_purge.apply(db, args.file, args.sha256)
        elif args.command == "gc":
            db = Database(_dsn("OW_GC_DSN"))
            store = EvidenceStore(Path(os.environ["OW_EVIDENCE_ROOT"]), read_only=True)
            if args.action == "plan":
                value = garbage_collection.plan(
                    db,
                    store,
                    args.file,
                    operation_id=args.operation_id,
                    minimum_age_seconds=args.minimum_age_seconds,
                )
            else:
                if args.sha256 is None or args.journal is None:
                    raise WorkbenchError("GC_PLAN_DIGEST_AND_JOURNAL_REQUIRED")
                value = garbage_collection.apply(db, store, args.file, args.sha256, args.journal)
        elif args.command == "checkpoint":
            value = recovery.checkpoint(
                Database(_dsn("OW_RECOVERY_DSN")),
                EvidenceStore(Path(os.environ["OW_EVIDENCE_ROOT"]), read_only=True),
                args.file,
            )
        elif args.command == "restore":
            value = recovery.restore(
                Database(_dsn("OW_RECOVERY_DSN")),
                args.file,
                args.sha256,
                Path(os.environ["OW_EVIDENCE_ROOT"]),
                policy_path=args.policy_file,
                policy_sha=args.policy_sha256,
                minimum_revision=args.minimum_policy_revision,
            )
        elif args.command == "lifecycle":
            db = Database(_dsn("OW_LIFECYCLE_DSN"))
            if args.action == "export-policy":
                if args.file is None:
                    raise WorkbenchError("POLICY_FILE_REQUIRED")
                value = lifecycle.export_policy(db, args.file)
            elif args.action == "inspect":
                value = lifecycle.inspect(db, args.document_id)
            else:
                change = lifecycle.Change.model_validate_json(
                    json.dumps(
                        {
                            "action": args.action,
                            "document_id": args.document_id,
                            "operation_id": args.operation_id,
                            "actor": args.actor,
                            "rationale": args.rationale,
                            "retention_class": args.retention_class,
                            "retain_until": args.retain_until,
                            "hold_id": args.hold_id,
                        }
                    )
                )
                value = lifecycle.apply(db, change)
        elif args.command == "migrate":
            migrate(_dsn("OW_MIGRATION_DSN"))
            value = {"schema_version": SCHEMA_VERSION}
        elif args.command == "migrate-retrieval":
            migrate_retrieval(_dsn("OW_MIGRATION_DSN"))
            value = {"schema_version": SCHEMA_VERSION, "retrieval_schema_version": 4}
        elif args.command == "enrich":
            db = Database(_dsn("OW_WRITER_DSN")) if args.route is not None else None
            generator = _generator(args, db)
            if args.action == "reconcile":
                if args.route is not None:
                    raise WorkbenchError("REMOTE_RECONCILE_UNSUPPORTED")
                value = generator.reconcile()
            else:
                db = db or Database(_dsn("OW_WRITER_DSN"))
                if args.action == "enqueue":
                    if not args.document_id:
                        raise WorkbenchError("DOCUMENT_ID_REQUIRED")
                    value = {
                        "job_id": intelligence.enqueue(
                            db, generator, args.document_id, args.operation_id, args.data_class
                        )
                    }
                else:
                    value = intelligence.enrich_once(
                        db,
                        EvidenceStore(Path(os.environ["OW_EVIDENCE_ROOT"]), read_only=True),
                        generator,
                    )
        elif args.command == "cloud-exposure":
            # Read-only aggregate: per route and currency, never summed across them.
            policy, policy_sha = cloud.load_policy(_operator_bytes(args.cloud_policy))
            db = Database(_dsn("OW_WRITER_DSN"))
            value = {
                "policy_sha256": policy_sha,
                "routes": [
                    {
                        "route_id": route.route_id,
                        "currency": route.pricebook.currency,
                        "cap": str(route.cap),
                        "exposure": str(
                            cloud.exposure(db, route.route_id, route.pricebook.currency)
                        ),
                    }
                    for route in policy.routes
                ],
            }
        elif args.command == "cloud-ledger":
            # Settlement authority is separate from the writer that spends.
            db = Database(_dsn("OW_ACCOUNTING_DSN"))
            if args.action == "unsettled":
                value = cloud.unsettled(
                    db, route_id=args.route, include_estimated=args.include_estimated
                )
            else:
                try:
                    settlement = cloud.Settlement.model_validate_json(
                        json.dumps(
                            {
                                "attempt_id": args.attempt_id,
                                "basis": args.basis,
                                "cost": args.cost,
                                "currency": args.currency,
                                "evidence_sha256": cloud.evidence_digest(args.evidence)
                                if args.evidence is not None
                                else None,
                                "actor": args.actor,
                                "rationale": args.rationale,
                            }
                        )
                    )
                except ValidationError:
                    raise WorkbenchError("INVALID_SETTLEMENT") from None
                value = cloud.settle(db, settlement)
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
            if args.max_sources is not None:
                if not args.due_only:
                    raise WorkbenchError("MAX_SOURCES_REQUIRES_DUE_ONLY")
                if not 1 <= args.max_sources <= 128:
                    raise WorkbenchError("INVALID_COLLECTION_LIMIT")
            with args.config.open("rb") as stream:
                encoded = stream.read(8 * 1024 * 1024 + 1)
            if len(encoded) > 8 * 1024 * 1024:
                raise WorkbenchError("SOURCE_CONFIGURATION_TOO_LARGE")
            config = SourceConfig.model_validate_json(encoded)
            if not config.sources:
                value = {"status": "unconfigured", "sources": 0}
            else:
                db = Database(_dsn("OW_COLLECTOR_DSN"))
                db.validate_collector()
                store = EvidenceStore(Path(os.environ["OW_EVIDENCE_ROOT"]))
                if args.due_only:
                    value = collect_due(
                        config.sources,
                        db,
                        store,
                        limit=32 if args.max_sources is None else args.max_sources,
                    )
                    print(json.dumps(value, ensure_ascii=False))
                    if value["status"] == "failed":
                        raise SystemExit(1)
                    return
                value = []
                for source in config.sources:
                    try:
                        result = collect(source, db, store, due_only=args.due_only)
                        value.append({"source_id": source.source_id, **result})
                    except WorkbenchError as exc:
                        # A failed source must not prevent independent configured sources.
                        value.append(
                            {"source_id": source.source_id, "status": "failed", "error": exc.code}
                        )
                if any(row["status"] == "failed" for row in value):
                    print(json.dumps(value, ensure_ascii=False))
                    raise SystemExit(1)
        else:
            db = Database(_dsn("OW_READER_DSN"))
            service = ReadService(
                db,
                EvidenceStore(Path(os.environ["OW_EVIDENCE_ROOT"]), read_only=True),
                encoder=_encoder(os.environ["OW_ENCODER_MANIFEST"])
                if os.environ.get("OW_ENCODER_MANIFEST")
                else None,
                reranker=LocalReranker(
                    _manifest(os.environ["OW_RERANKER_MANIFEST"], RerankerManifest)
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
