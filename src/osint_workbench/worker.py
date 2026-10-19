"""Bounded, replayable local work. Derived rows and completion share one transaction."""

import hashlib
import json
from typing import Literal

from psycopg.types.json import Jsonb
from pydantic import Field, ValidationError, model_validator

from .contracts import Digest, Identifier, StrictModel
from .database import Database
from .errors import WorkbenchError
from .evidence import EvidenceStore
from .jobs import Jobs
from .lifecycle import assert_document_visible
from .text import chunks, digest

CHUNKER = "characters/1:size=1800:overlap=150"


class AcceptedDocument(StrictModel):
    document_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    operation_id: Identifier | None = None
    chunker: Literal["characters/1:size=1800:overlap=150"] | None = None

    @model_validator(mode="after")
    def explicit_operation_pair(self):
        if (self.operation_id is None) != (self.chunker is None):
            raise ValueError("explicit chunk operations require a version and operation ID")
        return self


class ChunkRequest(StrictModel):
    document_id: Digest
    operation_id: Identifier


def enqueue_chunk(db: Database, document_id, operation_id):
    """Create a distinct operator-requested chunk operation; never reset a job.

    A retained historical version may be chunked without rewinding its source
    head. Snapshot and algorithm are bound under lifecycle admission.
    """
    request = ChunkRequest(document_id=document_id, operation_id=operation_id)
    with db.connect() as conn:
        assert_document_visible(conn, request.document_id)
        row = conn.execute(
            "SELECT snapshot_id FROM ow.visible_documents WHERE document_id=%s",
            (request.document_id,),
        ).fetchone()
        if not row:
            raise WorkbenchError("DOCUMENT_NOT_FOUND")
        payload = AcceptedDocument(
            document_id=request.document_id,
            snapshot_id=row["snapshot_id"],
            operation_id=request.operation_id,
            chunker=CHUNKER,
        ).model_dump(exclude_none=True)
        key = "chunk-operation/1:" + digest(json.dumps(payload, sort_keys=True).encode())
        return Database.enqueue_stored(conn, "document.accepted", key, payload)


def run_batch(db: Database, store: EvidenceStore, *, max_jobs: int = 32) -> dict:
    """One bounded tick; never claim unsupported downstream job kinds.

    Results are aggregate-only for a service journal. Each successful job has
    already committed independently; a failed tick does not roll those back.
    """
    if type(max_jobs) is not int or not 1 <= max_jobs <= 1000:
        raise WorkbenchError("INVALID_WORK_LIMIT")
    counts = {"succeeded": 0, "failed": 0, "superseded": 0}
    idle = False
    for _ in range(max_jobs):
        result = run_once(db, store)
        if result["status"] == "idle":
            idle = True
            break
        counts[result["status"]] += 1
    return {
        "kind": "chunk_worker_tick",
        "attempted": sum(counts.values()),
        **counts,
        "idle_observed": idle,
        "limit_reached": not idle,
    }


def run_once(db: Database, store: EvidenceStore) -> dict:
    jobs = Jobs(db)
    job = jobs.claim(kinds=["document.accepted"], lease_seconds=60)
    if job is None:
        return {"status": "idle"}
    try:
        payload = AcceptedDocument.model_validate(job["payload"])
        document = db.document(payload.document_id)
        if document["snapshot_id"] != payload.snapshot_id:
            raise WorkbenchError("JOB_PROVENANCE_MISMATCH")
        snapshot = db.snapshot(payload.snapshot_id)
        text = store.get(snapshot["text_sha256"]).decode("utf-8")
        store.get(snapshot["raw_sha256"])
        if digest(document["full_body"].encode()) != snapshot["text_sha256"]:
            raise WorkbenchError("DOCUMENT_INTEGRITY_MISMATCH")
        parts = chunks(text)
        # Version includes every split parameter; never mix settings under one identity.
        chunker = CHUNKER
        with db.connect() as conn:
            locked = jobs.locked(conn, job["job_id"], job["fence"])
            assert_document_visible(conn, payload.document_id)
            for ordinal, part in enumerate(parts):
                chunk_id = hashlib.sha256(
                    json.dumps([payload.document_id, chunker, ordinal, part["sha256"]]).encode()
                ).hexdigest()
                conn.execute(
                    """INSERT INTO ow.chunks(chunk_id,document_id,chunker,ordinal,
                    start_offset,end_offset,text_sha256,body) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT DO NOTHING""",
                    (
                        chunk_id,
                        payload.document_id,
                        chunker,
                        ordinal,
                        part["start"],
                        part["end"],
                        part["sha256"],
                        part["text"],
                    ),
                )
            downstream = Database.enqueue_stored(
                conn,
                "document.chunked",
                payload.document_id + ":" + chunker,
                {"document_id": payload.document_id, "chunker": chunker, "chunks": len(parts)},
            )
            assert_document_visible(conn, payload.document_id)
            jobs.finish_locked(
                conn,
                locked,
                Jsonb(
                    {
                        "chunks": len(parts),
                        "chunker": chunker,
                        "downstream_enqueue": downstream,
                    }
                ),
            )
        return {
            "status": "succeeded",
            "job_id": str(job["job_id"]),
            "chunks": len(parts),
            "downstream_enqueue": downstream,
        }
    except (WorkbenchError, ValidationError) as exc:
        code = exc.code if isinstance(exc, WorkbenchError) else "INVALID_JOB_PAYLOAD"
        if code == "STALE_JOB_LEASE":
            return {"status": "superseded", "job_id": str(job["job_id"])}
        # Temporary lifecycle admission contention retains bounded job retry.
        # Integrity/provenance failures still require operator review.
        try:
            jobs.fail(
                job["job_id"],
                job["fence"],
                code,
                retryable=code in {"LIFECYCLE_BUSY", "EVIDENCE_STORE_BUSY"},
            )
        except WorkbenchError as failure:
            if failure.code != "STALE_JOB_LEASE":
                raise
            return {"status": "superseded", "job_id": str(job["job_id"])}
        return {"status": "failed", "job_id": str(job["job_id"]), "error": code}
    except Exception:
        # Never persist exception messages, source text, DSNs or provider responses.
        try:
            jobs.fail(job["job_id"], job["fence"], "WORKER_BACKEND_FAILURE")
        except WorkbenchError as exc:
            if exc.code != "STALE_JOB_LEASE":
                raise
        raise WorkbenchError("WORKER_BACKEND_FAILURE") from None
