"""Read-only, evidence-verified KEV projection; no publisher authentication or exposure."""

import json
import re
import time

from .advisory import (
    AdvisoryRecord,
    EvidenceReference,
    ExploitationObservation,
    serialize_advisory_record,
)
from .api_acquisition import _documents
from .errors import WorkbenchError
from .text import digest

PROJECTION = "kev-advisory/1"
MAX_RECEIPT_BYTES = 270336


def _record(item, publisher_id, text_sha256, text_size, observed_at):
    # Whole normalized-record UTF-8 bytes, deliberately not raw-catalogue offsets.
    reference = EvidenceReference(snapshot_sha256=text_sha256, start=0, end=text_size)
    try:
        record = AdvisoryRecord(
            schema_version=1,
            publisher_id=publisher_id,
            record_id=item["cveID"],
            revision=text_sha256,
            status="unknown",  # KEV does not declare advisory publication/withdrawal status.
            description=item["shortDescription"],
            observed_at=observed_at,
            cve_ids=(item["cveID"],),
            evidence=(reference,),
            exploitation=(
                ExploitationObservation(
                    publisher_id=publisher_id,
                    cve_id=item["cveID"],
                    status="reported",  # An attributed catalogue assertion, not local exposure.
                    evidence=(reference,),
                ),
            ),
        )
        return json.loads(serialize_advisory_record(record))
    except (ValueError, TypeError, KeyError):
        raise WorkbenchError("KEV_PROJECTION_RECORD_INCOMPATIBLE") from None


def project(db, store, document_id: str, publisher_id: str) -> dict:
    """Project one visible immutable revision using the exact reader authority.

    Raw catalogue parsing reuses the bounded isolated acquisition parser. The
    operator's publisher label is attribution only, bound to source_id in the
    receipt. This does not persist a new fact or expose a new MCP tool.
    """
    if type(document_id) is not str or re.fullmatch(r"[0-9a-f]{64}", document_id) is None:
        raise WorkbenchError("INVALID_DOCUMENT_ID")
    if (
        type(publisher_id) is not str
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", publisher_id) is None
    ):
        raise WorkbenchError("INVALID_ADVISORY_PUBLISHER")
    db.validate_reader()
    if not store.read_only:
        raise WorkbenchError("READ_ONLY_EVIDENCE_REQUIRED")
    # DB before store: retain lifecycle and cooperative object-GC exclusion across
    # SQL, verified CAS reads, parser execution and the final expiry check.
    with db.connect() as conn, store.admission():
        row = conn.execute(
            """SELECT d.document_id,d.source_id,d.external_key,d.snapshot_id,d.title,d.body,
            d.published_at,s.source_id AS snapshot_source,s.raw_sha256,s.text_sha256,
            s.extractor,s.acquired_at FROM ow.visible_documents d
            JOIN ow.visible_snapshots s USING(snapshot_id) WHERE d.document_id=%s""",
            (document_id,),
        ).fetchone()
        if row is None:
            raise WorkbenchError("DOCUMENT_NOT_FOUND")
        if row["extractor"] != "cisa-kev/1" or row["source_id"] != row["snapshot_source"]:
            raise WorkbenchError("KEV_PROJECTION_PROVENANCE_MISMATCH")
        text = store.get(row["text_sha256"])
        raw = store.get(row["raw_sha256"])
        if text != row["body"].encode("utf-8"):
            raise WorkbenchError("EVIDENCE_INTEGRITY_MISMATCH")
        documents, _ = _documents(raw, row["source_id"], time.monotonic() + 10, "cisa-kev/1")
        matched = next(
            (d for d in documents if digest(d.external_id.encode()) == row["external_key"]), None
        )
        if (
            matched is None
            or matched.text.encode("utf-8") != text
            or matched.title != row["title"]
            or row["published_at"] is not None
        ):
            raise WorkbenchError("KEV_PROJECTION_PROVENANCE_MISMATCH")
        record = _record(
            json.loads(matched.text),
            publisher_id,
            row["text_sha256"],
            len(text),
            row["acquired_at"],
        )
        # Time-based expiry may occur without an exclusive lifecycle mutation.
        if not conn.execute(
            "SELECT 1 FROM ow.visible_documents WHERE document_id=%s", (document_id,)
        ).fetchone():
            raise WorkbenchError("DOCUMENT_NOT_FOUND")
        payload = {
            "projection": PROJECTION,
            "document_id": document_id,
            "source_id": row["source_id"],
            "snapshot_id": row["snapshot_id"],
            "raw_sha256": row["raw_sha256"],
            "evidence_coordinate_space": "normalized_record_utf8_bytes",
            "publisher_authority": "operator_label_not_authenticated",
            "current_catalogue_membership": "not_established",
            "source_freshness": "not_evaluated",
            "applicability": "not_evaluated",
            "record": record,
        }
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        receipt = {"sha256": digest(encoded), "payload": payload}
        if len(json.dumps(receipt, ensure_ascii=False).encode()) + 1 > MAX_RECEIPT_BYTES:
            raise WorkbenchError("KEV_PROJECTION_RESULT_LIMIT")
        return receipt
