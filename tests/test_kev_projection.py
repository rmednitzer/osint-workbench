"""Synthetic stored KEV observations: evidence/authority and installed operator reads."""

import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta

import psycopg
import pytest

from osint_workbench import kev_projection
from osint_workbench.advisory import parse_advisory_record
from osint_workbench.api_parser import parse
from osint_workbench.database import Database
from osint_workbench.errors import WorkbenchError
from osint_workbench.evidence import EvidenceStore
from osint_workbench.text import digest
from tests.test_kev import RECORD, catalogue, raw
from tests.test_lifecycle import change


def fixture_record(description="Österreich: synthetic evidence 🦊"):
    item = dict(RECORD, shortDescription=description)
    wire = raw(catalogue([item]))
    document = parse(wire, "synthetic-source", "cisa-kev/1")[0][0]
    return item, wire, document


def test_projection_record_preserves_bytes_and_does_not_invent_dates_or_scores():
    item, _, doc = fixture_record()
    text = doc.text.encode()
    observed = datetime(2026, 10, 20, 8, tzinfo=UTC)
    value = kev_projection._record(item, "declared-publisher", digest(text), len(text), observed)
    record = parse_advisory_record(json.dumps(value).encode())
    assert record.description == item["shortDescription"]
    assert record.revision == digest(text)
    assert record.observed_at == observed and record.status == "unknown"
    assert record.published_at is None and record.modified_at is None
    assert record.exploitation[0].status == "reported"
    assert record.exploitation[0].observation_date is None
    assert record.cvss == record.epss == ()
    reference = record.evidence[0]
    assert reference == record.exploitation[0].evidence[0]
    assert text[reference.start : reference.end].decode() == doc.text
    assert reference.end > len(doc.text)
    assert "dueDate" not in value and "dateAdded" not in value


@pytest.mark.parametrize("description", ["private-canary\ncontinued", "x" * 4097])
def test_projection_refuses_incompatible_description_without_truncation(description):
    item, _, doc = fixture_record(description)
    with pytest.raises(WorkbenchError, match="^KEV_PROJECTION_RECORD_INCOMPATIBLE$"):
        kev_projection._record(
            item, "publisher", digest(doc.text.encode()), len(doc.text.encode()), datetime.now(UTC)
        )


@pytest.mark.parametrize("publisher", ["", "p" * 65, "publisher.invalid", "private-canary\n"])
def test_invalid_publisher_refused_before_database_or_objects(publisher):
    with pytest.raises(WorkbenchError, match="^INVALID_ADVISORY_PUBLISHER$"):
        kev_projection.project(None, None, "a" * 64, publisher)


def stored(
    writer,
    tmp_path,
    *,
    extractor="cisa-kev/1",
    raw_override=None,
    description="Österreich: synthetic evidence 🦊",
):
    _, wire, document = fixture_record(description)
    store = EvidenceStore(tmp_path / "objects")
    doc_id = writer.ingest(
        document, wire if raw_override is None else raw_override, store, extractor
    )
    return document, doc_id, store, EvidenceStore(store.root, read_only=True)


@pytest.mark.integration
def test_installed_advisory_cli_binds_source_snapshot_and_revision(databases, tmp_path):
    writer, reader, roles = databases
    document, doc_id, store, readonly = stored(writer, tmp_path)
    receipt = kev_projection.project(reader, readonly, doc_id, "declared-publisher")
    encoded = json.dumps(
        receipt["payload"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    assert receipt["sha256"] == digest(encoded)
    payload = receipt["payload"]
    assert payload["source_id"] == document.source_id
    assert payload["document_id"] == doc_id
    assert payload["record"]["publisher_id"] == "declared-publisher"
    assert payload["evidence_coordinate_space"] == "normalized_record_utf8_bytes"
    assert payload["current_catalogue_membership"] == "not_established"
    assert payload["publisher_authority"] == "operator_label_not_authenticated"
    snapshot = reader.snapshot(payload["snapshot_id"])
    assert payload["record"]["revision"] == snapshot["text_sha256"]
    assert (
        parse_advisory_record(json.dumps(payload["record"]).encode()).observed_at
        == snapshot["acquired_at"]
    )
    # Actual installed interpreter/module/SQL/CAS/parser; no model manifest is loaded.
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            "osint_workbench.cli",
            "advisory",
            doc_id,
            "--publisher-id",
            "declared-publisher",
        ],
        env={k: v for k, v in os.environ.items() if not k.startswith("OW_")}
        | {
            "OW_READER_DSN": roles["reader"],
            "OW_EVIDENCE_ROOT": str(store.root),
            "OW_ENCODER_MANIFEST": "/unavailable/synthetic-model",
        },
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == receipt
    # Caller attribution is bound by the receipt, never silently inferred from source.
    assert (
        kev_projection.project(reader, readonly, doc_id, "other-publisher")["sha256"]
        != receipt["sha256"]
    )
    with pytest.raises(WorkbenchError, match="UNSAFE_READER"):
        kev_projection.project(writer, readonly, doc_id, "publisher")
    with pytest.raises(WorkbenchError, match="READ_ONLY_EVIDENCE_REQUIRED"):
        kev_projection.project(reader, store, doc_id, "publisher")


@pytest.mark.integration
@pytest.mark.parametrize("fault", ["extractor", "raw-record", "body", "raw-bytes", "external-key"])
def test_projection_refuses_false_provenance_and_corrupt_evidence(databases, tmp_path, fault):
    writer, reader, roles = databases
    override = (
        raw(catalogue([dict(RECORD, shortDescription="Unrelated original bytes")]))
        if fault == "raw-record"
        else None
    )
    _, doc_id, store, readonly = stored(
        writer,
        tmp_path,
        extractor="text/1" if fault == "extractor" else "cisa-kev/1",
        raw_override=override,
    )
    if fault == "body":
        with psycopg.connect(roles["admin"]) as conn:
            conn.execute(
                "UPDATE ow.documents SET body='private-canary' WHERE document_id=%s", (doc_id,)
            )
    if fault == "external-key":
        # Change stored identity to another admitted logical key while preserving
        # visible lifecycle admission: content equality alone must not suffice.
        with psycopg.connect(roles["admin"]) as conn:
            conn.execute(
                "UPDATE ow.documents SET external_key=%s WHERE document_id=%s",
                (digest(b"wrong"), doc_id),
            )
            conn.execute(
                "UPDATE ow.lifecycle_items SET external_key=%s "
                "WHERE source_id=%s AND external_key=%s",
                (digest(b"wrong"), "synthetic-source", digest(RECORD["cveID"].encode())),
            )
    if fault == "raw-bytes":
        sha = reader.snapshot(reader.document(doc_id)["snapshot_id"])["raw_sha256"]
        (store.root / sha[:2] / sha).write_bytes(b"private-canary")
    code = (
        "EVIDENCE_INTEGRITY_MISMATCH"
        if fault in {"body", "raw-bytes"}
        else "KEV_PROJECTION_PROVENANCE_MISMATCH"
    )
    with pytest.raises(WorkbenchError, match=f"^{code}$"):
        kev_projection.project(reader, readonly, doc_id, "publisher")


@pytest.mark.integration
def test_projection_visibility_revisions_and_holds(databases, tmp_path):
    writer, reader, roles = databases
    document, original, store, readonly = stored(writer, tmp_path)
    _, wire, revised = fixture_record("Revised synthetic record")
    newer = writer.ingest(revised, wire, store, "cisa-kev/1")
    old = kev_projection.project(reader, readonly, original, "publisher")
    new = kev_projection.project(reader, readonly, newer, "publisher")
    assert old["payload"]["record"]["revision"] != new["payload"]["record"]["revision"]
    assert old["payload"]["current_catalogue_membership"] == "not_established"
    operator = Database(roles["lifecycle"])
    change(operator, newer, "hold", hold_id="synthetic-hold")
    change(
        operator,
        newer,
        "retention",
        retention_class="short-lived",
        retain_until=datetime.now(UTC) - timedelta(seconds=1),
    )
    for doc_id in (original, newer):
        with pytest.raises(WorkbenchError, match="^DOCUMENT_NOT_FOUND$"):
            kev_projection.project(reader, readonly, doc_id, "publisher")
    change(operator, newer, "release", hold_id="synthetic-hold")
    change(operator, newer, "retire")
    with pytest.raises(WorkbenchError, match="^DOCUMENT_NOT_FOUND$"):
        kev_projection.project(reader, readonly, original, "publisher")
    with pytest.raises(WorkbenchError, match="RETIRED_OR_EXPIRED"):
        writer.ingest(document, raw(), store, "cisa-kev/1")


@pytest.mark.integration
def test_expiry_during_projection_is_rechecked(databases, tmp_path, monkeypatch):
    writer, reader, roles = databases
    _, doc_id, _, readonly = stored(writer, tmp_path)
    original = kev_projection._record

    def expires(*args):
        record = original(*args)
        # Administrative fixture intervention discriminates the final admission
        # statement without a timing-sensitive sleep or blocked lifecycle writer.
        with psycopg.connect(roles["admin"]) as conn:
            conn.execute(
                "UPDATE ow.lifecycle_items SET retain_until=clock_timestamp()-interval '1 second' "
                "WHERE source_id=%s AND external_key=%s",
                ("synthetic-source", digest(RECORD["cveID"].encode())),
            )
        return record

    monkeypatch.setattr(kev_projection, "_record", expires)
    with pytest.raises(WorkbenchError, match="^DOCUMENT_NOT_FOUND$"):
        kev_projection.project(reader, readonly, doc_id, "publisher")


@pytest.mark.integration
def test_stored_valid_kev_incompatible_with_envelope_refuses_projection(databases, tmp_path):
    writer, reader, _ = databases
    _, doc_id, _, readonly = stored(
        writer, tmp_path, description="Valid KEV\nmultiline description"
    )
    with pytest.raises(WorkbenchError, match="^KEV_PROJECTION_RECORD_INCOMPATIBLE$"):
        kev_projection.project(reader, readonly, doc_id, "publisher")
    assert reader.document(doc_id)["document_id"] == doc_id
