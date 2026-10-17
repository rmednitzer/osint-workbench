import json
import os
import subprocess
import sys
import time
import uuid

import psycopg
import pytest
from pydantic import ValidationError

from osint_workbench import garbage_collection as gc
from osint_workbench.database import Database
from osint_workbench.errors import WorkbenchError
from osint_workbench.evidence import EvidenceStore
from tests.test_lifecycle import change
from tests.test_recovery import _input


def orphan(store, value=b"orphan"):
    sha = store.put(value)
    path = store.root / sha[:2] / sha
    old = time.time_ns() - 2 * 86400 * 10**9
    os.utime(path, ns=(old, old))
    return sha, path


def prepare(roles, tmp_path, store, name="cleanup"):
    path = tmp_path / (name + ".owgc")
    receipt = gc.plan(Database(roles["admin"]), store, path, operation_id=name)
    return path, receipt["sha256"]


def test_age_and_operation_bounds_before_database():
    for age in (0, 3599, True, 32 * 86400):
        with pytest.raises(ValidationError):
            gc.plan(None, None, None, operation_id="cleanup", minimum_age_seconds=age)
    with pytest.raises(ValidationError):
        gc.plan(None, None, None, operation_id="../escape")


@pytest.mark.integration
def test_references_include_retired_versions_holds_and_raw_feed(databases, tmp_path):
    writer, reader, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    first = writer.ingest(_input("Previous storage evidence."), b"old raw", store)
    latest = writer.ingest(_input(), b"current raw", store)
    change(Database(roles["lifecycle"]), latest, "retire")
    held = writer.ingest(_input(external="held"), b"held raw", store)
    change(Database(roles["lifecycle"]), held, "hold", hold_id="preserve")
    raw_sha, raw_path = orphan(store, b"shared feed with no accepted entries")
    with writer.connect() as conn:
        conn.execute(
            "INSERT INTO ow.collection_runs(run_id,source_id,status,raw_sha256) "
            "VALUES (%s,'fixture','failed',%s)",
            (uuid.uuid4(), raw_sha),
        )
    sha, removed = orphan(store)
    retained = {p.name for p in store.root.glob("*/*")} - {sha}
    # Make every retained object old enough; age must never override reachability.
    for p in store.root.glob("*/*"):
        os.utime(p, ns=(1_000_000_000, 1_000_000_000))
    plan, sha = prepare(roles, tmp_path, store)
    result = gc.apply(Database(roles["admin"]), store, plan, sha, tmp_path / "journal")
    assert result["objects"] == 1 and not result["physical_record_erasure"]
    assert not removed.exists() and raw_path.exists()
    assert {p.name for p in store.root.glob("*/*")} == retained
    with writer.connect() as conn:
        assert conn.execute("SELECT 1 FROM ow.documents WHERE document_id=%s", (first,)).fetchone()
    assert reader.document(held)
    assert gc.apply(Database(roles["admin"]), store, plan, sha, tmp_path / "journal")["resumed"]


@pytest.mark.integration
@pytest.mark.parametrize("mutation", ["reference", "hold"])
def test_stale_plan_rejected_before_intent_or_unlink(databases, tmp_path, mutation):
    writer, _, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    doc = writer.ingest(_input(), b"raw", store)
    _, candidate = orphan(store)
    plan, sha = prepare(roles, tmp_path, store)
    if mutation == "reference":
        writer.ingest(_input(external="new"), b"orphan", store)
    else:
        change(Database(roles["lifecycle"]), doc, "hold", hold_id="new-hold")
    with pytest.raises(WorkbenchError, match="GC_STALE_PLAN"):
        gc.apply(Database(roles["admin"]), store, plan, sha, tmp_path / "journal")
    assert candidate.exists() and not (tmp_path / "journal").exists()


@pytest.mark.integration
@pytest.mark.parametrize("mutation", ["replace", "symlink", "hardlink", "corrupt", "missing"])
def test_changed_object_rejected_before_any_deletion(databases, tmp_path, mutation):
    _, _, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    _, candidate = orphan(store)
    _, other = orphan(store, b"other orphan")
    plan, sha = prepare(roles, tmp_path, store)
    if mutation == "replace":
        data = candidate.read_bytes()
        candidate.unlink()
        candidate.write_bytes(data)
    elif mutation == "symlink":
        candidate.unlink()
        candidate.symlink_to(other)
    elif mutation == "hardlink":
        os.link(candidate, tmp_path / "extra-link")
    elif mutation == "corrupt":
        candidate.write_bytes(b"modified")
    else:
        candidate.unlink()
    with pytest.raises((WorkbenchError, OSError)):
        gc.apply(Database(roles["admin"]), store, plan, sha, tmp_path / "journal")
    assert other.exists() and not (tmp_path / "journal").exists()


@pytest.mark.integration
def test_unlink_fsync_failure_and_durable_resume(databases, tmp_path, monkeypatch):
    _, _, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    _, candidate = orphan(store)
    plan, sha = prepare(roles, tmp_path, store)
    journal = tmp_path / "journal"
    real_fsync = os.fsync

    def fail_after_unlink(fd):
        if not candidate.exists():
            raise OSError("synthetic post-unlink durability failure")
        real_fsync(fd)

    with monkeypatch.context() as patch:
        patch.setattr(gc.os, "fsync", fail_after_unlink)
        with pytest.raises(OSError):
            gc.apply(Database(roles["admin"]), store, plan, sha, journal)
    assert (journal / "intent.json").exists() and not (journal / "complete.json").exists()
    assert not candidate.exists()
    # A fresh journal may not authorize missing objects; the original intent must be retained.
    with pytest.raises(WorkbenchError, match="GC_OBJECT_MISSING"):
        gc.apply(Database(roles["admin"]), store, plan, sha, tmp_path / "wrong-journal")
    result = gc.apply(Database(roles["admin"]), store, plan, sha, journal)
    assert result["resumed"] and (journal / "complete.json").exists()


@pytest.mark.integration
def test_no_deletion_without_durable_intent(databases, tmp_path, monkeypatch):
    _, _, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    _, candidate = orphan(store)
    plan, sha = prepare(roles, tmp_path, store)

    def fail(*args):
        raise OSError("synthetic intent failure")

    monkeypatch.setattr(gc, "_write_new", fail)
    with pytest.raises(OSError):
        gc.apply(Database(roles["admin"]), store, plan, sha, tmp_path / "journal")
    assert candidate.exists()


@pytest.mark.integration
def test_young_unexpected_inventory_permissions_and_wrong_store(databases, tmp_path):
    writer, _, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    young = store.put(b"young")
    receipt_path, sha = prepare(roles, tmp_path, store)
    assert json.loads(receipt_path.read_text())["payload"]["objects"] == []
    assert (store.root / young[:2] / young).exists()
    for role in (roles["writer"], roles["reader"]):
        with pytest.raises(WorkbenchError, match="OPERATOR_REQUIRED"):
            gc.plan(Database(role), store, tmp_path / "denied.owgc", operation_id="denied")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        gc.plan(
            Database(roles["lifecycle"]), store, tmp_path / "denied.owgc", operation_id="denied"
        )
    other = EvidenceStore(tmp_path / "other")
    with pytest.raises(WorkbenchError, match="GC_STORE_CHANGED"):
        gc.apply(Database(roles["admin"]), other, receipt_path, sha, tmp_path / "journal")
    (store.root / "unexpected").write_bytes(b"keep")
    with pytest.raises(WorkbenchError, match="GC_UNEXPECTED_ENTRY"):
        prepare(roles, tmp_path, store, "unexpected")


@pytest.mark.integration
def test_cli_plan_apply_and_digest_refusal(databases, tmp_path):
    _, _, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    _, candidate = orphan(store)
    env = {**os.environ, "OW_GC_DSN": roles["admin"], "OW_EVIDENCE_ROOT": str(store.root)}
    plan = tmp_path / "review.owgc"
    command = [sys.executable, "-m", "osint_workbench.cli", "gc"]
    run = subprocess.run(
        command + ["plan", "--file", str(plan), "--operation-id", "cli"],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    sha = json.loads(run.stdout)["sha256"]
    args = ["apply", "--file", str(plan), "--journal", str(tmp_path / "journal"), "--sha256"]
    denied = subprocess.run(command + args + ["0" * 64], env=env, capture_output=True, text=True)
    assert denied.returncode == 1 and candidate.exists()
    applied = subprocess.run(
        command + args + [sha], env=env, capture_output=True, text=True, check=True
    )
    assert json.loads(applied.stdout)["objects"] == 1 and not candidate.exists()


@pytest.mark.integration
def test_killed_cleanup_resumes_from_persisted_intent(databases, tmp_path):
    _, _, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    _, candidate = orphan(store)
    plan, sha = prepare(roles, tmp_path, store)
    journal = tmp_path / "journal"
    code = """
import os, sys
from pathlib import Path
from osint_workbench import garbage_collection as gc
from osint_workbench.database import Database
from osint_workbench.evidence import EvidenceStore
unlink = os.unlink
sha = sys.argv[3]
def killed(name, *args, **kwargs):
    result = unlink(name, *args, **kwargs)
    if name == sha:
        os._exit(73)
    return result
gc.os.unlink = killed
gc.apply(Database(os.environ["OW_GC_DSN"]),
         EvidenceStore(Path(sys.argv[1]), read_only=True), Path(sys.argv[2]),
         sys.argv[4], Path(sys.argv[5]))
"""
    killed = subprocess.run(
        [sys.executable, "-c", code, str(store.root), str(plan), candidate.name, sha, str(journal)],
        env={**os.environ, "OW_GC_DSN": roles["admin"]},
        capture_output=True,
        text=True,
    )
    assert killed.returncode == 73 and not candidate.exists()
    assert (journal / "intent.json").exists() and not (journal / "complete.json").exists()
    assert gc.apply(Database(roles["admin"]), store, plan, sha, journal)["resumed"]


@pytest.mark.integration
def test_row_security_and_inventory_bound_fail_closed(databases, tmp_path, monkeypatch):
    _, _, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    _, candidate = orphan(store)
    admin = Database(roles["admin"])
    try:
        with admin.connect() as conn:
            conn.execute("ALTER TABLE ow.snapshots ENABLE ROW LEVEL SECURITY")
        with pytest.raises(WorkbenchError, match="GC_UNSUPPORTED_ROW_SECURITY"):
            prepare(roles, tmp_path, store)
    finally:
        with admin.connect() as conn:
            conn.execute("ALTER TABLE ow.snapshots DISABLE ROW LEVEL SECURITY")
    monkeypatch.setattr(gc, "MAX_FILES", 1)
    with pytest.raises(WorkbenchError, match="GC_LIMIT_EXCEEDED"):
        prepare(roles, tmp_path, store)
    assert candidate.exists() and not (tmp_path / "cleanup.owgc").exists()


@pytest.mark.integration
def test_visible_intent_after_failed_fsync_must_be_resynced(databases, tmp_path, monkeypatch):
    _, _, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    _, candidate = orphan(store)
    plan, sha = prepare(roles, tmp_path, store)
    journal = tmp_path / "journal"
    real_fsync = os.fsync

    def fail_journal_fsync(fd):
        if journal.exists() and os.fstat(fd).st_ino == journal.stat().st_ino:
            raise OSError("synthetic intent directory persistence failure")
        real_fsync(fd)

    with monkeypatch.context() as patch:
        patch.setattr(gc.os, "fsync", fail_journal_fsync)
        with pytest.raises(OSError):
            gc.apply(Database(roles["admin"]), store, plan, sha, journal)
        assert (journal / "intent.json").exists() and candidate.exists()
        # A visible file alone is insufficient: retry must persist the intent first.
        with pytest.raises(OSError):
            gc.apply(Database(roles["admin"]), store, plan, sha, journal)
        assert candidate.exists()
    assert gc.apply(Database(roles["admin"]), store, plan, sha, journal)["resumed"]
