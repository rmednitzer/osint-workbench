"""Native lock-loss/process-death acceptance for cooperative evidence writers."""

import fcntl
import json
import os
import select
import subprocess
import sys

import psycopg
import pytest

from osint_workbench import garbage_collection as gc
from osint_workbench.database import Database
from osint_workbench.errors import WorkbenchError
from osint_workbench.evidence import EvidenceStore
from tests.test_garbage_collection import orphan, prepare

pytestmark = pytest.mark.integration
PAYLOAD = b"byte-identical orphan"

GC_PROCESS = r"""
import json,os,sys
from pathlib import Path
from osint_workbench import garbage_collection as gc
from osint_workbench.database import Database
from osint_workbench.evidence import EvidenceStore

root,plan,sha,journal,candidate,stage=sys.argv[1:]
backend=None
original_state=gc._state
original_unlink=os.unlink

def pause(point):
    print(json.dumps({'stage':point,'backend':backend}),flush=True)
    if sys.stdin.readline().strip()!='continue':
        raise RuntimeError('synthetic controller disconnected')

def state(conn):
    global backend
    result=original_state(conn)
    backend=conn.info.backend_pid
    if stage=='captured':
        pause('captured')
    return result

def unlink(name,*args,**kwargs):
    if name==candidate and stage=='before-unlink':
        pause('before-unlink')
    result=original_unlink(name,*args,**kwargs)
    if name==candidate and stage=='after-unlink':
        pause('after-unlink')
    return result

gc._state=state
os.unlink=unlink
try:
    result=gc.apply(Database(os.environ['OW_GC_TEST_DSN']),EvidenceStore(Path(root)),
                    Path(plan),sha,Path(journal))
    print(json.dumps({'stage':'finished','status':'completed','objects':result['objects']}),flush=True)
except Exception as error:
    print(json.dumps({'stage':'finished','status':'failed','type':type(error).__name__}),flush=True)
"""

WRITER_PROCESS = r"""
import json,os,sys
from pathlib import Path
from osint_workbench.contracts import DocumentInput
from osint_workbench.database import Database
from osint_workbench.evidence import EvidenceStore

db=Database(os.environ['OW_WRITER_TEST_DSN'])
store=EvidenceStore(Path(sys.argv[1]))
original_connect=db.connect

def connect(*args,**kwargs):
    conn=original_connect(*args,**kwargs)
    print(json.dumps({'stage':'db-admitted','backend':conn.info.backend_pid}),flush=True)
    return conn

db.connect=connect
print(json.dumps({'stage':'ready'}),flush=True)
try:
    document=db.ingest(DocumentInput(source_id='fixture',external_id='barrier-input',
        title='Synthetic',text='byte-identical orphan'),b'byte-identical orphan',store)
    print(json.dumps({'stage':'accepted','document_id':document}),flush=True)
except Exception as error:
    print(json.dumps({'stage':'failed','type':type(error).__name__,
                      'code':getattr(error,'code',None)}),flush=True)
"""


def line(process, seconds=10):
    assert process.stdout is not None
    ready, _, _ = select.select([process.stdout], [], [], seconds)
    assert ready, "synthetic child did not reach its bounded coordination point"
    raw = process.stdout.readline()
    assert raw, "synthetic child exited before coordination"
    return json.loads(raw)


def child(script, arguments, roles):
    return subprocess.Popen(
        [sys.executable, "-u", "-c", script, *map(str, arguments)],
        env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONIOENCODING": "utf-8",
            "OW_GC_TEST_DSN": roles["admin"],
            "OW_WRITER_TEST_DSN": roles["writer"],
        },
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )


def stop(process):
    if process is not None:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=10)


def terminate_backend(roles, pid):
    # Direct admin connection intentionally does not wait for the GC advisory lock.
    # The PID was emitted by this test's own child after its actual reference read.
    with psycopg.connect(roles["admin"], autocommit=True) as conn:
        row = conn.execute(
            "SELECT datname=current_database() FROM pg_stat_activity WHERE pid=%s", (pid,)
        ).fetchone()
        assert row == (True,)
        assert conn.execute("SELECT pg_terminate_backend(%s,1000)", (pid,)).fetchone() == (True,)


def assert_store_exclusive(root):
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(BlockingIOError):
            fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
    finally:
        os.close(descriptor)


def no_accepted_documents(roles):
    with psycopg.connect(roles["admin"]) as conn:
        assert conn.execute("SELECT count(*) FROM ow.documents").fetchone() == (0,)


def accepted_evidence(roles, store, result):
    assert result["stage"] == "accepted"
    with psycopg.connect(roles["admin"]) as conn:
        row = conn.execute(
            "SELECT s.raw_sha256,s.text_sha256 FROM ow.documents d "
            "JOIN ow.snapshots s USING(snapshot_id) WHERE document_id=%s",
            (result["document_id"],),
        ).fetchone()
        assert conn.execute("SELECT count(*) FROM ow.documents").fetchone() == (1,)
    assert row is not None
    assert store.get(row[0]) == store.get(row[1]) == PAYLOAD


@pytest.mark.parametrize("stage", ["captured", "before-unlink"])
def test_pg_lock_loss_cannot_admit_missing_evidence_reference(databases, tmp_path, stage):
    _, _, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    sha, candidate = orphan(store, PAYLOAD)
    plan, plan_sha = prepare(roles, tmp_path, store)
    journal = tmp_path / "journal"
    collector = writer = None
    try:
        collector = child(GC_PROCESS, [store.root, plan, plan_sha, journal, sha, stage], roles)
        point = line(collector)
        assert point["stage"] == stage
        terminate_backend(roles, point["backend"])
        # The database session lock has gone, but a cross-process shared admission
        # attempt must still fail against the actual store-directory exclusive lock.
        assert_store_exclusive(store.root)
        writer = child(WRITER_PROCESS, [store.root], roles)
        assert line(writer)["stage"] == "ready"
        assert line(writer)["stage"] == "db-admitted"
        assert_store_exclusive(store.root)
        no_accepted_documents(roles)
        assert writer.poll() is None
        assert collector.stdin is not None
        collector.stdin.write(b"continue\n")
        collector.stdin.flush()
        outcome = line(collector)
        assert outcome["stage"] == "finished"
        collector.wait(timeout=10)
        accepted_evidence(roles, store, line(writer))
        writer.wait(timeout=10)
        assert candidate.exists()
        if stage == "before-unlink":
            assert (journal / "intent.json").exists()
        # A completion file, if written before DB-context failure, describes only
        # orphan deletion; the subsequently accepted writer recreates its evidence.
        if (journal / "complete.json").exists():
            completion = json.loads((journal / "complete.json").read_bytes())["payload"]
            assert completion["plan_sha256"] == plan_sha and completion["objects"] == 1
        with pytest.raises(WorkbenchError, match="GC_STALE_PLAN"):
            gc.apply(Database(roles["admin"]), store, plan, plan_sha, journal)
        assert store.get(sha) == PAYLOAD
    finally:
        stop(writer)
        stop(collector)


@pytest.mark.parametrize("stage", ["before-unlink", "after-unlink"])
def test_killed_gc_releases_process_barrier_and_old_journal_cannot_delete_new_reference(
    databases, tmp_path, stage
):
    _, _, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    sha, candidate = orphan(store, PAYLOAD)
    plan, plan_sha = prepare(roles, tmp_path, store)
    journal = tmp_path / "journal"
    collector = writer = None
    try:
        collector = child(GC_PROCESS, [store.root, plan, plan_sha, journal, sha, stage], roles)
        assert line(collector)["stage"] == stage
        assert_store_exclusive(store.root)
        assert (journal / "intent.json").exists()
        assert not (journal / "complete.json").exists()
        assert candidate.exists() is (stage == "before-unlink")
        collector.kill()
        collector.wait(timeout=10)
        writer = child(WRITER_PROCESS, [store.root], roles)
        assert line(writer)["stage"] == "ready"
        assert line(writer)["stage"] == "db-admitted"
        accepted_evidence(roles, store, line(writer))
        writer.wait(timeout=10)
        assert candidate.exists() and store.get(sha) == PAYLOAD
        with pytest.raises(WorkbenchError, match="GC_STALE_PLAN"):
            gc.apply(Database(roles["admin"]), store, plan, plan_sha, journal)
        assert (journal / "intent.json").exists() and not (journal / "complete.json").exists()
        assert store.get(sha) == PAYLOAD
    finally:
        stop(writer)
        stop(collector)
