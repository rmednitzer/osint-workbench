"""Explicit, bounded orphan-object cleanup. Never purges retained database records."""

import os
import re
import stat
import time
from pathlib import Path
from typing import Literal

from pydantic import Field

from .contracts import Digest, Identifier, StrictModel
from .errors import WorkbenchError
from .evidence import MAX_OBJECT, EvidenceStore
from .lifecycle import _authorize
from .recovery import _history, _json, _read_envelope, _write_new
from .text import digest

MAX_FILES = 10_000
MAX_BYTES = 64 * 1024 * 1024
MAX_PLAN = 8 * 1024 * 1024
MIN_AGE = 3600


class Object(StrictModel):
    sha256: Digest
    device: int = Field(ge=0)
    inode: int = Field(ge=0)
    size: int = Field(ge=0, le=MAX_OBJECT)
    mtime_ns: int = Field(ge=0)
    ctime_ns: int = Field(ge=0)


class Plan(StrictModel):
    format: Literal[1] = 1
    kind: Literal["orphan_gc"] = "orphan_gc"
    operation_id: Identifier
    dataset_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    policy_revision: int = Field(ge=0)
    created_ns: int = Field(ge=0)
    minimum_age_seconds: int = Field(ge=MIN_AGE, le=31 * 86400)
    root_device: int = Field(ge=0)
    root_inode: int = Field(ge=0)
    references_sha256: Digest
    objects: list[Object] = Field(max_length=MAX_FILES)


def _identity(info, sha):
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise WorkbenchError("GC_UNSAFE_OBJECT")
    return Object(
        sha256=sha,
        device=info.st_dev,
        inode=info.st_ino,
        size=info.st_size,
        mtime_ns=info.st_mtime_ns,
        ctime_ns=info.st_ctime_ns,
    )


def _state(conn):
    _authorize(conn)
    _history(conn)  # Unknown schema/profile tables fail closed: references may have changed.
    if conn.execute(
        "SELECT 1 FROM pg_class WHERE oid IN ('ow.snapshots'::regclass, "
        "'ow.collection_runs'::regclass) AND relrowsecurity"
    ).fetchone():
        raise WorkbenchError("GC_UNSUPPORTED_ROW_SECURITY")
    control = conn.execute("SELECT dataset_id,revision FROM ow.lifecycle_control").fetchone()
    rows = conn.execute(
        "SELECT sha FROM (SELECT raw_sha256 AS sha FROM ow.snapshots UNION "
        "SELECT text_sha256 FROM ow.snapshots UNION SELECT raw_sha256 FROM ow.collection_runs "
        "WHERE raw_sha256 IS NOT NULL) refs ORDER BY sha LIMIT 100001"
    ).fetchall()
    if len(rows) > 100_000:
        raise WorkbenchError("GC_LIMIT_EXCEEDED")
    refs = {row["sha"] for row in rows}
    return str(control["dataset_id"]), control["revision"], refs


def _open_root(store):
    return os.open(store.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)


def _check_file(directory, obj):
    """Anchor reads to the already opened shard, never a caller-controlled filename."""
    fd = os.open(obj.sha256, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    with os.fdopen(fd, "rb") as stream:
        if _identity(os.fstat(stream.fileno()), obj.sha256) != obj:
            raise WorkbenchError("GC_OBJECT_CHANGED")
        data = stream.read(MAX_OBJECT + 1)
        if len(data) != obj.size or digest(data) != obj.sha256:
            raise WorkbenchError("GC_OBJECT_CHANGED")
        if _identity(os.fstat(stream.fileno()), obj.sha256) != obj:
            raise WorkbenchError("GC_OBJECT_CHANGED")


def plan(db, store: EvidenceStore, path: Path, *, operation_id, minimum_age_seconds=86400):
    # Validate bounds before any filesystem/database work.
    IdentifierCheck.model_validate(
        {"operation_id": operation_id, "minimum_age_seconds": minimum_age_seconds}
    )
    with db.connect(lifecycle_exclusive=True) as conn:
        dataset, revision, refs = _state(conn)
        root = _open_root(store)
        try:
            info, now, objects, count, total = os.fstat(root), time.time_ns(), [], 0, 0
            # scandir remains streaming; neither arbitrary entries nor retained files bypass bounds.
            with os.scandir(root) as shards:
                for shard in shards:
                    count += 1
                    if count > MAX_FILES:
                        raise WorkbenchError("GC_LIMIT_EXCEEDED")
                    if not re.fullmatch(r"[0-9a-f]{2}", shard.name):
                        raise WorkbenchError("GC_UNEXPECTED_ENTRY")
                    child = os.open(
                        shard.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root
                    )
                    try:
                        with os.scandir(child) as entries:
                            for entry in entries:
                                count += 1
                                if count > MAX_FILES:
                                    raise WorkbenchError("GC_LIMIT_EXCEEDED")
                                sha = entry.name
                                if not re.fullmatch(shard.name + r"[0-9a-f]{62}", sha):
                                    raise WorkbenchError("GC_UNEXPECTED_ENTRY")
                                obj = _identity(entry.stat(follow_symlinks=False), sha)
                                if obj.device != info.st_dev:
                                    raise WorkbenchError("GC_CROSS_DEVICE_OBJECT")
                                if sha in refs or now - obj.mtime_ns < minimum_age_seconds * 10**9:
                                    continue
                                total += obj.size
                                if total > MAX_BYTES:
                                    raise WorkbenchError("GC_LIMIT_EXCEEDED")
                                _check_file(child, obj)
                                objects.append(obj)
                    finally:
                        os.close(child)
            value = Plan(
                operation_id=operation_id,
                dataset_id=dataset,
                policy_revision=revision,
                created_ns=now,
                minimum_age_seconds=minimum_age_seconds,
                root_device=info.st_dev,
                root_inode=info.st_ino,
                references_sha256=digest(_json(sorted(refs))),
                objects=sorted(objects, key=lambda o: o.sha256),
            )
            payload = value.model_dump(mode="json")
            sha = digest(_json(payload))
            _write_new(path, _json({"payload": payload, "sha256": sha}))
        finally:
            os.close(root)
    return {
        "sha256": sha,
        "objects": len(objects),
        "bytes": total,
        "classification": "private_gc_plan",
        "physical_record_erasure": False,
    }


class IdentifierCheck(StrictModel):
    operation_id: Identifier
    minimum_age_seconds: int = Field(ge=MIN_AGE, le=31 * 86400)


def _journal(path, plan_sha):
    """Durable intent precedes every unlink. A missing/partial intent never authorizes resume."""
    expected = {"format": 1, "kind": "orphan_gc_intent", "plan_sha256": plan_sha}
    existed = path.exists()
    if not existed:
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.mkdir(path.name, 0o700, dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)
        _write_new(
            path / "intent.json", _json({"payload": expected, "sha256": digest(_json(expected))})
        )
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    os.close(directory)
    actual = _read_envelope(path / "intent.json", digest(_json(expected)), limit=4096)
    if actual != expected:
        raise WorkbenchError("GC_JOURNAL_MISMATCH")
    return existed


def apply(db, store: EvidenceStore, path: Path, expected_sha: str, journal: Path):
    value = Plan.model_validate_json(_json(_read_envelope(path, expected_sha, limit=MAX_PLAN)))
    if len({o.sha256 for o in value.objects}) != len(value.objects):
        raise WorkbenchError("GC_INVALID_PLAN")
    total = sum(o.size for o in value.objects)
    if (
        total > MAX_BYTES
        or any(
            value.created_ns - o.mtime_ns < value.minimum_age_seconds * 10**9 for o in value.objects
        )
        or value.created_ns > time.time_ns()
    ):
        raise WorkbenchError("GC_INVALID_PLAN")
    # A plan is data, never filesystem authority outside fixed digest/shard paths.
    with db.connect(lifecycle_exclusive=True) as conn:
        dataset, revision, refs = _state(conn)
        if (dataset, revision, digest(_json(sorted(refs)))) != (
            value.dataset_id,
            value.policy_revision,
            value.references_sha256,
        ) or any(o.sha256 in refs for o in value.objects):
            raise WorkbenchError("GC_STALE_PLAN")
        root = _open_root(store)
        directories = {}
        try:
            info = os.fstat(root)
            if (info.st_dev, info.st_ino) != (value.root_device, value.root_inode):
                raise WorkbenchError("GC_STORE_CHANGED")
            # Open every shard once, then re-use anchored descriptors throughout deletion.
            for shard in sorted({o.sha256[:2] for o in value.objects}):
                directories[shard] = os.open(
                    shard, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root
                )
            # Validate existing journal before allowing any absent object.
            resume = journal.exists()
            if resume:
                _journal(journal, expected_sha)
            for obj in value.objects:
                try:
                    _check_file(directories[obj.sha256[:2]], obj)
                except FileNotFoundError:
                    if not resume:
                        raise WorkbenchError("GC_OBJECT_MISSING") from None
            _journal(journal, expected_sha)
            for obj in value.objects:
                directory = directories[obj.sha256[:2]]
                try:
                    _check_file(directory, obj)
                    os.unlink(obj.sha256, dir_fd=directory)
                except FileNotFoundError:
                    if not resume:
                        raise WorkbenchError("GC_OBJECT_MISSING") from None
                # Also fsync on resume: prior unlink may have happened before its directory fsync.
                os.fsync(directory)
            result = {
                "format": 1,
                "kind": "orphan_gc_completion",
                "plan_sha256": expected_sha,
                "objects": len(value.objects),
                "bytes": total,
                "physical_record_erasure": False,
            }
            encoded = _json(result)
            try:
                _write_new(
                    journal / "complete.json", _json({"payload": result, "sha256": digest(encoded)})
                )
            except FileExistsError:
                if _read_envelope(journal / "complete.json", digest(encoded), limit=4096) != result:
                    raise WorkbenchError("GC_JOURNAL_MISMATCH") from None
            return {**result, "resumed": resume}
        finally:
            for fd in directories.values():
                os.close(fd)
            os.close(root)
