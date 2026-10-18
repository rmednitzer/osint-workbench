"""Bounded private checkpoint; data only, never executable SQL or external config."""

import base64
import json
import os
import re
import stat
import uuid
from contextlib import closing
from importlib.resources import files
from pathlib import Path

from psycopg import sql
from psycopg.types.json import Jsonb

from . import lifecycle
from .database import Database
from .errors import WorkbenchError
from .evidence import EvidenceStore
from .text import digest

MAX_BUNDLE = 128 * 1024 * 1024
MAX_METADATA = 32 * 1024 * 1024
MAX_OBJECT_BYTES = 64 * 1024 * 1024
MAX_ROWS = 100_000
CORE = (
    "sources",
    "collection_state",
    "lifecycle_control",
    *lifecycle.POLICY_TABLES,
    "snapshots",
    "documents",
    "document_heads",
    "jobs",
    "job_events",
    "chunks",
    "collection_runs",
    "enrichments",
    "assertions",
    "assertion_reviews",
    "briefings",
    "remote_operations",
)
RETRIEVAL = (
    "embedding_spaces",
    "retrieval_generations",
    "retrieval_members",
    "retrieval_exclusions",
    "retrieval_vectors",
    "retrieval_active",
)
SEQUENCES = {"job_events": "event_id", "assertion_reviews": "review_id"}
SETTLEMENT_COLUMNS = (
    "settlement_basis",
    "settled_cost",
    "settlement_evidence_sha256",
    "settled_by",
    "settlement_rationale",
    "settled_at",
)


def _json(value):
    return json.dumps(value, sort_keys=True, allow_nan=False).encode()


def _history(conn):
    scripts = [
        "schema.sql",
        "migrations/002_workflows.sql",
        "migrations/003_intelligence.sql",
        "migrations/004_lifecycle.sql",
        "migrations/005_collection_schedule.sql",
        "migrations/006_collector_role.sql",
        "migrations/007_retired_record_purge.sql",
        "migrations/008_collector_item_reuse.sql",
        "migrations/009_cloud_ledger.sql",
        "migrations/010_cloud_settlement.sql",
    ]
    expected = {
        str(i): digest(files("osint_workbench").joinpath(p).read_bytes())
        for i, p in enumerate(scripts, 1)
    }
    observed = {
        str(r["version"]): r["sha256"]
        for r in conn.execute("SELECT version,sha256 FROM ow.migrations").fetchall()
    }
    if observed != expected:
        raise WorkbenchError("RECOVERY_SCHEMA_MISMATCH")
    if conn.execute("SELECT to_regclass('ow.retrieval_migrations') AS t").fetchone()["t"]:
        rows = conn.execute(
            "SELECT version,sha256 FROM ow.retrieval_migrations ORDER BY version"
        ).fetchall()
        retrieval = [
            "retrieval.sql",
            "migrations/retrieval_002_lifecycle.sql",
            "migrations/retrieval_003_purge_role.sql",
            "migrations/retrieval_004_member_exclusions.sql",
        ]
        hashes = {
            i: digest(files("osint_workbench").joinpath(p).read_bytes())
            for i, p in enumerate(retrieval, 1)
        }
        if rows != [{"version": i, "sha256": sha} for i, sha in hashes.items()]:
            raise WorkbenchError("RECOVERY_SCHEMA_MISMATCH")
        expected.update({"retrieval/" + str(i): sha for i, sha in hashes.items()})
    names = set(CORE) | {"migrations"}
    if "retrieval/1" in expected:
        names.update((*RETRIEVAL, "retrieval_migrations"))
    observed_tables = {
        r["relname"]
        for r in conn.execute(
            "SELECT relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname='ow' AND c.relkind IN ('r','p','f','m')"
        ).fetchall()
    }
    if observed_tables != names:
        raise WorkbenchError("RECOVERY_SCHEMA_MISMATCH")
    return expected


def _full_visibility(conn):
    # A SELECT grant alone does not establish a complete backup under row filtering.
    # This reference profile has no supported RLS policy; reject even owner bypass.
    if conn.execute(
        "SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname='ow' AND c.relrowsecurity LIMIT 1"
    ).fetchone():
        raise WorkbenchError("RECOVERY_ROW_SECURITY_UNSUPPORTED")


def _columns(conn, table):
    return [
        r["attname"]
        for r in conn.execute(
            "SELECT attname FROM pg_attribute WHERE attrelid=%s::regclass "
            "AND attnum>0 AND NOT attisdropped AND attgenerated='' ORDER BY attnum",
            ("ow." + table,),
        ).fetchall()
    ]


def _database_identity(conn, history):
    major = conn.execute(
        "SELECT current_setting('server_version_num')::int / 10000 AS v"
    ).fetchone()["v"]
    version = None
    if "retrieval/1" in history:
        row = conn.execute(
            "SELECT extversion,n.nspname FROM pg_extension e JOIN pg_namespace n "
            "ON n.oid=e.extnamespace WHERE extname='vector'"
        ).fetchone()
        if not row or row["nspname"] != "ow_vector":
            raise WorkbenchError("RECOVERY_SCHEMA_MISMATCH")
        version = row["extversion"]
    return {"postgres_major": major, "pgvector": version}


def _references(tables):
    refs = set()
    for row in tables["snapshots"]:
        refs.update((row["raw_sha256"], row["text_sha256"]))
    refs.update(r["raw_sha256"] for r in tables["collection_runs"] if r["raw_sha256"])
    refs.update(r["raw_sha256"] for r in tables.get("collection_state", []) if r["raw_sha256"])
    return refs


def _provenance(tables, objects):
    try:
        _check_provenance(tables, objects)
    except (ValueError, TypeError, KeyError, AttributeError, IndexError, RecursionError):
        raise WorkbenchError("INVALID_RECOVERY_BUNDLE") from None


def _check_provenance(tables, objects):
    snapshots = {r["snapshot_id"]: r for r in tables["snapshots"]}
    documents = {r["document_id"]: r["body"] for r in tables["documents"]}
    for row in tables["documents"]:
        if digest(row["body"].encode()) != snapshots[row["snapshot_id"]]["text_sha256"]:
            raise WorkbenchError("RECOVERY_PROVENANCE_MISMATCH")
    for table in ("chunks", "assertions", "retrieval_vectors"):
        for row in tables.get(table, []):
            text = documents[row["document_id"]]
            start, end = row["start_offset"], row["end_offset"]
            if type(start) is not int or type(end) is not int or not 0 <= start < end <= len(text):
                raise WorkbenchError("RECOVERY_PROVENANCE_MISMATCH")
            part = text[start:end]
            if (
                (table == "assertions" and part != row["quote"])
                or (table != "assertions" and digest(part.encode()) != row["text_sha256"])
                or (table == "chunks" and part != row["body"])
            ):
                raise WorkbenchError("RECOVERY_PROVENANCE_MISMATCH")
    for row in tables["briefings"]:
        if digest(_json(row["content"])) != row["briefing_id"]:
            raise WorkbenchError("RECOVERY_PROVENANCE_MISMATCH")
    if _references(tables) != set(objects):
        raise WorkbenchError("RECOVERY_OBJECT_SET_MISMATCH")


def _write_new(path, data):
    """No overwrite; a partial write is never promoted to the requested filename."""
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temp = ".checkpoint-" + uuid.uuid4().hex
    try:
        fd = os.open(
            temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory
        )
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(
                temp, path.name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False
            )
            os.fsync(directory)
        finally:
            os.unlink(temp, dir_fd=directory)
    finally:
        os.close(directory)


def checkpoint(db: Database, store: EvidenceStore, path: Path):
    tables, rows, size = {}, 0, 0
    with store.transaction(db) as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        conn.execute("SELECT pg_advisory_xact_lock(418287405)")
        history = _history(conn)  # Validate the already-established MVCC snapshot.
        _full_visibility(conn)
        database = _database_identity(conn, history)
        captured = conn.execute("SELECT transaction_timestamp()::text AS t").fetchone()["t"]
        names = CORE + (RETRIEVAL if "retrieval/1" in history else ())
        for name in names:
            columns = sql.SQL(",").join(map(sql.Identifier, _columns(conn, name)))
            query = sql.SQL("SELECT row_to_json(t)::text AS value FROM (SELECT {} FROM ow.{}) t")
            with conn.cursor(name="checkpoint_" + name) as cursor:
                cursor.execute(query.format(columns, sql.Identifier(name)))
                values = []
                for row in cursor:
                    value = json.loads(row["value"])
                    size += len(_json(value))
                    rows += 1
                    if size > MAX_METADATA or rows > MAX_ROWS:
                        raise WorkbenchError("RECOVERY_LIMIT_EXCEEDED")
                    values.append(value)
            tables[name] = values
        # A DB commit is accepted only after its immutable evidence is durable.
        # Concurrent accepted writes after this snapshot are deliberately excluded.
        objects, total = {}, 0
        for sha in sorted(_references(tables)):
            data = store.get(sha)
            total += len(data)
            if total > MAX_OBJECT_BYTES:
                raise WorkbenchError("RECOVERY_LIMIT_EXCEEDED")
            objects[sha] = base64.b64encode(data).decode("ascii")
    _provenance(tables, objects)
    policy = lifecycle.validate_policy(
        {
            "format": 1,
            "kind": "lifecycle_policy",
            "control": tables["lifecycle_control"][0],
            "tables": {name: tables[name] for name in lifecycle.POLICY_TABLES},
        }
    )
    lifecycle.assert_no_purged_documents(tables, policy)
    payload = {
        "format": 2,
        "captured_at": captured,
        "migrations": history,
        "database": database,
        "tables": tables,
        "objects": objects,
    }
    encoded = _json(payload)
    bundle = _json({"payload": payload, "sha256": digest(encoded)})
    if len(bundle) > MAX_BUNDLE:
        raise WorkbenchError("RECOVERY_LIMIT_EXCEEDED")
    _write_new(path, bundle)
    return {
        "sha256": digest(encoded),
        "rows": rows,
        "objects": len(objects),
        "captured_at": captured,
        "classification": "private_checkpoint",
    }


def _read_envelope(path, expected_sha, *, limit=None):
    limit = MAX_BUNDLE if limit is None else limit
    if not isinstance(expected_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
        raise WorkbenchError("INVALID_RECOVERY_DIGEST")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise WorkbenchError("INVALID_RECOVERY_BUNDLE")
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise WorkbenchError("RECOVERY_LIMIT_EXCEEDED")
    bundle = json.loads(raw)
    if set(bundle) != {"payload", "sha256"}:
        raise WorkbenchError("INVALID_RECOVERY_BUNDLE")
    payload = bundle["payload"]
    if digest(_json(payload)) != expected_sha or bundle["sha256"] != expected_sha:
        raise WorkbenchError("RECOVERY_DIGEST_MISMATCH")
    return payload


def _read(path, expected_sha):
    payload = _read_envelope(path, expected_sha)
    if (
        set(payload) != {"format", "captured_at", "migrations", "database", "tables", "objects"}
        or type(payload["format"]) is not int
        or payload["format"] != 2
    ):
        raise WorkbenchError("INVALID_RECOVERY_BUNDLE")
    return payload


# Published core version -> the optional retrieval profiles it shipped with.
PUBLISHED_PAIRS = {4: (2,), 5: (2,), 6: (2,), 7: (3,), 8: (3, 4), 9: (4,)}


def _known_legacy_history(observed, current, version):
    """Only exact published core/profile pairs older than the current history.

    The current target history has already been checked against every packaged
    migration. Do not treat an arbitrary prefix, missing profile or unknown hash
    as proof of a compatible earlier data contract.
    """
    if version not in PUBLISHED_PAIRS:
        return False
    for profile in PUBLISHED_PAIRS[version]:
        keys = {str(i) for i in range(1, version + 1)}
        keys |= {f"retrieval/{i}" for i in range(1, profile + 1)}
        expected = {key: value for key, value in current.items() if key in keys}
        if observed == expected and observed != current:
            return True
    return False


def restore(
    db: Database,
    path: Path,
    expected_sha: str,
    root: Path,
    *,
    policy_path: Path,
    policy_sha: str,
    minimum_revision: int,
):
    """Only an empty migrated target and an absent object root. Never executes bundle SQL."""
    payload = _read(path, expected_sha)
    tables, objects = payload["tables"], payload["objects"]
    policy = _read_envelope(policy_path, policy_sha, limit=lifecycle.MAX_POLICY)
    tables = lifecycle.reconcile_policy(tables, policy, minimum_revision)
    lifecycle.assert_no_purged_documents(tables, policy)
    _provenance(tables, objects)
    with closing(db.connect()) as conn:
        conn.execute("SELECT pg_advisory_xact_lock(418287405)")
        history = _history(conn)
        _full_visibility(conn)
        names = CORE + (RETRIEVAL if "retrieval/1" in history else ())

        # V6/V7/V8 change defaults, grants and allowed lifecycle actions only.
        # Exact known v5-v8 retain the same core layout; v4 needs an empty schedule.
        # Profiles before 4 have no exclusion table: no generation excluded anything.
        # No schema3/format1 inference or mixed migration history is accepted.
        # Tables introduced after a legacy pair are empty at adoption: no older
        # release recorded remote attempts or retrieval exclusions.
        def latest(prefix):
            return max(
                (
                    int(k.removeprefix(prefix))
                    for k in payload["migrations"]
                    if k.startswith(prefix)
                    and k.removeprefix(prefix).isascii()
                    and k.removeprefix(prefix).isdigit()
                ),
                default=0,
            )

        core, profile = latest(""), latest("retrieval/")
        absent = ({"remote_operations"} if core < 9 else set()) | (
            {"retrieval_exclusions"} if profile < 4 else set()
        )
        legacy = set(names) - absent
        adopted = {
            version: _known_legacy_history(payload["migrations"], history, version)
            and set(tables) == (legacy - {"collection_state"} if version == 4 else legacy)
            for version in PUBLISHED_PAIRS
        }
        adopted_v4 = adopted[4]
        if any(adopted.values()):
            for name in absent & set(names):
                tables[name] = []
            # Core 9 predates settlement: every adopted attempt is unsettled.
            attempts = tables["remote_operations"]
            if not isinstance(attempts, list) or not all(isinstance(r, dict) for r in attempts):
                raise WorkbenchError("INVALID_RECOVERY_BUNDLE")
            for row in attempts:
                if set(SETTLEMENT_COLUMNS) & set(row):
                    raise WorkbenchError("RECOVERY_COLUMNS_MISMATCH")
                row.update(dict.fromkeys(SETTLEMENT_COLUMNS))
        if adopted_v4:
            tables["collection_state"] = []
            if any("http_status" in row for row in tables["collection_runs"]):
                raise WorkbenchError("RECOVERY_COLUMNS_MISMATCH")
            for row in tables["collection_runs"]:
                row["http_status"] = None
        if (
            (history != payload["migrations"] and not any(adopted.values()))
            or set(tables) != set(names)
            or _database_identity(conn, history) != payload["database"]
        ):
            raise WorkbenchError("RECOVERY_SCHEMA_MISMATCH")
        conn.execute(
            sql.SQL("LOCK TABLE {} IN ACCESS EXCLUSIVE MODE").format(
                sql.SQL(",").join(sql.Identifier("ow", name) for name in names)
            )
        )
        count, size = 0, 0
        for name in names:
            existing = conn.execute(
                sql.SQL("SELECT 1 FROM ow.{} LIMIT 1").format(sql.Identifier(name))
            ).fetchone()
            if name == "lifecycle_control":
                control = conn.execute("SELECT revision FROM ow.lifecycle_control").fetchone()
                if not control or control["revision"] != 0:
                    raise WorkbenchError("RECOVERY_TARGET_NOT_EMPTY")
            elif existing:
                raise WorkbenchError("RECOVERY_TARGET_NOT_EMPTY")
            columns = _columns(conn, name)
            if not isinstance(tables[name], list):
                raise WorkbenchError("INVALID_RECOVERY_BUNDLE")
            for row in tables[name]:
                count += 1
                size += len(_json(row))
                if set(row) != set(columns):
                    raise WorkbenchError("RECOVERY_COLUMNS_MISMATCH")
        if count > MAX_ROWS or size > MAX_METADATA:
            raise WorkbenchError("RECOVERY_LIMIT_EXCEEDED")
        # Exclusive creation prevents mixing snapshots or overwriting another store.
        parent = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.mkdir(root.name, mode=0o700, dir_fd=parent)
            os.fsync(parent)  # The new root entry must survive before metadata acceptance.
        finally:
            os.close(parent)
        store, total = EvidenceStore(root), 0
        with store.acceptance(conn):
            for sha, encoded in objects.items():
                data = base64.b64decode(encoded, validate=True)
                total += len(data)
                if total > MAX_OBJECT_BYTES:
                    raise WorkbenchError("RECOVERY_LIMIT_EXCEEDED")
                if digest(data) != sha or store.put(data) != sha:
                    raise WorkbenchError("RECOVERY_OBJECT_INTEGRITY_MISMATCH")
            for name in names:
                if name == "lifecycle_control":
                    control = tables[name][0]
                    conn.execute(
                        "UPDATE ow.lifecycle_control SET dataset_id=%s,revision=%s",
                        (control["dataset_id"], control["revision"]),
                    )
                    continue
                columns = sql.SQL(",").join(map(sql.Identifier, _columns(conn, name)))
                query = sql.SQL(
                    "INSERT INTO ow.{} ({}) OVERRIDING SYSTEM VALUE "
                    "SELECT {} FROM jsonb_populate_record(NULL::ow.{},%s)"
                ).format(sql.Identifier(name), columns, columns, sql.Identifier(name))
                for row in tables[name]:
                    conn.execute(query, (Jsonb(row),))
            # Do not revive work or external effects from a historical checkpoint.
            quarantined = conn.execute("""UPDATE ow.jobs SET status='failed',fence=NULL,
                lease_until=NULL,last_error='RECOVERY_RECONCILIATION_REQUIRED',
                updated_at=clock_timestamp() WHERE status IN ('ready','running') RETURNING job_id,
                attempt""").fetchall()
            for name, column in SEQUENCES.items():
                conn.execute(
                    sql.SQL(
                        "SELECT setval(pg_get_serial_sequence(%s,%s),"
                        "coalesce(max({}),1),max({}) IS NOT NULL) FROM ow.{}"
                    ).format(sql.Identifier(column), sql.Identifier(column), sql.Identifier(name)),
                    ("ow." + name, column),
                )
            for row in quarantined:
                conn.execute(
                    "INSERT INTO ow.job_events(job_id,attempt,event,code) "
                    "VALUES (%s,%s,'failed','RECOVERY_RECONCILIATION_REQUIRED')",
                    (row["job_id"], row["attempt"]),
                )
            conn.execute("UPDATE ow.sources SET enabled=false")
            conn.execute(
                "UPDATE ow.collection_state SET etag=NULL,last_modified=NULL,"
                "raw_sha256=NULL,failures=0,next_attempt=clock_timestamp()"
            )
            conn.execute("""UPDATE ow.collection_runs SET status='interrupted',
                error_code='RECOVERY_RECONCILIATION_REQUIRED',finished_at=clock_timestamp()
                WHERE status='running'""")
            if "retrieval/1" in history:
                conn.execute("""UPDATE ow.retrieval_generations SET status='failed',
                    error_code='RECOVERY_RECONCILIATION_REQUIRED' WHERE status='building'""")
    return {
        "sha256": expected_sha,
        "rows": count,
        "objects": len(objects),
        "quarantined_jobs": len(quarantined),
        "sources_enabled": False,
        "status": "restored_requires_operator_reconciliation",
        "policy_sha256": policy_sha,
        "policy_revision": policy["control"]["revision"],
        **{f"adopted_core_v{version}": value for version, value in adopted.items()},
    }
