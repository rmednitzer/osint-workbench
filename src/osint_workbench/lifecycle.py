"""Operator-only preservation and logical suppression; no physical-erasure claim."""

import json
from typing import Annotated, Literal
from uuid import UUID

from psycopg import sql
from psycopg.types.json import Jsonb
from pydantic import AwareDatetime, Field, field_validator

from .contracts import Digest, Identifier, StrictModel
from .errors import WorkbenchError
from .text import digest

POLICY_TABLES = ("lifecycle_items", "lifecycle_holds", "lifecycle_tombstones", "lifecycle_events")
MAX_POLICY = 32 * 1024 * 1024


class Change(StrictModel):
    action: Literal["retention", "hold", "release", "retire"]
    document_id: Digest
    operation_id: Identifier
    actor: str = Field(min_length=1, max_length=96)
    rationale: str = Field(min_length=1, max_length=2000)
    retention_class: Identifier | None = None
    retain_until: AwareDatetime | None = None
    hold_id: Identifier | None = None


class Control(StrictModel):
    singleton: Literal[True]
    dataset_id: UUID
    revision: int = Field(ge=0, le=100_000)


class Item(StrictModel):
    source_id: Identifier
    external_key: Digest
    retention_class: Identifier
    retain_until: AwareDatetime | None


class Hold(StrictModel):
    hold_id: Identifier
    source_id: Identifier
    external_key: Digest
    placed_at: AwareDatetime
    released_at: AwareDatetime | None


class Tombstone(StrictModel):
    source_id: Identifier
    external_key: Digest
    retired_at: AwareDatetime


class Event(StrictModel):
    operation_id: Identifier
    request_sha256: Digest
    revision: int = Field(gt=0)
    source_id: Identifier
    external_key: Digest
    action: Literal["retention", "hold", "release", "retire", "purge"]
    actor: str = Field(min_length=1, max_length=96)
    rationale: str = Field(min_length=1, max_length=2000)
    result: dict
    recorded_at: AwareDatetime


PURGE_COUNT_KEYS = frozenset(
    {
        "documents",
        "snapshots",
        "document_heads",
        "jobs",
        "job_events",
        "chunks",
        "enrichments",
        "assertions",
        "assertion_reviews",
        "briefings",
        "retrieval_vectors",
        "retrieval_members",
        "retrieval_active",
        "retrieval_generations_invalidated",
    }
)


class PurgeResult(StrictModel):
    format: Literal[1]
    kind: Literal["retired_record_purge"]
    operation_id: Identifier
    plan_sha256: Digest
    dataset_id: UUID
    source_id: Identifier
    external_key: Digest
    policy_revision_before: int = Field(ge=0)
    revision: int = Field(gt=0)
    counts: dict[str, Annotated[int, Field(ge=0)]]
    sql_deleted: Literal[True]
    physical_erasure: Literal[False]
    cas_objects_deleted: Literal[0]
    backup_erasure: Literal[False]

    @field_validator("counts")
    @classmethod
    def exact_count_keys(cls, value):
        if set(value) != PURGE_COUNT_KEYS or value.get("documents", 0) < 1:
            raise ValueError("complete fixed purge counts and deleted documents required")
        return value

    @field_validator("format", "cas_objects_deleted", mode="before")
    @classmethod
    def literal_integers(cls, value):
        if type(value) is not int:
            raise ValueError("integer required")
        return value

    @field_validator("sql_deleted", "physical_erasure", "backup_erasure", mode="before")
    @classmethod
    def literal_booleans(cls, value):
        if type(value) is not bool:
            raise ValueError("boolean required")
        return value


def purge_request_sha(operation_id, source_id, external_key, actor, rationale, plan_sha256):
    payload = {
        "format": 1,
        "kind": "retired_record_purge",
        "operation_id": operation_id,
        "source_id": source_id,
        "external_key": external_key,
        "actor": actor,
        "rationale": rationale,
        "plan_sha256": plan_sha256,
    }
    return digest(json.dumps(payload, sort_keys=True, allow_nan=False).encode())


MODELS = {
    "lifecycle_items": Item,
    "lifecycle_holds": Hold,
    "lifecycle_tombstones": Tombstone,
    "lifecycle_events": Event,
}


def assert_key_visible(conn, source_id, external_key):
    row = conn.execute(
        """SELECT
        EXISTS(SELECT 1 FROM ow.lifecycle_tombstones WHERE source_id=%s AND external_key=%s)
        OR EXISTS(SELECT 1 FROM ow.lifecycle_items WHERE source_id=%s AND external_key=%s
                  AND retain_until<=clock_timestamp()) AS hidden""",
        (source_id, external_key, source_id, external_key),
    ).fetchone()
    if row["hidden"]:
        raise WorkbenchError("DOCUMENT_RETIRED_OR_EXPIRED")


def assert_document_visible(conn, document_id):
    if not conn.execute(
        "SELECT 1 FROM ow.visible_documents WHERE document_id=%s", (document_id,)
    ).fetchone():
        raise WorkbenchError("DOCUMENT_RETIRED_OR_EXPIRED")


def _authorize(conn):
    if not conn.execute(
        "SELECT pg_has_role(current_user,'ow_lifecycle','MEMBER') AS ok"
    ).fetchone()["ok"]:
        raise WorkbenchError("LIFECYCLE_OPERATOR_REQUIRED")


def _key(conn, document_id):
    row = conn.execute(
        "SELECT source_id,external_key FROM ow.documents WHERE document_id=%s", (document_id,)
    ).fetchone()
    if not row:
        raise WorkbenchError("DOCUMENT_NOT_FOUND")
    return row["source_id"], row["external_key"]


def _cancel(conn, source, external):
    cursor = conn.execute(
        """WITH prior AS MATERIALIZED (
          SELECT job_id,attempt,fence FROM ow.jobs
          WHERE status IN ('ready','running') AND payload->>'document_id' IN
          (SELECT document_id FROM ow.documents WHERE source_id=%s AND external_key=%s)
          FOR UPDATE
        ), changed AS (
          UPDATE ow.jobs j SET status='cancelled',fence=NULL,lease_until=NULL,
          last_error='LIFECYCLE_RETIRED',updated_at=clock_timestamp()
          FROM prior p WHERE j.job_id=p.job_id RETURNING j.job_id
        ) INSERT INTO ow.job_events(job_id,attempt,fence,event,code)
          SELECT p.job_id,p.attempt,p.fence,'cancelled','LIFECYCLE_RETIRED'
          FROM prior p JOIN changed c USING(job_id)""",
        (source, external),
    )
    return cursor.rowcount


def _validate_change(change):
    if (
        not change.actor.strip()
        or not change.rationale.strip()
        or (change.action == "retention" and (not change.retention_class or change.hold_id))
        or (change.action in {"hold", "release"} and not change.hold_id)
        or (change.action != "retention" and (change.retention_class or change.retain_until))
        or (change.action == "retire" and change.hold_id)
    ):
        raise WorkbenchError("INVALID_LIFECYCLE_CHANGE")


def apply(db, change: Change):
    _validate_change(change)
    request_sha = digest(change.model_dump_json().encode())
    with db.connect(lifecycle_exclusive=True) as conn:
        _authorize(conn)
        previous = conn.execute(
            "SELECT request_sha256,result FROM ow.lifecycle_events WHERE operation_id=%s",
            (change.operation_id,),
        ).fetchone()
        if previous:
            if previous["request_sha256"] != request_sha:
                raise WorkbenchError("LIFECYCLE_OPERATION_CONFLICT")
            return {**previous["result"], "replayed": True}
        source, external = _key(conn, change.document_id)
        retired = conn.execute(
            "SELECT 1 FROM ow.lifecycle_tombstones WHERE source_id=%s AND external_key=%s",
            (source, external),
        ).fetchone()
        if retired and change.action != "release":
            raise WorkbenchError("DOCUMENT_RETIRED")
        cancelled = 0
        if change.action == "retention":
            conn.execute(
                "UPDATE ow.lifecycle_items SET retention_class=%s,retain_until=%s "
                "WHERE source_id=%s AND external_key=%s",
                (change.retention_class, change.retain_until, source, external),
            )
            if (
                change.retain_until
                and conn.execute(
                    "SELECT %s<=clock_timestamp() AS expired", (change.retain_until,)
                ).fetchone()["expired"]
            ):
                cancelled = _cancel(conn, source, external)
        elif change.action == "hold":
            if conn.execute(
                "SELECT 1 FROM ow.lifecycle_holds WHERE hold_id=%s", (change.hold_id,)
            ).fetchone():
                raise WorkbenchError("HOLD_ID_ALREADY_USED")
            conn.execute(
                "INSERT INTO ow.lifecycle_holds(hold_id,source_id,external_key) VALUES (%s,%s,%s)",
                (change.hold_id, source, external),
            )
        elif change.action == "release":
            row = conn.execute(
                "UPDATE ow.lifecycle_holds SET released_at=clock_timestamp() "
                "WHERE hold_id=%s AND source_id=%s AND external_key=%s "
                "AND released_at IS NULL RETURNING hold_id",
                (change.hold_id, source, external),
            ).fetchone()
            if not row:
                raise WorkbenchError("ACTIVE_HOLD_NOT_FOUND")
        else:
            if conn.execute(
                "SELECT 1 FROM ow.lifecycle_holds WHERE source_id=%s AND external_key=%s "
                "AND released_at IS NULL",
                (source, external),
            ).fetchone():
                raise WorkbenchError("DOCUMENT_HELD")
            conn.execute(
                "INSERT INTO ow.lifecycle_tombstones(source_id,external_key) VALUES (%s,%s)",
                (source, external),
            )
            cancelled = _cancel(conn, source, external)
        revision = conn.execute(
            "UPDATE ow.lifecycle_control SET revision=revision+1 RETURNING revision"
        ).fetchone()["revision"]
        result = {
            "operation_id": change.operation_id,
            "document_id": change.document_id,
            "action": change.action,
            "revision": revision,
            "cancelled_jobs": cancelled,
            "physical_erasure": False,
            "retention_class": change.retention_class,
            "retain_until": change.model_dump(mode="json")["retain_until"],
            "hold_id": change.hold_id,
        }
        conn.execute(
            "INSERT INTO ow.lifecycle_events(operation_id,request_sha256,revision,"
            "source_id,external_key,action,"
            "actor,rationale,result) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                change.operation_id,
                request_sha,
                revision,
                source,
                external,
                change.action,
                change.actor,
                change.rationale,
                Jsonb(result),
            ),
        )
    return {**result, "replayed": False}


def inspect(db, document_id):
    # Validate the identifier even though every SQL value is parameterized.
    from pydantic import TypeAdapter

    TypeAdapter(Digest).validate_python(document_id)
    with db.connect() as conn:
        _authorize(conn)
        source, external = _key(conn, document_id)
        item = conn.execute(
            "SELECT retention_class,retain_until FROM ow.lifecycle_items "
            "WHERE source_id=%s AND external_key=%s",
            (source, external),
        ).fetchone()
        holds = conn.execute(
            "SELECT hold_id,placed_at,released_at FROM ow.lifecycle_holds "
            "WHERE source_id=%s AND external_key=%s ORDER BY hold_id LIMIT 1001",
            (source, external),
        ).fetchall()
        if len(holds) > 1000:
            raise WorkbenchError("LIFECYCLE_LIMIT_EXCEEDED")
        retired = bool(
            conn.execute(
                "SELECT 1 FROM ow.lifecycle_tombstones WHERE source_id=%s AND external_key=%s",
                (source, external),
            ).fetchone()
        )
        control = conn.execute("SELECT dataset_id,revision FROM ow.lifecycle_control").fetchone()
    return {
        "document_id": document_id,
        **item,
        **control,
        "holds": holds,
        "retired": retired,
        "physical_erasure": False,
    }


def validate_policy(payload):
    if (
        not isinstance(payload, dict)
        or set(payload) != {"format", "kind", "control", "tables"}
        or type(payload["format"]) is not int
        or payload["format"] != 1
        or payload["kind"] != "lifecycle_policy"
        or set(payload["tables"]) != set(POLICY_TABLES)
    ):
        raise WorkbenchError("INVALID_LIFECYCLE_POLICY")
    control = Control.model_validate_json(json.dumps(payload["control"]))
    count = 0
    parsed = {}
    for table, model in MODELS.items():
        if not isinstance(payload["tables"][table], list):
            raise WorkbenchError("INVALID_LIFECYCLE_POLICY")
        parsed[table] = []
        for row in payload["tables"][table]:
            parsed[table].append(model.model_validate_json(json.dumps(row)))
            count += 1
    events = payload["tables"]["lifecycle_events"]
    if (
        count > 100_000
        or len(events) != control.revision
        or {e["revision"] for e in events} != set(range(1, control.revision + 1))
        or len({e["operation_id"] for e in events}) != len(events)
    ):
        raise WorkbenchError("LIFECYCLE_POLICY_HISTORY_MISMATCH")
    _validate_state(parsed, control)
    return payload


def _validate_state(parsed, control):
    def key(row):
        return row.source_id, row.external_key

    items = {key(r): r for r in parsed["lifecycle_items"]}
    holds = {r.hold_id: r for r in parsed["lifecycle_holds"]}
    tombstones = {key(r) for r in parsed["lifecycle_tombstones"]}
    if (
        len(items) != len(parsed["lifecycle_items"])
        or len(holds) != len(parsed["lifecycle_holds"])
        or len(tombstones) != len(parsed["lifecycle_tombstones"])
    ):
        raise WorkbenchError("LIFECYCLE_POLICY_HISTORY_MISMATCH")
    expected_items = {k: ("manual", None) for k in items}
    expected_holds, expected_tombstones, expected_purges = {}, set(), set()
    try:
        for event in sorted(parsed["lifecycle_events"], key=lambda e: e.revision):
            result = event.result
            if event.action == "purge":
                purged = PurgeResult.model_validate_json(json.dumps(result))
                k = key(event)
                if (
                    k not in items
                    or not event.actor.strip()
                    or not event.rationale.strip()
                    or k not in expected_tombstones
                    or k in expected_purges
                    or (k, False) in expected_holds.values()
                    or purged.source_id != event.source_id
                    or purged.external_key != event.external_key
                    or purged.operation_id != event.operation_id
                    or purged.dataset_id != control.dataset_id
                    or purged.revision != event.revision
                    or purged.policy_revision_before != event.revision - 1
                    or purge_request_sha(
                        event.operation_id,
                        event.source_id,
                        event.external_key,
                        event.actor,
                        event.rationale,
                        purged.plan_sha256,
                    )
                    != event.request_sha256
                ):
                    raise ValueError
                expected_purges.add(k)
                continue
            change = Change.model_validate_json(
                json.dumps(
                    {
                        "action": event.action,
                        "document_id": result["document_id"],
                        "operation_id": event.operation_id,
                        "actor": event.actor,
                        "rationale": event.rationale,
                        "retention_class": result["retention_class"],
                        "retain_until": result["retain_until"],
                        "hold_id": result["hold_id"],
                    }
                )
            )
            _validate_change(change)
            k = key(event)
            if (
                k not in items
                or digest(change.model_dump_json().encode()) != event.request_sha256
                or result["revision"] != event.revision
                or result["action"] != event.action
                or result["operation_id"] != event.operation_id
                or result["physical_erasure"] is not False
                or type(result["cancelled_jobs"]) is not int
                or result["cancelled_jobs"] < 0
            ):
                raise ValueError
            if event.action == "retention":
                if k in expected_tombstones or not change.retention_class:
                    raise ValueError
                expected_items[k] = (change.retention_class, change.retain_until)
            elif event.action == "hold":
                if (
                    k in expected_tombstones
                    or change.hold_id in expected_holds
                    or not change.hold_id
                ):
                    raise ValueError
                expected_holds[change.hold_id] = (k, False)
            elif event.action == "release":
                if expected_holds.get(change.hold_id) != (k, False):
                    raise ValueError
                expected_holds[change.hold_id] = (k, True)
            else:
                if k in expected_tombstones or (k, False) in expected_holds.values():
                    raise ValueError
                expected_tombstones.add(k)
        if expected_tombstones != tombstones or set(expected_holds) != set(holds):
            raise ValueError
        for k, item in items.items():
            if (item.retention_class, item.retain_until) != expected_items[k]:
                raise ValueError
        for hold_id, hold in holds.items():
            if (key(hold), hold.released_at is not None) != expected_holds[hold_id]:
                raise ValueError
            if hold.released_at is not None and hold.released_at < hold.placed_at:
                raise ValueError
    except (KeyError, ValueError):
        raise WorkbenchError("LIFECYCLE_POLICY_HISTORY_MISMATCH") from None


def assert_no_purged_documents(tables, policy):
    """Refuse retained SQL documents named by a durable purge decision.

    This does not remove bytes, rewrite checkpoints, or prove deletion of external
    copies. A pre-purge checkpoint must not resurrect purged retained content even
    under a newer policy that would suppress its ordinary reader visibility.
    """
    validate_policy(policy)
    purged = {
        (event["source_id"], event["external_key"])
        for event in policy["tables"]["lifecycle_events"]
        if event["action"] == "purge"
    }
    if any((row["source_id"], row["external_key"]) in purged for row in tables["documents"]):
        raise WorkbenchError("RECOVERY_PURGED_CONTENT_PRESENT")


def export_policy(db, path):
    from .recovery import _json, _write_new

    with db.connect() as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        _authorize(conn)
        control = conn.execute(
            "SELECT row_to_json(c) AS value FROM ow.lifecycle_control c"
        ).fetchone()["value"]
        tables = {}
        total, count = 0, 0
        for name in POLICY_TABLES:
            rows = []
            with conn.cursor(name="policy_" + name) as cursor:
                cursor.execute(
                    sql.SQL("SELECT row_to_json(t) AS value FROM ow.{} t").format(
                        sql.Identifier(name)
                    )
                )
                for row in cursor:
                    total += len(_json(row["value"]))
                    count += 1
                    if total > MAX_POLICY or count > 100_000:
                        raise WorkbenchError("LIFECYCLE_LIMIT_EXCEEDED")
                    rows.append(row["value"])
            tables[name] = rows
    payload = validate_policy(
        {"format": 1, "kind": "lifecycle_policy", "control": control, "tables": tables}
    )
    sha = digest(_json(payload))
    data = _json({"payload": payload, "sha256": sha})
    if len(data) > MAX_POLICY:
        raise WorkbenchError("LIFECYCLE_LIMIT_EXCEEDED")
    _write_new(path, data)
    return {
        "sha256": sha,
        "dataset_id": control["dataset_id"],
        "revision": control["revision"],
        "classification": "private_lifecycle_policy",
    }


def reconcile_policy(backup_tables, payload, minimum_revision):
    """Trusted external receipt is necessary; offline code cannot infer its freshness."""
    validate_policy(payload)
    validate_policy(
        {
            "format": 1,
            "kind": "lifecycle_policy",
            "control": backup_tables["lifecycle_control"][0],
            "tables": {name: backup_tables[name] for name in POLICY_TABLES},
        }
    )
    old = backup_tables["lifecycle_control"][0]
    current = payload["control"]
    if (
        type(minimum_revision) is not int
        or minimum_revision < 0
        or current["dataset_id"] != old["dataset_id"]
        or current["revision"] < max(minimum_revision, old["revision"])
    ):
        raise WorkbenchError("LIFECYCLE_POLICY_STALE_OR_WRONG_DATASET")
    policy = payload["tables"]
    event_map = {
        e["operation_id"]: Event.model_validate_json(json.dumps(e))
        for e in policy["lifecycle_events"]
    }
    for event in backup_tables["lifecycle_events"]:
        if event_map.get(event["operation_id"]) != Event.model_validate_json(json.dumps(event)):
            raise WorkbenchError("LIFECYCLE_POLICY_HISTORY_MISMATCH")
    for table, keys in (("lifecycle_tombstones", ("source_id", "external_key")),):
        rows = {
            tuple(r[k] for k in keys): Tombstone.model_validate_json(json.dumps(r))
            for r in policy[table]
        }
        if any(
            rows.get(tuple(r[k] for k in keys)) != Tombstone.model_validate_json(json.dumps(r))
            for r in backup_tables[table]
        ):
            raise WorkbenchError("LIFECYCLE_POLICY_HISTORY_MISMATCH")
    holds = {
        h["hold_id"]: Hold.model_validate_json(json.dumps(h)) for h in policy["lifecycle_holds"]
    }
    for row in backup_tables["lifecycle_holds"]:
        hold = Hold.model_validate_json(json.dumps(row))
        new = holds.get(hold.hold_id)
        if (
            not new
            or any(
                getattr(new, k) != getattr(hold, k)
                for k in ("source_id", "external_key", "placed_at")
            )
            or (hold.released_at is not None and new.released_at != hold.released_at)
        ):
            raise WorkbenchError("LIFECYCLE_POLICY_HISTORY_MISMATCH")
    items = {(r["source_id"], r["external_key"]): r for r in backup_tables["lifecycle_items"]}
    items.update({(r["source_id"], r["external_key"]): r for r in policy["lifecycle_items"]})
    return {
        **backup_tables,
        **policy,
        "lifecycle_control": [current],
        "lifecycle_items": list(items.values()),
    }
