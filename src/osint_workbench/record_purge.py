"""Explicit retired-record SQL deletion; no CAS, backup or media-erasure claim."""

import json
from pathlib import Path
from typing import Literal

from psycopg import sql
from psycopg.types.json import Jsonb
from pydantic import AwareDatetime, ConfigDict, Field, field_validator

from . import lifecycle, recovery
from .contracts import Digest, Identifier, StrictModel
from .errors import WorkbenchError
from .text import digest

MAX_ROWS = 10_000
MAX_METADATA = 16 * 1024 * 1024
MAX_PLAN = 4 * 1024 * 1024
KEYS = {
    "sources": ("source_id",),
    "collection_state": ("source_id",),
    "lifecycle_control": ("singleton",),
    "lifecycle_items": ("source_id", "external_key"),
    "lifecycle_holds": ("hold_id",),
    "lifecycle_tombstones": ("source_id", "external_key"),
    "lifecycle_events": ("operation_id",),
    "snapshots": ("snapshot_id",),
    "documents": ("document_id",),
    "document_heads": ("source_id", "external_key"),
    "jobs": ("job_id",),
    "job_events": ("event_id",),
    "chunks": ("chunk_id",),
    "collection_runs": ("run_id",),
    "enrichments": ("enrichment_id",),
    "assertions": ("assertion_id",),
    "assertion_reviews": ("review_id",),
    "briefings": ("briefing_id",),
    "embedding_spaces": ("space_id",),
    "retrieval_generations": ("generation_id",),
    "retrieval_members": ("generation_id", "document_id"),
    "retrieval_exclusions": ("generation_id", "document_id"),
    "retrieval_vectors": ("generation_id", "document_id", "ordinal"),
    "retrieval_active": ("singleton",),
}
DELETE_ORDER = (
    "briefings",
    "assertion_reviews",
    "assertions",
    "enrichments",
    "job_events",
    "jobs",
    "chunks",
    "retrieval_active",
    "retrieval_vectors",
    "retrieval_exclusions",
    "retrieval_members",
    "document_heads",
    "documents",
    "snapshots",
)


# Exact column names for the admitted published profile, including generated FTS.
# Future data-bearing columns require an explicit closure review, not inferred support.
COLUMNS = {
    "migrations": "version sha256 applied_at",
    "sources": "source_id enabled freshness_seconds last_attempt last_success last_error",
    "snapshots": "snapshot_id source_id raw_sha256 text_sha256 extractor acquired_at",
    "documents": "document_id source_id external_key snapshot_id title body "
    "published_at search_vector",
    "document_heads": "source_id external_key document_id",
    "jobs": "job_id kind dedup_key payload status attempt fence lease_until result available_at "
    "max_attempts last_error created_at updated_at",
    "job_events": "event_id job_id attempt fence event code recorded_at",
    "chunks": "chunk_id document_id chunker ordinal start_offset end_offset text_sha256 body",
    "collection_runs": "run_id source_id status accepted_documents raw_sha256 error_code "
    "started_at finished_at suppressed_documents http_status",
    "collection_state": "source_id resource_sha256 next_attempt failures etag "
    "last_modified raw_sha256",
    "enrichments": "enrichment_id document_id job_id generator_id prompt_version prompt_sha256 "
    "response_sha256 status created_at",
    "assertions": "assertion_id enrichment_id document_id subject predicate object "
    "statement polarity "
    "start_offset end_offset quote",
    "assertion_reviews": "review_id assertion_id decision actor rationale reviewed_at",
    "briefings": "briefing_id content created_at",
    "remote_operations": "attempt_id operation_id route_id policy_sha256 task data_class "
    "decision reason packet_sha256 currency reserved status input_tokens output_tokens usage "
    "estimated_cost response_sha256 error_code created_at updated_at",
    "lifecycle_control": "singleton dataset_id revision",
    "lifecycle_items": "source_id external_key retention_class retain_until",
    "lifecycle_holds": "hold_id source_id external_key placed_at released_at",
    "lifecycle_tombstones": "source_id external_key retired_at",
    "lifecycle_events": "operation_id request_sha256 revision source_id external_key action actor "
    "rationale result recorded_at",
    "retrieval_migrations": "version sha256",
    "embedding_spaces": "space_id manifest dimensions",
    "retrieval_generations": "generation_id space_id dimensions corpus_sha256 status "
    "error_code created_at",
    "retrieval_members": "generation_id document_id",
    "retrieval_exclusions": "generation_id document_id reason",
    "retrieval_vectors": "generation_id space_id dimensions document_id ordinal start_offset "
    "end_offset text_sha256 embedding",
    "retrieval_active": "singleton generation_id",
}


class Request(StrictModel):
    document_id: Digest
    operation_id: Identifier
    actor: str = Field(min_length=1, max_length=96)
    rationale: str = Field(min_length=1, max_length=2000)

    @field_validator("actor", "rationale")
    @classmethod
    def nonblank(cls, value):
        if not value.strip():
            raise ValueError("nonblank actor and rationale required")
        return value


class Row(StrictModel):
    key: dict[str, str | int | bool]
    sha256: Digest


class Plan(StrictModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    format: Literal[1] = 1
    kind: Literal["retired_record_purge_plan"] = "retired_record_purge_plan"
    request: Request
    created_at: AwareDatetime
    dataset_id: str
    policy_revision: int = Field(ge=0, le=100_000)
    migrations: dict[str, Digest]
    source_id: Identifier
    external_key: Digest
    inventory_sha256: Digest
    rows: dict[str, tuple[Row, ...]]
    invalidated_generations: tuple[str, ...]
    shared_snapshots: tuple[Digest, ...]
    retained_collection_references: int = Field(ge=0)

    @field_validator("format", mode="before")
    @classmethod
    def integer_format(cls, value):
        if type(value) is not int:
            raise ValueError("integer format required")
        return value


def _authorize(conn, history):
    """Require exact effective purge authority, including SET ROLE reachability."""
    identity = conn.execute("""SELECT
      session_user<>current_user AS changed_identity,
      NOT pg_has_role(current_user,'ow_purger','USAGE') AS missing_role,
      NOT coalesce(has_schema_privilege(current_user,to_regnamespace('ow')::oid,'USAGE'),false)
        AS missing_schema,
      EXISTS(SELECT 1 FROM pg_roles r
        WHERE pg_has_role(current_user,r.oid,'MEMBER') AND
          (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls
           OR r.rolname NOT IN (current_user,'ow_purger'))) AS unsafe_roles,
      EXISTS(SELECT 1 FROM pg_roles WHERE rolname='ow_purger' AND rolcanlogin) AS login_group,
      EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.admin_option AND
        pg_has_role(current_user,m.member,'MEMBER')) AS role_delegation,
      EXISTS(SELECT 1 FROM pg_database WHERE datname=current_database() AND
        (pg_has_role(current_user,datdba,'MEMBER') OR
         has_database_privilege(current_user,oid,'CREATE'))) AS database_authority,
      EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname IN ('ow','ow_vector','public') AND
        (pg_has_role(current_user,n.nspowner,'MEMBER') OR
         has_schema_privilege(current_user,n.oid,'CREATE'))) AS schema_authority,
      EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname IN ('ow','ow_vector') AND
        has_schema_privilege(current_user,n.oid,'USAGE WITH GRANT OPTION')) AS schema_delegation,
      EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname IN ('ow','ow_vector') AND
        pg_has_role(current_user,c.relowner,'MEMBER')) AS owned_relations,
      EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname IN ('ow','ow_vector') AND
        pg_has_role(current_user,p.proowner,'MEMBER')) AS owned_functions,
      EXISTS(SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
        WHERE n.nspname IN ('ow','ow_vector') AND
        pg_has_role(current_user,t.typowner,'MEMBER')) AS owned_types,
      EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname IN ('ow','ow_vector') AND p.prosecdef
        AND has_schema_privilege(current_user,n.oid,'USAGE')
        AND has_function_privilege(current_user,p.oid,'EXECUTE')) AS definer_functions,
      EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname IN ('ow','ow_vector') AND c.relkind='S'
        AND has_sequence_privilege(current_user,c.oid,'USAGE,SELECT,UPDATE')) AS sequences,
      EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname IN ('ow','ow_vector') AND c.relkind IN ('r','p','v','m','f')
        AND has_table_privilege(current_user,c.oid,'TRUNCATE,REFERENCES,TRIGGER,MAINTAIN'))
        AS table_authority,
      EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname IN ('ow','ow_vector') AND c.relkind IN ('r','p','v','m','f')
        AND has_table_privilege(current_user,c.oid,'DELETE WITH GRANT OPTION'))
        AS delete_delegation""").fetchone()
    if not identity or any(identity.values()):
        raise WorkbenchError("PURGE_OPERATOR_REQUIRED")
    names = (*recovery.CORE, "migrations")
    if "retrieval/1" in history:
        names += (*recovery.RETRIEVAL, "retrieval_migrations")
    columns = conn.execute(
        """SELECT n.nspname,c.relname,a.attname
      FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
      WHERE n.nspname='ow' AND c.relname=ANY(%s::text[])
        AND c.relkind IN ('r','p')""",
        (list(names),),
    ).fetchall()
    expected_columns = {(name, column) for name in names for column in COLUMNS[name].split()}
    if {(r["relname"], r["attname"]) for r in columns} != expected_columns:
        raise WorkbenchError("PURGE_OPERATOR_REQUIRED")
    # Include generated columns: table SELECT grants also cover search_vector.
    allowed = {(r["nspname"], r["relname"], r["attname"], "SELECT") for r in columns}
    allowed |= {
        (r["nspname"], r["relname"], r["attname"], "INSERT")
        for r in columns
        if r["relname"] == "lifecycle_events"
    }
    allowed.add(("ow", "lifecycle_control", "revision", "UPDATE"))
    if "retrieval/1" in history:
        allowed |= {
            ("ow", "retrieval_generations", column, "UPDATE") for column in ("status", "error_code")
        }
    granted = conn.execute("""SELECT n.nspname,c.relname,a.attname,p.privilege,
        has_column_privilege(current_user,c.oid,a.attnum,
          p.privilege || ' WITH GRANT OPTION') AS delegation
      FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
      CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('REFERENCES')) p(privilege)
      WHERE n.nspname IN ('ow','ow_vector') AND c.relkind IN ('r','p','v','m','f')
      AND has_column_privilege(current_user,c.oid,a.attnum,p.privilege)""").fetchall()
    actual = {(r["nspname"], r["relname"], r["attname"], r["privilege"]) for r in granted}
    if actual != allowed or any(r["delegation"] for r in granted):
        raise WorkbenchError("PURGE_OPERATOR_REQUIRED")
    deletes = conn.execute("""SELECT n.nspname,c.relname
      FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname IN ('ow','ow_vector') AND c.relkind IN ('r','p','v','m','f')
      AND has_table_privilege(current_user,c.oid,'DELETE')""").fetchall()
    actual_deletes = {(r["nspname"], r["relname"]) for r in deletes}
    allowed_deletes = {("ow", name) for name in DELETE_ORDER if name in names}
    if actual_deletes != allowed_deletes:
        raise WorkbenchError("PURGE_OPERATOR_REQUIRED")


def _state(conn):
    # Admit authority from catalog feedback before selecting protected history rows.
    # A denied principal must not fail first with a raw PostgreSQL privilege error.
    if not conn.execute(
        "SELECT coalesce(pg_has_role(current_user,to_regrole('ow_purger')::oid,"
        "'USAGE'),false) AS ok"
    ).fetchone()["ok"]:
        raise WorkbenchError("PURGE_OPERATOR_REQUIRED")
    configured = conn.execute(
        "SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname='ow' AND c.relname='retrieval_migrations') AS present"
    ).fetchone()["present"]
    _authorize(conn, {"retrieval/1": "configured"} if configured else {})
    history = recovery._history(conn)
    recovery._full_visibility(conn)
    # Unknown deletion side effects cannot be inferred from the reference schema.
    if conn.execute("""SELECT 1 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
        JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='ow'
        AND NOT t.tgisinternal UNION ALL
        SELECT 1 FROM pg_rewrite w JOIN pg_class c ON c.oid=w.ev_class
        JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='ow' AND w.rulename<>'_RETURN' UNION ALL
        SELECT 1 FROM pg_constraint c JOIN pg_class r ON r.oid=c.confrelid
        JOIN pg_namespace n ON n.oid=r.relnamespace WHERE c.contype='f'
        AND n.nspname='ow' AND (c.connamespace<>n.oid OR c.confdeltype<>'a') LIMIT 1""").fetchone():
        raise WorkbenchError("PURGE_UNSUPPORTED_DEPENDENCY")
    tables, count, size = {}, 0, 0
    names = recovery.CORE + (recovery.RETRIEVAL if "retrieval/1" in history else ())
    for name in names:
        columns = sql.SQL(",").join(map(sql.Identifier, recovery._columns(conn, name)))
        query = sql.SQL("SELECT row_to_json(t)::text AS value FROM (SELECT {} FROM ow.{}) t")
        values = []
        with conn.cursor(name="purge_" + name) as cursor:
            cursor.execute(query.format(columns, sql.Identifier(name)))
            for row in cursor:
                size += len(row["value"].encode())
                count += 1
                if count > MAX_ROWS or size > MAX_METADATA:
                    raise WorkbenchError("PURGE_LIMIT_EXCEEDED")
                values.append(json.loads(row["value"]))
        tables[name] = sorted(values, key=lambda r: recovery._json(_key(name, r)))
    control = tables["lifecycle_control"]
    if len(control) != 1:
        raise WorkbenchError("PURGE_INVALID_POLICY")
    policy = {
        "format": 1,
        "kind": "lifecycle_policy",
        "control": control[0],
        "tables": {name: tables[name] for name in lifecycle.POLICY_TABLES},
    }
    lifecycle.validate_policy(policy)
    lifecycle.assert_no_purged_documents(tables, policy)
    return history, tables


def _key(table, row):
    return {k: row[k] for k in KEYS[table]}


def _closure(tables, request):
    selected = next(
        (d for d in tables["documents"] if d["document_id"] == request.document_id), None
    )
    if selected is None:
        raise WorkbenchError("DOCUMENT_NOT_FOUND")
    logical = selected["source_id"], selected["external_key"]

    def key(d):
        return d["source_id"], d["external_key"]

    if not any(key(t) == logical for t in tables["lifecycle_tombstones"]):
        raise WorkbenchError("PURGE_RETIREMENT_REQUIRED")
    held = {key(h) for h in tables["lifecycle_holds"] if h["released_at"] is None}
    if logical in held:
        raise WorkbenchError("DOCUMENT_HELD")
    chosen = {n: [] for n in DELETE_ORDER if n in tables}
    chosen["documents"] = [d for d in tables["documents"] if key(d) == logical]
    documents = {d["document_id"] for d in chosen["documents"]}
    chosen["enrichments"] = [e for e in tables["enrichments"] if e["document_id"] in documents]
    enrichments = {e["enrichment_id"] for e in chosen["enrichments"]}
    for a in tables["assertions"]:
        if a["document_id"] in documents or a["enrichment_id"] in enrichments:
            if a["document_id"] not in documents or a["enrichment_id"] not in enrichments:
                raise WorkbenchError("PURGE_CROSS_ITEM_REFERENCE")
            chosen["assertions"].append(a)
    assertions = {a["assertion_id"] for a in chosen["assertions"]}
    chosen["assertion_reviews"] = [
        r for r in tables["assertion_reviews"] if r["assertion_id"] in assertions
    ]
    jobs = {e["job_id"] for e in chosen["enrichments"]}
    jobs |= {
        j["job_id"]
        for j in tables["jobs"]
        if isinstance(j["payload"], dict) and j["payload"].get("document_id") in documents
    }
    if any(
        e["job_id"] in jobs and e["document_id"] not in documents for e in tables["enrichments"]
    ):
        raise WorkbenchError("PURGE_CROSS_ITEM_REFERENCE")
    by_job = {j["job_id"]: j for j in tables["jobs"]}
    for enrichment in chosen["enrichments"]:
        job = by_job.get(enrichment["job_id"])
        if (
            not job
            or not isinstance(job["payload"], dict)
            or job["payload"].get("document_id") != enrichment["document_id"]
        ):
            raise WorkbenchError("PURGE_CROSS_ITEM_REFERENCE")
    chosen["jobs"] = [j for j in tables["jobs"] if j["job_id"] in jobs]
    chosen["job_events"] = [e for e in tables["job_events"] if e["job_id"] in jobs]
    chosen["chunks"] = [c for c in tables["chunks"] if c["document_id"] in documents]
    chosen["document_heads"] = [
        h for h in tables["document_heads"] if h["document_id"] in documents
    ]
    by_document = {d["document_id"]: d for d in tables["documents"]}
    by_assertion = {a["assertion_id"]: a for a in tables["assertions"]}
    for briefing in tables["briefings"]:
        content = briefing["content"]
        if (
            not isinstance(content, dict)
            or type(content.get("schema_version")) is not int
            or content.get("schema_version") != 1
            or set(content)
            != {
                "schema_version",
                "kind",
                "corpus_cutoff",
                "items",
                "selected_documents",
                "diversity",
                "degraded",
                "omission_reason",
            }
            or content.get("kind") != "reviewed_assertion_digest"
            or not isinstance(content.get("selected_documents"), list)
            or not isinstance(content.get("items"), list)
            or digest(json.dumps(content, sort_keys=True).encode()) != briefing["briefing_id"]
        ):
            raise WorkbenchError("PURGE_UNSUPPORTED_PRODUCT")
        selected_ids, item_ids = content["selected_documents"], set()
        if (
            not 1 <= len(selected_ids) <= 50
            or len(content["items"]) > 100
            or type(content.get("degraded")) is not bool
            or content["degraded"] != (not bool(content["items"]))
            or content.get("diversity") != "not_assessed"
            or content.get("omission_reason")
            != (None if content["items"] else "no_reviewed_assertions")
            or not isinstance(content.get("corpus_cutoff"), str)
            or any(not isinstance(i, str) or i not in by_document for i in selected_ids)
            or len(set(selected_ids)) != len(selected_ids)
        ):
            raise WorkbenchError("PURGE_UNSUPPORTED_PRODUCT")
        for item in content["items"]:
            if (
                not isinstance(item, dict)
                or set(item)
                != {
                    "assertion_id",
                    "document_id",
                    "snapshot_id",
                    "source_id",
                    "statement",
                    "polarity",
                    "quote",
                    "start_offset",
                    "end_offset",
                    "review",
                }
                or not isinstance(item.get("document_id"), str)
                or not isinstance(item.get("assertion_id"), str)
            ):
                raise WorkbenchError("PURGE_UNSUPPORTED_PRODUCT")
            assertion = by_assertion.get(item["assertion_id"])
            if (
                not assertion
                or assertion["document_id"] != item["document_id"]
                or item["document_id"] not in selected_ids
                or item["review"] != "accepted"
                or item["snapshot_id"] != by_document[item["document_id"]]["snapshot_id"]
                or item["source_id"] != by_document[item["document_id"]]["source_id"]
                or any(
                    item[k] != assertion[k]
                    for k in ("statement", "polarity", "quote", "start_offset", "end_offset")
                )
            ):
                raise WorkbenchError("PURGE_UNSUPPORTED_PRODUCT")
            item_ids.add(item["document_id"])
        referenced = set(selected_ids) | item_ids
        if referenced & documents:
            if any(key(by_document[i]) in held for i in referenced):
                raise WorkbenchError("PURGE_HELD_COLLATERAL")
            chosen["briefings"].append(briefing)
    snapshots = {d["snapshot_id"] for d in chosen["documents"]}
    shared = snapshots & {
        d["snapshot_id"] for d in tables["documents"] if d["document_id"] not in documents
    }
    chosen["snapshots"] = [s for s in tables["snapshots"] if s["snapshot_id"] in snapshots - shared]
    generations = set()
    if "retrieval_members" in tables:
        for name in ("retrieval_members", "retrieval_exclusions", "retrieval_vectors"):
            chosen[name] = [r for r in tables[name] if r["document_id"] in documents]
            generations.update(r["generation_id"] for r in chosen[name])
        chosen["retrieval_active"] = [
            r for r in tables["retrieval_active"] if r["generation_id"] in generations
        ]
    residual = sum(
        r["source_id"] == logical[0] and r.get("raw_sha256") is not None
        for name in ("collection_runs", "collection_state")
        for r in tables[name]
    )
    return logical, chosen, generations, shared, residual


def _make_plan(conn, request, created_at=None, state=None):
    history, tables = _state(conn) if state is None else state
    logical, chosen, generations, shared, residual = _closure(tables, request)
    rows = {
        name: tuple(Row(key=_key(name, r), sha256=digest(recovery._json(r))) for r in values)
        for name, values in chosen.items()
    }
    control = tables["lifecycle_control"][0]
    return Plan(
        request=request,
        created_at=created_at
        or conn.execute("SELECT transaction_timestamp() AS t").fetchone()["t"],
        dataset_id=control["dataset_id"],
        policy_revision=control["revision"],
        migrations=history,
        source_id=logical[0],
        external_key=logical[1],
        inventory_sha256=digest(recovery._json(tables)),
        rows=rows,
        invalidated_generations=tuple(sorted(generations)),
        shared_snapshots=tuple(sorted(shared)),
        retained_collection_references=residual,
    )


def plan(db, path: Path, *, document_id, operation_id, actor, rationale):
    request = Request(
        document_id=document_id, operation_id=operation_id, actor=actor, rationale=rationale
    )
    if not actor.strip() or not rationale.strip():
        raise WorkbenchError("INVALID_PURGE_REQUEST")
    with db.connect(lifecycle_exclusive=True) as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        value = _make_plan(conn, request)
        payload = value.model_dump(mode="json")
        sha = digest(recovery._json(payload))
        bundle = recovery._json({"payload": payload, "sha256": sha})
        if len(bundle) > MAX_PLAN:
            raise WorkbenchError("PURGE_LIMIT_EXCEEDED")
        recovery._write_new(path, bundle)
    return {
        "sha256": sha,
        "counts": {n: len(v) for n, v in value.rows.items()},
        "invalidated_generations": len(value.invalidated_generations),
        "shared_snapshots": len(value.shared_snapshots),
        "retained_collection_references": value.retained_collection_references,
        "classification": "private_purge_plan",
        "physical_erasure": False,
    }


def _delete_rows(conn, table, keys):
    conditions = sql.SQL(" AND ").join(
        sql.SQL("{}=%s").format(sql.Identifier(k)) for k in KEYS[table]
    )
    query = sql.SQL("DELETE FROM ow.{} WHERE ").format(sql.Identifier(table)) + conditions
    total = 0
    for key in keys:
        total += conn.execute(query, tuple(key[k] for k in KEYS[table])).rowcount
    return total


def apply(db, path: Path, expected_sha: str):
    try:
        value = Plan.model_validate_json(
            recovery._json(recovery._read_envelope(path, expected_sha, limit=MAX_PLAN))
        )
    except (ValueError, TypeError, KeyError, RecursionError):
        raise WorkbenchError("INVALID_PURGE_PLAN") from None
    with db.connect(lifecycle_exclusive=True) as conn:
        state = _state(conn)
        prior = conn.execute(
            "SELECT * FROM ow.lifecycle_events WHERE operation_id=%s", (value.request.operation_id,)
        ).fetchone()
        request_sha = lifecycle.purge_request_sha(
            value.request.operation_id,
            value.source_id,
            value.external_key,
            value.request.actor,
            value.request.rationale,
            expected_sha,
        )
        if prior:
            if prior["action"] != "purge" or prior["request_sha256"] != request_sha:
                raise WorkbenchError("PURGE_OPERATION_CONFLICT")
            result = lifecycle.PurgeResult.model_validate_json(recovery._json(prior["result"]))
            control = conn.execute("SELECT dataset_id FROM ow.lifecycle_control").fetchone()
            if str(result.dataset_id) != str(control["dataset_id"]):
                raise WorkbenchError("PURGE_OPERATION_CONFLICT")
            return {**result.model_dump(mode="json"), "replayed": True}
        observed = _make_plan(conn, value.request, value.created_at, state)
        if observed != value or value.policy_revision >= 100_000:
            raise WorkbenchError("PURGE_STALE_PLAN")
        counts = {key: 0 for key in lifecycle.PURGE_COUNT_KEYS}
        for name in DELETE_ORDER:
            if name not in value.rows:
                continue
            counts[name] = _delete_rows(conn, name, [r.key for r in value.rows[name]])
            if counts[name] != len(value.rows[name]):
                raise WorkbenchError("PURGE_CHANGED_DURING_APPLY")
        if value.invalidated_generations:
            counts["retrieval_generations_invalidated"] = conn.execute(
                "UPDATE ow.retrieval_generations SET status='failed',"
                "error_code='RETIRED_RECORD_PURGED' "
                "WHERE generation_id=ANY(%s::uuid[])",
                (list(value.invalidated_generations),),
            ).rowcount
            if counts["retrieval_generations_invalidated"] != len(value.invalidated_generations):
                raise WorkbenchError("PURGE_CHANGED_DURING_APPLY")
        revision = conn.execute(
            "UPDATE ow.lifecycle_control SET revision=revision+1 RETURNING revision"
        ).fetchone()["revision"]
        result = lifecycle.PurgeResult.model_validate_json(
            recovery._json(
                {
                    "format": 1,
                    "kind": "retired_record_purge",
                    "operation_id": value.request.operation_id,
                    "plan_sha256": expected_sha,
                    "dataset_id": value.dataset_id,
                    "source_id": value.source_id,
                    "external_key": value.external_key,
                    "policy_revision_before": value.policy_revision,
                    "revision": revision,
                    "counts": counts,
                    "sql_deleted": True,
                    "physical_erasure": False,
                    "cas_objects_deleted": 0,
                    "backup_erasure": False,
                }
            )
        ).model_dump(mode="json")
        conn.execute(
            "INSERT INTO ow.lifecycle_events(operation_id,request_sha256,revision,"
            "source_id,external_key,action,actor,rationale,result) "
            "VALUES (%s,%s,%s,%s,%s,'purge',%s,%s,%s)",
            (
                value.request.operation_id,
                request_sha,
                revision,
                value.source_id,
                value.external_key,
                value.request.actor,
                value.request.rationale,
                Jsonb(result),
            ),
        )
    # A lost commit acknowledgement remains an error. An explicit retry reads the
    # transactionally stored decision rather than inferring success from missing rows.
    return {**result, "replayed": False}
