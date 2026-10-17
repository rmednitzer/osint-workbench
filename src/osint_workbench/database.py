import hashlib
import json
import uuid
from importlib.resources import files

import psycopg
from psycopg.rows import dict_row

from .contracts import DocumentInput
from .errors import WorkbenchError
from .evidence import EvidenceStore

SCHEMA_VERSION = 7
LIFECYCLE_LOCK = 418287408
MIGRATIONS = (
    "schema.sql",
    "migrations/002_workflows.sql",
    "migrations/003_intelligence.sql",
    "migrations/004_lifecycle.sql",
    "migrations/005_collection_schedule.sql",
    "migrations/006_collector_role.sql",
    "migrations/007_retired_record_purge.sql",
)


def migrate(dsn: str) -> None:
    package = files("osint_workbench")
    scripts = [package.joinpath(name) for name in MIGRATIONS]
    with psycopg.connect(dsn, connect_timeout=5) as conn:
        conn.execute("SELECT pg_advisory_xact_lock(%s)", (LIFECYCLE_LOCK,))
        conn.execute("SELECT pg_advisory_xact_lock(418287405)")
        exists = conn.execute("SELECT to_regclass('ow.migrations')").fetchone()[0]
        applied = {}
        if exists:
            applied = dict(conn.execute("SELECT version,sha256 FROM ow.migrations").fetchall())
            if set(applied) != set(range(1, len(applied) + 1)) or max(applied, default=0) > len(
                scripts
            ):
                raise WorkbenchError("UNSUPPORTED_MIGRATION_HISTORY")
        for version, resource in enumerate(scripts, start=1):
            script = resource.read_text()
            sha = hashlib.sha256(script.encode()).hexdigest()
            if version in applied:
                if applied[version] != sha:
                    raise WorkbenchError("MIGRATION_DIGEST_MISMATCH")
                continue
            conn.execute(script)
            conn.execute("INSERT INTO ow.migrations(version,sha256) VALUES (%s,%s)", (version, sha))


class Database:
    def __init__(self, dsn: str):
        self._dsn = dsn

    def connect(self, *, lifecycle_exclusive=False):
        conn = psycopg.connect(
            self._dsn,
            connect_timeout=5,
            row_factory=dict_row,
            options="-c statement_timeout=10000 -c lock_timeout=5000 -c timezone=UTC",
        )
        # Acquire before any application transaction snapshot, including repeatable
        # read. Session end releases it even after rollback or process failure.
        try:
            conn.autocommit = True
            query = (
                "SELECT pg_advisory_lock(%s)"
                if lifecycle_exclusive
                else ("SELECT pg_advisory_lock_shared(%s)")
            )
            conn.execute(query, (LIFECYCLE_LOCK,))
            conn.autocommit = False
            return conn
        except (psycopg.errors.LockNotAvailable, psycopg.errors.QueryCanceled):
            conn.close()
            raise WorkbenchError("LIFECYCLE_BUSY") from None
        except Exception:
            conn.close()
            raise

    def validate_reader(self) -> None:
        with self.connect() as conn:
            row = conn.execute("""SELECT rolsuper,rolcreaterole,rolcreatedb,rolbypassrls,
              session_user<>current_user AS changed_identity
              FROM pg_roles WHERE rolname=current_user""").fetchone()
            if any(row.values()):
                raise WorkbenchError("UNSAFE_READER_IDENTITY")
            if conn.execute(
                """SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname='ow' AND c.relname=ANY(%s::text[])
                AND has_any_column_privilege(current_user,c.oid,'SELECT') LIMIT 1""",
                (
                    [
                        "documents",
                        "snapshots",
                        "chunks",
                        "assertions",
                        "briefings",
                        "jobs",
                        "enrichments",
                        "assertion_reviews",
                        "retrieval_vectors",
                        "retrieval_members",
                        "lifecycle_control",
                        "lifecycle_items",
                        "lifecycle_holds",
                        "lifecycle_tombstones",
                        "lifecycle_events",
                        "collection_state",
                    ],
                ),
            ).fetchone():
                raise WorkbenchError("UNSAFE_READER_IDENTITY")
            row = conn.execute("""SELECT
              has_table_privilege(current_user,'ow.documents','INSERT,UPDATE,DELETE') AS docs,
              has_table_privilege(current_user,'ow.jobs','INSERT,UPDATE,DELETE') AS jobs,
              has_schema_privilege(current_user,'ow','CREATE') AS ddl,
              pg_has_role(current_user,'ow_writer','MEMBER') AS writer,
              pg_has_role(current_user,'ow_lifecycle','MEMBER') AS lifecycle,
              pg_has_role(current_user,'ow_collector','MEMBER') AS collector,
              pg_has_role(current_user,'ow_purger','MEMBER') AS purger""").fetchone()
            if any(row.values()):
                raise WorkbenchError("UNSAFE_READER_IDENTITY")
            if conn.execute("""SELECT 1 FROM pg_class c JOIN pg_namespace n
              ON n.oid=c.relnamespace WHERE n.nspname IN ('ow','ow_vector')
              AND c.relkind IN ('r','p','v','m','f') AND
              (has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,MAINTAIN') OR
               has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE'))
              LIMIT 1""").fetchone():
                raise WorkbenchError("UNSAFE_READER_IDENTITY")

    def validate_collector(self) -> None:
        """Refuse broadened application authority before source/network dispatch.

        Checks effective grants and SET ROLE reachability, not just the login's
        direct ACL. Database PUBLIC TEMP is deliberately outside this app-DDL
        boundary. This is process authority, not source-level row isolation.
        """
        permissions = {
            "migrations": {"SELECT": "version sha256"},
            "sources": {
                "SELECT": "source_id enabled freshness_seconds",
                "INSERT": "source_id enabled freshness_seconds",
                "UPDATE": "enabled freshness_seconds last_attempt last_success last_error",
            },
            "snapshots": {"INSERT": "snapshot_id source_id raw_sha256 text_sha256 extractor"},
            "documents": {
                "SELECT": "document_id",
                "INSERT": "document_id source_id external_key snapshot_id title body published_at",
            },
            "document_heads": {
                "SELECT": "source_id external_key document_id",
                "INSERT": "source_id external_key document_id",
                "UPDATE": "document_id",
            },
            "jobs": {"INSERT": "job_id dedup_key payload"},
            "lifecycle_items": {
                "SELECT": "source_id external_key retain_until",
                "INSERT": "source_id external_key",
            },
            "lifecycle_tombstones": {"SELECT": "source_id external_key"},
            "collection_runs": {
                "SELECT": "run_id source_id status accepted_documents suppressed_documents",
                "INSERT": "run_id source_id status",
                "UPDATE": "status error_code finished_at accepted_documents "
                "suppressed_documents raw_sha256 http_status",
            },
            "collection_state": {
                "SELECT": "source_id resource_sha256 next_attempt failures etag "
                "last_modified raw_sha256",
                "INSERT": "source_id resource_sha256",
                "UPDATE": "resource_sha256 next_attempt failures etag last_modified raw_sha256",
            },
        }
        allowed = {
            ("ow", table, column, privilege)
            for table, grants in permissions.items()
            for privilege, columns in grants.items()
            for column in columns.split()
        }
        with self.connect() as conn:
            unsafe = conn.execute("""SELECT
              NOT pg_has_role(current_user,'ow_collector','USAGE') AS no_collector,
              session_user<>current_user AS changed_identity,
              EXISTS(SELECT 1 FROM pg_roles r
                WHERE pg_has_role(current_user,r.oid,'MEMBER') AND
                  (r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolbypassrls
                   OR r.rolreplication OR r.rolname NOT IN (current_user,'ow_collector')))
                AS unsafe_roles,
              EXISTS(SELECT 1 FROM pg_roles WHERE rolname='ow_collector' AND rolcanlogin)
                AS login_group,
              EXISTS(SELECT 1 FROM pg_auth_members m
                WHERE m.admin_option AND pg_has_role(current_user,m.member,'MEMBER'))
                AS role_delegation,
              EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname IN ('ow','ow_vector')
                AND has_schema_privilege(current_user,n.oid,'USAGE WITH GRANT OPTION'))
                AS schema_delegation,
              EXISTS(SELECT 1 FROM pg_database WHERE datname=current_database() AND
                (pg_has_role(current_user,datdba,'MEMBER') OR
                 has_database_privilege(current_user,oid,'CREATE'))) AS database_authority,
              EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname IN ('ow','ow_vector','public')
                AND (pg_has_role(current_user,n.nspowner,'MEMBER') OR
                     has_schema_privilege(current_user,n.oid,'CREATE'))) AS schema_authority,
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
                AND has_sequence_privilege(current_user,c.oid,'USAGE,SELECT,UPDATE'))
                AS sequence_authority,
              EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname IN ('ow','ow_vector') AND c.relkind IN ('r','p','v','m','f')
                AND has_table_privilege(current_user,c.oid,
                  'DELETE,TRUNCATE,TRIGGER,REFERENCES,MAINTAIN'))
                AS table_authority""").fetchone()
            if any(unsafe.values()):
                raise WorkbenchError("UNSAFE_COLLECTOR_IDENTITY")
            if conn.execute(
                """SELECT 1 FROM pg_class c JOIN pg_namespace n
              ON n.oid=c.relnamespace WHERE n.nspname='ow' AND c.relname=ANY(%s::text[])
              AND (c.relrowsecurity OR c.relforcerowsecurity) LIMIT 1""",
                (list(permissions),),
            ).fetchone():
                raise WorkbenchError("UNSAFE_COLLECTOR_IDENTITY")
            granted = conn.execute("""SELECT n.nspname,c.relname,a.attname,p.privilege
              FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
              JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
              CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('REFERENCES')) p(privilege)
              WHERE n.nspname IN ('ow','ow_vector') AND c.relkind IN ('r','p','v','m','f')
              AND has_column_privilege(current_user,c.oid,a.attnum,p.privilege)""").fetchall()
            actual = {(r["nspname"], r["relname"], r["attname"], r["privilege"]) for r in granted}
            if actual != allowed:
                raise WorkbenchError("UNSAFE_COLLECTOR_IDENTITY")
            if conn.execute("""SELECT 1
              FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
              JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
              CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('REFERENCES')) p(privilege)
              WHERE n.nspname IN ('ow','ow_vector') AND c.relkind IN ('r','p','v','m','f')
              AND has_column_privilege(current_user,c.oid,a.attnum,
                p.privilege || ' WITH GRANT OPTION') LIMIT 1""").fetchone():
                raise WorkbenchError("UNSAFE_COLLECTOR_IDENTITY")
            history = conn.execute(
                "SELECT version,sha256 FROM ow.migrations ORDER BY version LIMIT %s",
                (SCHEMA_VERSION + 1,),
            ).fetchall()
            expected = [
                {
                    "version": version,
                    "sha256": hashlib.sha256(
                        files("osint_workbench").joinpath(name).read_text().encode()
                    ).hexdigest(),
                }
                for version, name in enumerate(MIGRATIONS, 1)
            ]
            default = conn.execute("""SELECT pg_get_expr(d.adbin,d.adrelid) AS expression
              FROM pg_attrdef d JOIN pg_attribute a
                ON a.attrelid=d.adrelid AND a.attnum=d.adnum
              WHERE d.adrelid='ow.jobs'::regclass AND a.attname='kind'""").fetchone()
            if (
                history != expected
                or not default
                or default["expression"] != "'document.accepted'::text"
            ):
                raise WorkbenchError("UNSAFE_COLLECTOR_IDENTITY")

    def ingest(
        self, doc: DocumentInput, raw: bytes, store: EvidenceStore, extractor: str = "text/1"
    ) -> str:
        # Objects are durable before accepted metadata. DB failure may leave an
        # orphan; it must not create accepted records pointing at missing bytes.
        with self.connect() as conn:
            from .lifecycle import assert_key_visible

            assert_key_visible(
                conn, doc.source_id, hashlib.sha256(doc.external_id.encode()).hexdigest()
            )
            raw_sha, text_sha = store.put(raw), store.put(doc.text.encode())
            return self.ingest_stored(conn, doc, raw_sha, text_sha, extractor)

    @staticmethod
    def ingest_stored(conn, doc, raw_sha, text_sha, extractor, *, observed_current=False):
        """Internal transaction boundary; caller has durably verified both objects."""
        snapshot = hashlib.sha256(
            json.dumps([doc.source_id, raw_sha, text_sha, extractor]).encode()
        ).hexdigest()
        external = hashlib.sha256(doc.external_id.encode()).hexdigest()
        document = hashlib.sha256(
            json.dumps(
                [
                    doc.source_id,
                    external,
                    snapshot,
                    doc.title,
                    doc.published_at.isoformat() if doc.published_at else None,
                ]
            ).encode()
        ).hexdigest()
        conn.execute(
            "INSERT INTO ow.sources(source_id) VALUES (%s) ON CONFLICT DO NOTHING",
            (doc.source_id,),
        )
        from .lifecycle import assert_key_visible

        assert_key_visible(conn, doc.source_id, external)
        conn.execute(
            "INSERT INTO ow.lifecycle_items(source_id,external_key) VALUES (%s,%s) "
            "ON CONFLICT DO NOTHING",
            (doc.source_id, external),
        )
        conn.execute(
            """INSERT INTO ow.snapshots
            (snapshot_id,source_id,raw_sha256,text_sha256,extractor)
            VALUES (%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
            (snapshot, doc.source_id, raw_sha, text_sha, extractor),
        )
        inserted = conn.execute(
            """INSERT INTO ow.documents
            (document_id,source_id,external_key,snapshot_id,title,body,published_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING document_id""",
            (
                document,
                doc.source_id,
                external,
                snapshot,
                doc.title,
                doc.text,
                doc.published_at,
            ),
        ).fetchone()
        # Generic immutable replay must not rewind a later head. A serialized
        # collector may explicitly reconcile the representation it just observed.
        if inserted or observed_current:
            conn.execute(
                """INSERT INTO ow.document_heads(source_id,external_key,document_id)
              VALUES (%s,%s,%s) ON CONFLICT(source_id,external_key)
              DO UPDATE SET document_id=excluded.document_id""",
                (doc.source_id, external, document),
            )
        if inserted:
            conn.execute(
                """INSERT INTO ow.jobs(job_id,dedup_key,payload)
              VALUES (%s,%s,%s) ON CONFLICT DO NOTHING""",
                (
                    uuid.uuid4(),
                    document,
                    psycopg.types.json.Jsonb({"document_id": document, "snapshot_id": snapshot}),
                ),
            )
        return document

    def search(self, query: str, limit: int = 20, offset: int = 0) -> list[dict]:
        if not isinstance(query, str) or not 1 <= len(query.strip()) <= 2000:
            raise WorkbenchError("INVALID_QUERY")
        if (
            type(limit) is not int
            or not 1 <= limit <= 100
            or type(offset) is not int
            or not 0 <= offset <= 10000
        ):
            raise WorkbenchError("INVALID_PAGE")
        with self.connect() as conn:
            return conn.execute(
                """SELECT document_id,snapshot_id,source_id,title,
              left(body,1000) AS excerpt,
              ts_rank_cd(search_vector,websearch_to_tsquery('simple',%s)) AS rank
              FROM ow.active_documents WHERE search_vector @@ websearch_to_tsquery('simple',%s)
              ORDER BY rank DESC,document_id LIMIT %s OFFSET %s""",
                (query, query, limit, offset),
            ).fetchall()

    def document(self, document_id: str, offset: int = 0, size: int = 8000) -> dict:
        if len(document_id) != 64 or any(c not in "0123456789abcdef" for c in document_id):
            raise WorkbenchError("INVALID_DOCUMENT_ID")
        if (
            type(offset) is not int
            or not 0 <= offset <= 1_000_000
            or type(size) is not int
            or not 1 <= size <= 16000
        ):
            raise WorkbenchError("INVALID_PAGE")
        with self.connect() as conn:
            row = conn.execute(
                """SELECT document_id,snapshot_id,source_id,title,
              substring(body FROM %s FOR %s) AS text,length(body) AS total_characters,
              body AS full_body,published_at FROM ow.visible_documents WHERE document_id=%s""",
                (offset + 1, size, document_id),
            ).fetchone()
        if row is None:
            raise WorkbenchError("DOCUMENT_NOT_FOUND")
        row["next_offset"] = (
            offset + len(row["text"])
            if offset + len(row["text"]) < row["total_characters"]
            else None
        )
        return row

    def snapshot(self, snapshot_id: str) -> dict:
        if len(snapshot_id) != 64 or any(c not in "0123456789abcdef" for c in snapshot_id):
            raise WorkbenchError("INVALID_SNAPSHOT_ID")
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM ow.visible_snapshots WHERE snapshot_id=%s", (snapshot_id,)
            ).fetchone()
        if row is None:
            raise WorkbenchError("SNAPSHOT_NOT_FOUND")
        return row

    def sources(self) -> list[dict]:
        with self.connect() as conn:
            return conn.execute(
                "SELECT * FROM ow.source_status ORDER BY source_id LIMIT 1000"
            ).fetchall()

    def status(self) -> dict:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM ow.pipeline_status").fetchone()
            version = conn.execute("SELECT version FROM ow.schema_status").fetchone()["version"]
            lifecycle = conn.execute("SELECT * FROM ow.lifecycle_status").fetchone()
        return {
            **row,
            "configured": row["sources"] > 0,
            "retrieval": "lexical",
            "schema_version": version,
            "lifecycle": lifecycle,
        }

    def enqueue(self, kind: str, dedup: str, payload: dict) -> str:
        from .jobs import bounded_json

        if not kind or len(kind) > 100 or not dedup or len(dedup) > 4096:
            raise WorkbenchError("INVALID_JOB")
        bounded = bounded_json(payload)
        with self.connect() as conn:
            if "document_id" in payload:
                from .lifecycle import assert_document_visible

                assert_document_visible(conn, payload["document_id"])
            return str(
                conn.execute(
                    """INSERT INTO ow.jobs(job_id,kind,dedup_key,payload)
              VALUES (%s,%s,%s,%s) ON CONFLICT(kind,dedup_key)
              DO UPDATE SET dedup_key=excluded.dedup_key RETURNING job_id""",
                    (uuid.uuid4(), kind, dedup, bounded),
                ).fetchone()["job_id"]
            )

    def claim(self, lease_seconds: int = 30) -> dict | None:
        from .jobs import Jobs

        return Jobs(self).claim(lease_seconds=lease_seconds)

    def finish(self, job_id: str, fence: str, result: dict) -> None:
        from .jobs import Jobs

        Jobs(self).finish(job_id, fence, result)
