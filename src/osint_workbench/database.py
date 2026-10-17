import hashlib
import json
import uuid
from importlib.resources import files

import psycopg
from psycopg.rows import dict_row

from .contracts import DocumentInput
from .errors import WorkbenchError
from .evidence import EvidenceStore

SCHEMA_VERSION = 4
LIFECYCLE_LOCK = 418287408


def migrate(dsn: str) -> None:
    package = files("osint_workbench")
    scripts = [
        package.joinpath("schema.sql"),
        package.joinpath("migrations/002_workflows.sql"),
        package.joinpath("migrations/003_intelligence.sql"),
        package.joinpath("migrations/004_lifecycle.sql"),
    ]
    with psycopg.connect(dsn) as conn:
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
            row = conn.execute("""SELECT rolsuper,rolcreaterole,rolcreatedb,rolbypassrls
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
                    ],
                ),
            ).fetchone():
                raise WorkbenchError("UNSAFE_READER_IDENTITY")
            row = conn.execute("""SELECT
              has_table_privilege(current_user,'ow.documents','INSERT,UPDATE,DELETE') AS docs,
              has_table_privilege(current_user,'ow.jobs','INSERT,UPDATE,DELETE') AS jobs,
              has_schema_privilege(current_user,'ow','CREATE') AS ddl,
              pg_has_role(current_user,'ow_writer','MEMBER') AS writer,
              pg_has_role(current_user,'ow_lifecycle','MEMBER') AS lifecycle""").fetchone()
            if any(row.values()):
                raise WorkbenchError("UNSAFE_READER_IDENTITY")
            if conn.execute("""SELECT 1 FROM pg_class c JOIN pg_namespace n
              ON n.oid=c.relnamespace WHERE n.nspname IN ('ow','ow_vector')
              AND c.relkind IN ('r','p','v','m','f') AND
              (has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE') OR
               has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE'))
              LIMIT 1""").fetchone():
                raise WorkbenchError("UNSAFE_READER_IDENTITY")

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
    def ingest_stored(conn, doc, raw_sha, text_sha, extractor):
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
        if inserted:
            conn.execute(
                """INSERT INTO ow.document_heads(source_id,external_key,document_id)
              VALUES (%s,%s,%s) ON CONFLICT(source_id,external_key)
              DO UPDATE SET document_id=excluded.document_id""",
                (doc.source_id, external, document),
            )
            conn.execute(
                """INSERT INTO ow.jobs(job_id,kind,dedup_key,payload)
              VALUES (%s,'document.accepted',%s,%s) ON CONFLICT DO NOTHING""",
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
