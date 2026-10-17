import hashlib
import json
import uuid
from importlib.resources import files

import psycopg
from psycopg.rows import dict_row

from .contracts import DocumentInput
from .errors import WorkbenchError
from .evidence import EvidenceStore


def migrate(dsn: str) -> None:
    script = files("osint_workbench").joinpath("schema.sql").read_text()
    sha = hashlib.sha256(script.encode()).hexdigest()
    with psycopg.connect(dsn) as conn:
        conn.execute("SELECT pg_advisory_xact_lock(418287405)")
        exists = conn.execute("SELECT to_regclass('ow.migrations')").fetchone()[0]
        if exists:
            row = conn.execute("SELECT sha256 FROM ow.migrations WHERE version=1").fetchone()
            if row:
                if row[0] != sha:
                    raise WorkbenchError("MIGRATION_DIGEST_MISMATCH")
                return
        conn.execute(script)
        conn.execute("INSERT INTO ow.migrations(version,sha256) VALUES (1,%s)", (sha,))


class Database:
    def __init__(self, dsn: str):
        self._dsn = dsn

    def connect(self):
        return psycopg.connect(
            self._dsn,
            row_factory=dict_row,
            options="-c statement_timeout=10000 -c lock_timeout=5000",
        )

    def validate_reader(self) -> None:
        with self.connect() as conn:
            row = conn.execute("""SELECT rolsuper,rolcreaterole,rolcreatedb,rolbypassrls
              FROM pg_roles WHERE rolname=current_user""").fetchone()
            if any(row.values()):
                raise WorkbenchError("UNSAFE_READER_IDENTITY")
            row = conn.execute("""SELECT
              has_table_privilege(current_user,'ow.documents','INSERT,UPDATE,DELETE') AS docs,
              has_table_privilege(current_user,'ow.jobs','INSERT,UPDATE,DELETE') AS jobs,
              has_schema_privilege(current_user,'ow','CREATE') AS ddl,
              pg_has_role(current_user,'ow_writer','MEMBER') AS writer""").fetchone()
            if any(row.values()):
                raise WorkbenchError("UNSAFE_READER_IDENTITY")

    def ingest(
        self, doc: DocumentInput, raw: bytes, store: EvidenceStore, extractor: str = "text/1"
    ) -> str:
        # Objects are durable before accepted metadata. DB failure may leave an
        # orphan; it must not create accepted records pointing at missing bytes.
        raw_sha, text_sha = store.put(raw), store.put(doc.text.encode())
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
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO ow.sources(source_id) VALUES (%s) ON CONFLICT DO NOTHING",
                (doc.source_id,),
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
                        psycopg.types.json.Jsonb(
                            {"document_id": document, "snapshot_id": snapshot}
                        ),
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
              body AS full_body,published_at FROM ow.documents WHERE document_id=%s""",
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
                "SELECT * FROM ow.snapshots WHERE snapshot_id=%s", (snapshot_id,)
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
        return {
            **row,
            "configured": row["sources"] > 0,
            "retrieval": "lexical",
            "schema_version": 1,
        }

    def enqueue(self, kind: str, dedup: str, payload: dict) -> str:
        if not kind or len(kind) > 100 or not dedup or len(dedup) > 4096:
            raise WorkbenchError("INVALID_JOB")
        with self.connect() as conn:
            return str(
                conn.execute(
                    """INSERT INTO ow.jobs(job_id,kind,dedup_key,payload)
              VALUES (%s,%s,%s,%s) ON CONFLICT(kind,dedup_key)
              DO UPDATE SET dedup_key=excluded.dedup_key RETURNING job_id""",
                    (uuid.uuid4(), kind, dedup, psycopg.types.json.Jsonb(payload)),
                ).fetchone()["job_id"]
            )

    def claim(self, lease_seconds: int = 30) -> dict | None:
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 3600:
            raise WorkbenchError("INVALID_LEASE")
        with self.connect() as conn:
            return conn.execute(
                """WITH candidate AS (
              SELECT job_id FROM ow.jobs WHERE status='ready' OR
              (status='running' AND lease_until<clock_timestamp())
              ORDER BY job_id FOR UPDATE SKIP LOCKED LIMIT 1)
              UPDATE ow.jobs SET status='running',attempt=attempt+1,fence=%s,
                lease_until=clock_timestamp()+make_interval(secs=>%s)
              WHERE job_id IN (SELECT job_id FROM candidate)
              RETURNING job_id,kind,payload,attempt,fence,lease_until""",
                (uuid.uuid4(), lease_seconds),
            ).fetchone()

    def finish(self, job_id: str, fence: str, result: dict) -> None:
        with self.connect() as conn:
            row = conn.execute(
                """UPDATE ow.jobs SET status='succeeded',result=%s,lease_until=NULL
              WHERE job_id=%s AND fence=%s AND status='running'
              AND lease_until>clock_timestamp() RETURNING job_id""",
                (psycopg.types.json.Jsonb(result), job_id, fence),
            ).fetchone()
            if row is None:
                raise WorkbenchError("STALE_JOB_LEASE")
