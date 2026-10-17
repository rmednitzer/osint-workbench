"""Optional exact pgvector generations. Active metadata never points at a partial build."""

import json
import uuid
from importlib.resources import files

import psycopg
from psycopg.types.json import Jsonb

from .database import Database, migrate
from .errors import WorkbenchError
from .evidence import EvidenceStore
from .local_encoder import LocalEncoder
from .retrieval import reciprocal_rank_fusion
from .text import digest


def migrate_retrieval(dsn):
    migrate(dsn)
    script = files("osint_workbench").joinpath("retrieval.sql").read_text()
    sha = digest(script.encode())
    with psycopg.connect(dsn) as conn:
        conn.execute("SELECT pg_advisory_xact_lock(418287405)")
        exists = conn.execute("SELECT to_regclass('ow.retrieval_migrations')").fetchone()[0]
        if exists:
            rows = conn.execute("SELECT version,sha256 FROM ow.retrieval_migrations").fetchall()
            if rows != [(1, sha)]:
                raise WorkbenchError("RETRIEVAL_MIGRATION_MISMATCH")
            return
        if conn.execute("SELECT 1 FROM pg_extension WHERE extname='vector'").fetchone():
            raise WorkbenchError("VECTOR_EXTENSION_ALREADY_PROVISIONED")
        conn.execute(script)
        conn.execute("INSERT INTO ow.retrieval_migrations VALUES (1,%s)", (sha,))


def corpus(conn, *, bodies=False):
    summary = conn.execute("""SELECT count(*) AS n,coalesce(sum(length(body)),0) AS size
                              FROM ow.active_documents""").fetchone()
    if summary["n"] > 1000 or summary["size"] > 2_000_000:
        raise WorkbenchError("REFERENCE_CORPUS_LIMIT")
    columns = "document_id,snapshot_id,body" if bodies else "document_id"
    # The selected columns are fixed internal constants.
    rows = conn.execute(
        "SELECT " + columns + " FROM ow.active_documents ORDER BY document_id"
    ).fetchall()
    return rows, digest(json.dumps([r["document_id"] for r in rows]).encode())


class VectorIndex:
    def __init__(self, db: Database, encoder: LocalEncoder):
        self.db, self.encoder = db, encoder
        self.space_id = encoder.manifest.identity()

    def build(self, store: EvidenceStore):
        with self.db.connect() as conn:
            conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            rows, corpus_sha = corpus(conn, bodies=True)
        if not rows:
            raise WorkbenchError("EMPTY_RETRIEVAL_CORPUS")
        generation = uuid.uuid4()
        manifest = self.encoder.manifest.model_dump(
            exclude={"model_path", "tokenizer_path", "threads"}
        )
        dimensions = self.encoder.manifest.space.dimensions
        with self.db.connect() as conn:
            conn.execute(
                """INSERT INTO ow.embedding_spaces(space_id,manifest,dimensions)
                          VALUES (%s,%s,%s) ON CONFLICT DO NOTHING""",
                (self.space_id, Jsonb(manifest), dimensions),
            )
            conn.execute(
                """INSERT INTO ow.retrieval_generations
                          (generation_id,space_id,dimensions,corpus_sha256,status)
                          VALUES (%s,%s,%s,%s,'building')""",
                (generation, self.space_id, dimensions, corpus_sha),
            )
        try:
            count = 0
            for row in rows:
                snapshot = self.db.snapshot(row["snapshot_id"])
                raw_text = store.get(snapshot["text_sha256"])
                store.get(snapshot["raw_sha256"])
                if digest(row["body"].encode()) != digest(raw_text):
                    raise WorkbenchError("DOCUMENT_INTEGRITY_MISMATCH")
                vectors = self.encoder.chunks(raw_text.decode("utf-8"))
                count += len(vectors)
                if count > 4096:
                    raise WorkbenchError("REFERENCE_CHUNK_LIMIT")
                with self.db.connect() as conn:
                    conn.execute(
                        "INSERT INTO ow.retrieval_members VALUES (%s,%s)",
                        (generation, row["document_id"]),
                    )
                    for ordinal, vector in enumerate(vectors):
                        start, end = vector["start"], vector["end"]
                        if (
                            type(start) is not int
                            or type(end) is not int
                            or not 0 <= start < end <= len(row["body"])
                            or digest(row["body"][start:end].encode()) != vector["sha256"]
                        ):
                            raise WorkbenchError("INVALID_CHUNK_PROVENANCE")
                        conn.execute(
                            """INSERT INTO ow.retrieval_vectors
                            (generation_id,space_id,dimensions,document_id,ordinal,
                             start_offset,end_offset,text_sha256,embedding)
                            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s::ow_vector.vector)""",
                            (
                                generation,
                                self.space_id,
                                dimensions,
                                row["document_id"],
                                ordinal,
                                start,
                                end,
                                vector["sha256"],
                                json.dumps(vector["vector"]),
                            ),
                        )
            with self.db.connect() as conn:
                conn.execute(
                    "UPDATE ow.retrieval_generations SET status='ready' WHERE generation_id=%s",
                    (generation,),
                )
            return {
                "generation_id": str(generation),
                "space_id": self.space_id,
                "documents": len(rows),
                "chunks": count,
                "status": "ready",
            }
        except Exception as exc:
            code = exc.code if isinstance(exc, WorkbenchError) else "INDEX_BUILD_FAILED"
            with self.db.connect() as conn:
                conn.execute(
                    "UPDATE ow.retrieval_generations SET status='failed',error_code=%s "
                    "WHERE generation_id=%s",
                    (code, generation),
                )
            raise WorkbenchError(code) from None

    def activate(self, generation_id):
        try:
            identifier = uuid.UUID(str(generation_id))
        except (ValueError, TypeError):
            raise WorkbenchError("INVALID_GENERATION_ID") from None
        with self.db.connect() as conn:
            conn.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            conn.execute("SELECT pg_advisory_xact_lock(418287407)")
            row = conn.execute(
                "SELECT * FROM ow.retrieval_generations WHERE generation_id=%s", (identifier,)
            ).fetchone()
            if not row or row["status"] != "ready" or row["space_id"] != self.space_id:
                raise WorkbenchError("INCOMPATIBLE_GENERATION")
            members, sha = corpus(conn)
            stored = conn.execute(
                "SELECT document_id FROM ow.retrieval_members "
                "WHERE generation_id=%s ORDER BY document_id",
                (identifier,),
            ).fetchall()
            if sha != row["corpus_sha256"] or stored != members or not members:
                raise WorkbenchError("STALE_RETRIEVAL_GENERATION")
            missing = conn.execute(
                """SELECT 1 FROM ow.retrieval_members m
                WHERE generation_id=%s AND NOT EXISTS (SELECT 1 FROM ow.retrieval_vectors v
                WHERE v.generation_id=m.generation_id AND v.document_id=m.document_id) LIMIT 1""",
                (identifier,),
            ).fetchone()
            if missing:
                raise WorkbenchError("INCOMPLETE_RETRIEVAL_GENERATION")
            conn.execute(
                """INSERT INTO ow.retrieval_active(singleton,generation_id) VALUES (true,%s)
                          ON CONFLICT(singleton) DO UPDATE
                          SET generation_id=excluded.generation_id""",
                (identifier,),
            )
        return {"generation_id": str(identifier), "status": "active"}

    def status(self):
        with self.db.connect() as conn:
            exists = conn.execute(
                "SELECT to_regclass('ow.retrieval_active') AS relation"
            ).fetchone()["relation"]
            if exists is None:
                return {"retrieval": "hybrid-exact", "retrieval_state": "unconfigured"}
            row = conn.execute("""SELECT g.space_id,g.generation_id,g.status
                FROM ow.retrieval_active a JOIN ow.retrieval_generations g
                USING(generation_id)""").fetchone()
            return {
                "retrieval": "hybrid-exact",
                "retrieval_state": "unconfigured"
                if not row
                else "ready"
                if row["space_id"] == self.space_id and row["status"] == "ready"
                else "incompatible",
                "generation_id": str(row["generation_id"]) if row else None,
            }

    def search(self, query: str, limit: int = 20, offset: int = 0):
        if not isinstance(query, str) or not 1 <= len(query.strip()) <= 2000:
            raise WorkbenchError("INVALID_QUERY")
        if type(limit) is not int or not 1 <= limit <= 100:
            raise WorkbenchError("INVALID_PAGE")
        if type(offset) is not int or not 0 <= offset <= 200:
            raise WorkbenchError("INVALID_PAGE")
        with self.db.connect() as conn:
            conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            active = conn.execute("""SELECT g.* FROM ow.retrieval_active a
                                   JOIN ow.retrieval_generations g
                                   USING(generation_id)""").fetchone()
            if not active:
                raise WorkbenchError("RETRIEVAL_UNCONFIGURED")
            if active["space_id"] != self.space_id or active["status"] != "ready":
                raise WorkbenchError("INCOMPATIBLE_GENERATION")
            vector = self.encoder.query(query)
            _, sha = corpus(conn)
            semantic = conn.execute(
                """SELECT v.document_id,
                min(v.embedding OPERATOR(ow_vector.<=>) %s::ow_vector.vector) AS distance
                FROM ow.retrieval_vectors v JOIN ow.active_documents d USING(document_id)
                WHERE generation_id=%s GROUP BY v.document_id ORDER BY distance,v.document_id
                LIMIT 100""",
                (json.dumps(vector), active["generation_id"]),
            ).fetchall()
            lexical = conn.execute(
                """SELECT document_id FROM ow.active_documents
                WHERE search_vector @@ websearch_to_tsquery('simple',%s)
                ORDER BY ts_rank_cd(search_vector,websearch_to_tsquery('simple',%s)) DESC,
                document_id LIMIT 100""",
                (query, query),
            ).fetchall()
            fused = reciprocal_rank_fusion(
                [[r["document_id"] for r in lexical], [r["document_id"] for r in semantic]]
            )[offset : offset + limit]
            results = []
            for rank in fused:
                doc = conn.execute(
                    "SELECT document_id,snapshot_id,source_id,title,left(body,1000) "
                    "AS excerpt FROM ow.active_documents WHERE document_id=%s",
                    (rank["id"],),
                ).fetchone()
                results.append({**doc, "rrf_score": rank["rrf_score"]})
            return {
                "strategy": "hybrid-exact",
                "generation_id": str(active["generation_id"]),
                "space_id": self.space_id,
                "degraded": sha != active["corpus_sha256"],
                "degradation_reason": "CORPUS_CHANGED" if sha != active["corpus_sha256"] else None,
                "results": results,
            }
