"""Exact pgvector generations: only fully accounted builds may activate.

Explicit content exclusions can leave an active generation semantically partial.
"""

import json
import uuid
from importlib.resources import files

import psycopg
from psycopg.types.json import Jsonb

from .database import LIFECYCLE_LOCK, Database, migrate
from .errors import WorkbenchError
from .evidence import EvidenceStore
from .lifecycle import assert_document_visible
from .local_encoder import LocalEncoder
from .retrieval import reciprocal_rank_fusion
from .text import digest


def migrate_retrieval(dsn):
    migrate(dsn)
    scripts = [
        files("osint_workbench").joinpath(p).read_text()
        for p in (
            "retrieval.sql",
            "migrations/retrieval_002_lifecycle.sql",
            "migrations/retrieval_003_purge_role.sql",
            "migrations/retrieval_004_member_exclusions.sql",
        )
    ]
    with psycopg.connect(dsn) as conn:
        conn.execute("SELECT pg_advisory_xact_lock(%s)", (LIFECYCLE_LOCK,))
        conn.execute("SELECT pg_advisory_xact_lock(418287405)")
        exists = conn.execute("SELECT to_regclass('ow.retrieval_migrations')").fetchone()[0]
        applied = (
            dict(conn.execute("SELECT version,sha256 FROM ow.retrieval_migrations").fetchall())
            if exists
            else {}
        )
        if set(applied) != set(range(1, len(applied) + 1)) or len(applied) > len(scripts):
            raise WorkbenchError("RETRIEVAL_MIGRATION_MISMATCH")
        if (
            not exists
            and conn.execute("SELECT 1 FROM pg_extension WHERE extname='vector'").fetchone()
        ):
            raise WorkbenchError("VECTOR_EXTENSION_ALREADY_PROVISIONED")
        for version, script in enumerate(scripts, 1):
            sha = digest(script.encode())
            if version in applied:
                if applied[version] != sha:
                    raise WorkbenchError("RETRIEVAL_MIGRATION_MISMATCH")
                continue
            conn.execute(script)
            conn.execute("INSERT INTO ow.retrieval_migrations VALUES (%s,%s)", (version, sha))


def corpus(conn, *, bodies=False):
    summary = conn.execute("""SELECT count(*) AS n,coalesce(sum(length(body)),0) AS size
                              FROM ow.active_documents""").fetchone()
    if summary["n"] > 1000 or summary["size"] > 2_000_000:
        raise WorkbenchError("REFERENCE_CORPUS_LIMIT")
    columns = "document_id,snapshot_id,body" if bodies else "document_id"
    # The selected columns are fixed internal constants.
    rows = conn.execute(
        "SELECT " + columns + " FROM ow.active_documents ORDER BY document_id"  # noqa: S608
    ).fetchall()
    return rows, digest(json.dumps([r["document_id"] for r in rows]).encode())


# Encoder refusals determined by document content under a fixed manifest. Any
# other failure (integrity, compatibility, timeout, availability) fails the build.
EXCLUSION_REASONS = frozenset(
    {
        "INVALID_ENCODER_INPUT",
        "ENCODER_PACKET_TOO_LARGE",
        "ENCODER_INPUT_TOO_LONG",
        "TOKEN_OFFSETS_UNSUPPORTED",
        "ENCODER_CHUNK_LIMIT",
        "ENCODER_RESULT_LIMIT",
        # A chunk of only unknown tokens can pool to a zero vector.
        "INVALID_EMBEDDING_NORM",
    }
)

# Each member has exactly one disposition: vectors or an explicit exclusion.
_UNACCOUNTED = """SELECT 1 FROM ow.retrieval_members m WHERE generation_id=%s
    AND EXISTS (SELECT 1 FROM ow.retrieval_vectors v
    WHERE v.generation_id=m.generation_id AND v.document_id=m.document_id)
    = EXISTS (SELECT 1 FROM ow.retrieval_exclusions e
    WHERE e.generation_id=m.generation_id AND e.document_id=m.document_id) LIMIT 1"""


def _profile_current(conn):
    # A newer binary on an unmigrated profile must fail typed, never with raw SQL.
    return (
        conn.execute("SELECT to_regclass('ow.visible_retrieval_exclusions') AS v").fetchone()["v"]
        is not None
    )


def _excluded(conn, generation_id):
    return conn.execute(
        "SELECT count(*) AS n FROM ow.visible_retrieval_exclusions WHERE generation_id=%s",
        (generation_id,),
    ).fetchone()["n"]


class VectorIndex:
    def __init__(self, db: Database, encoder: LocalEncoder):
        self.db, self.encoder = db, encoder
        self.space_id = encoder.manifest.identity()

    @staticmethod
    def _building(conn, generation):
        # A status fence is checked under the row lock; all accepted chunks in
        # this transaction retain that authority until commit. Cooperative purge
        # additionally holds the exclusive lifecycle barrier between transactions.
        row = conn.execute(
            "SELECT status FROM ow.retrieval_generations WHERE generation_id=%s FOR UPDATE",
            (generation,),
        ).fetchone()
        if row is None or row["status"] != "building":
            raise WorkbenchError("RETRIEVAL_GENERATION_INVALIDATED")

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
            excluded = {}
            for row in rows:
                snapshot = self.db.snapshot(row["snapshot_id"])
                raw_text = store.get(snapshot["text_sha256"])
                store.get(snapshot["raw_sha256"])
                if digest(row["body"].encode()) != digest(raw_text):
                    raise WorkbenchError("DOCUMENT_INTEGRITY_MISMATCH")
                reason = None
                with self.db.connect() as authority:
                    self._building(authority, generation)
                    assert_document_visible(authority, row["document_id"])
                    try:
                        vectors = self.encoder.chunks(raw_text.decode("utf-8"))
                    except WorkbenchError as exc:
                        if exc.code not in EXCLUSION_REASONS:
                            raise
                        vectors, reason = [], exc.code
                if reason is not None:
                    excluded[reason] = excluded.get(reason, 0) + 1
                    if 2 * sum(excluded.values()) > len(rows):
                        raise WorkbenchError("RETRIEVAL_EXCLUSION_LIMIT")
                count += len(vectors)
                if count > 4096:
                    raise WorkbenchError("REFERENCE_CHUNK_LIMIT")
                with self.db.connect() as conn:
                    self._building(conn, generation)
                    assert_document_visible(conn, row["document_id"])
                    conn.execute(
                        "INSERT INTO ow.retrieval_members VALUES (%s,%s)",
                        (generation, row["document_id"]),
                    )
                    if reason is not None:
                        conn.execute(
                            "INSERT INTO ow.retrieval_exclusions VALUES (%s,%s,%s)",
                            (generation, row["document_id"], reason),
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
                self._building(conn, generation)
                stored = conn.execute(
                    "SELECT document_id FROM ow.retrieval_members "
                    "WHERE generation_id=%s ORDER BY document_id",
                    (generation,),
                ).fetchall()
                missing = conn.execute(_UNACCOUNTED, (generation,)).fetchone()
                recorded = conn.execute(
                    "SELECT count(*) AS n FROM ow.retrieval_exclusions WHERE generation_id=%s",
                    (generation,),
                ).fetchone()["n"]
                actual_chunks = conn.execute(
                    "SELECT count(*) AS n FROM ow.retrieval_vectors WHERE generation_id=%s",
                    (generation,),
                ).fetchone()["n"]
                # Validate the captured build contract, not the current corpus:
                # unrelated corpus drift remains a separate activation decision.
                if (
                    stored != [{"document_id": row["document_id"]} for row in rows]
                    or missing
                    or actual_chunks != count
                    or recorded != sum(excluded.values())
                    or count == 0
                ):
                    raise WorkbenchError("INCOMPLETE_RETRIEVAL_GENERATION")
                ready = conn.execute(
                    "UPDATE ow.retrieval_generations SET status='ready' "
                    "WHERE generation_id=%s AND status='building' RETURNING generation_id",
                    (generation,),
                ).fetchone()
                if ready is None:
                    raise WorkbenchError("RETRIEVAL_GENERATION_INVALIDATED")
            return {
                "generation_id": str(generation),
                "space_id": self.space_id,
                "documents": len(rows),
                "chunks": count,
                "excluded_documents": sum(excluded.values()),
                "exclusion_reasons": dict(sorted(excluded.items())),
                "status": "ready",
            }
        except Exception as exc:
            code = exc.code if isinstance(exc, WorkbenchError) else "INDEX_BUILD_FAILED"
            with self.db.connect() as conn:
                conn.execute(
                    "UPDATE ow.retrieval_generations SET status='failed',error_code=%s "
                    "WHERE generation_id=%s AND status='building'",
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
            missing = conn.execute(_UNACCOUNTED, (identifier,)).fetchone()
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
            if not _profile_current(conn):
                return {"retrieval": "hybrid-exact", "retrieval_state": "migration_required"}
            row = conn.execute("""SELECT g.space_id,g.generation_id,g.status
                FROM ow.retrieval_active a JOIN ow.retrieval_generations g
                USING(generation_id)""").fetchone()
            return {
                "excluded_documents": _excluded(conn, row["generation_id"]) if row else None,
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
            if not _profile_current(conn):
                raise WorkbenchError("RETRIEVAL_MIGRATION_REQUIRED")
            if active["space_id"] != self.space_id or active["status"] != "ready":
                raise WorkbenchError("INCOMPATIBLE_GENERATION")
            vector = self.encoder.query(query)
            try:
                _, sha = corpus(conn)
                drifted = sha != active["corpus_sha256"]
            except WorkbenchError as exc:
                if exc.code != "REFERENCE_CORPUS_LIMIT":
                    raise
                # No generation can exceed the build bounds and document IDs bind
                # immutable content, so an over-limit corpus has necessarily drifted.
                drifted = True
            semantic = conn.execute(
                """SELECT v.document_id,
                min(v.embedding OPERATOR(ow_vector.<=>) %s::ow_vector.vector) AS distance
                FROM ow.visible_retrieval_vectors v JOIN ow.active_documents d USING(document_id)
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
                # Excluded documents are reachable lexically, never semantically.
                "excluded_documents": _excluded(conn, active["generation_id"]),
                "degraded": drifted,
                "degradation_reason": "CORPUS_CHANGED" if drifted else None,
                "results": results,
            }
