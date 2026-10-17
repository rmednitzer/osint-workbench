from .database import Database
from .errors import WorkbenchError
from .evidence import EvidenceStore
from .text import digest


class ReadService:
    def __init__(self, db: Database, store: EvidenceStore, *, encoder=None, reranker=None):
        db.validate_reader()
        if not store.read_only:
            raise ValueError("reader requires a read-only store")
        self.db, self.store = db, store
        self.reranker = reranker
        self.index = None
        if encoder is not None:
            from .vector_index import VectorIndex

            self.index = VectorIndex(db, encoder)

    def search(self, query: str, limit: int = 20, offset: int = 0):
        if self.reranker is not None:
            if (
                type(limit) is not int
                or not 1 <= limit <= 32
                or type(offset) is not int
                or not 0 <= offset <= 32
            ):
                raise WorkbenchError("INVALID_RERANK_PAGE")
            result = (
                self.index.search(query, 32)
                if self.index is not None
                else {
                    "strategy": "lexical",
                    "degraded": False,
                    "results": self.db.search(query, 32),
                }
            )
            ranked = self.reranker.rank(query, result["results"]) if result["results"] else []
            return {
                **result,
                "strategy": result["strategy"] + "-reranked",
                "reranker_id": self.reranker.manifest.identity(),
                "rerank_input": "first_1000_codepoints",
                "candidate_limit": 32,
                "results": ranked[offset : offset + limit],
            }
        if self.index is not None:
            return self.index.search(query, limit, offset)
        return {
            "strategy": "lexical",
            "degraded": False,
            "results": self.db.search(query, limit, offset),
        }

    def status(self):
        value = self.db.status()
        if self.index is not None:
            value.update(self.index.status())
        return value

    def assertions(self, document_id=None, subject=None, limit=20, offset=0):
        from .intelligence import assertions

        return assertions(
            self.db, document_id=document_id, subject=subject, limit=limit, offset=offset
        )

    def briefing(self, briefing_id):
        from .intelligence import get_briefing

        return get_briefing(self.db, self.store, briefing_id)

    def document(self, document_id: str, offset: int = 0, size: int = 8000):
        result = self.db.document(document_id, offset, size)
        snapshot = self.db.snapshot(result["snapshot_id"])
        body = self.store.get(snapshot["text_sha256"]).decode("utf-8")
        if digest(result.pop("full_body").encode()) != snapshot["text_sha256"]:
            raise WorkbenchError("EVIDENCE_INTEGRITY_MISMATCH")
        result["text"] = body[offset : offset + size]
        result["integrity"] = "verified"
        return result

    def evidence(self, snapshot_id: str):
        result = self.db.snapshot(snapshot_id)
        self.store.get(result["raw_sha256"])
        self.store.get(result["text_sha256"])
        return {**result, "integrity": "verified", "review": "unreviewed"}
