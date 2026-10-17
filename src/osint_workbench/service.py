from .database import Database
from .errors import WorkbenchError
from .evidence import EvidenceStore
from .text import digest


class ReadService:
    def __init__(self, db: Database, store: EvidenceStore):
        db.validate_reader()
        if not store.read_only:
            raise ValueError("reader requires a read-only store")
        self.db, self.store = db, store

    def search(self, query: str, limit: int = 20, offset: int = 0):
        return {
            "strategy": "lexical",
            "degraded": False,
            "results": self.db.search(query, limit, offset),
        }

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
