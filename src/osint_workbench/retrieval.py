import hashlib
import json
import math
from collections import defaultdict
from typing import Literal

from pydantic import Field

from .contracts import StrictModel
from .errors import WorkbenchError


class EmbeddingSpace(StrictModel):
    model_revision: str = Field(min_length=1)
    tokenizer_revision: str = Field(min_length=1)
    query_template: str
    document_template: str
    pooling: str = Field(min_length=1)
    dimensions: int = Field(ge=1, le=65536)
    normalized: bool
    metric: Literal["cosine", "l2", "inner_product"]
    precision: Literal["float32", "float16"]

    def fingerprint(self) -> str:
        return hashlib.sha256(json.dumps(self.model_dump(), sort_keys=True).encode()).hexdigest()

    def validate_vector(self, vector: list[float]) -> None:
        if len(vector) != self.dimensions or any(
            type(v) not in (int, float) or not math.isfinite(v) for v in vector
        ):
            raise WorkbenchError("INVALID_EMBEDDING_VECTOR")
        norm = math.sqrt(sum(v * v for v in vector))
        if (self.metric == "cosine" and norm == 0) or (self.normalized and abs(norm - 1) > 1e-3):
            raise WorkbenchError("INVALID_EMBEDDING_NORM")


def reciprocal_rank_fusion(rankings: list[list[str]], *, k: int = 60) -> list[dict]:
    if type(k) is not int or k < 1 or len(rankings) > 16 or sum(map(len, rankings)) > 10000:
        raise WorkbenchError("INVALID_RANKING")
    scores = defaultdict(float)
    for ranking in rankings:
        if len(ranking) != len(set(ranking)):
            raise WorkbenchError("DUPLICATE_RANKING_ID")
        for rank, identifier in enumerate(ranking, start=1):
            scores[identifier] += 1 / (k + rank)
    return [
        {"id": key, "rrf_score": scores[key]}
        for key in sorted(scores, key=lambda key: (-scores[key], key))
    ]
