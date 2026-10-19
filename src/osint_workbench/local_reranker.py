"""Local ONNX pair scoring. Scores order candidates; they are not confidence."""

import json
import os
import subprocess
import sys
import tempfile
from typing import Literal

from pydantic import Field

from .contracts import Digest, StrictModel
from .errors import WorkbenchError
from .inference_state import PARENT_ENV
from .local_encoder import admission
from .text import digest


class RerankerManifest(StrictModel):
    schema_version: Literal[1] = 1
    model_path: str = Field(repr=False)
    tokenizer_path: str = Field(repr=False)
    model_sha256: Digest
    tokenizer_sha256: Digest
    output_name: str = Field(min_length=1, max_length=100)
    max_tokens: int = Field(ge=16, le=8192)
    positive_class: int = Field(default=0, ge=0, le=100)
    threads: int = Field(default=1, ge=1, le=8)

    def identity(self):
        return digest(
            json.dumps(
                self.model_dump(exclude={"model_path", "tokenizer_path", "threads"}), sort_keys=True
            ).encode()
        )


class LocalReranker:
    def __init__(self, manifest: RerankerManifest):
        self.manifest = manifest

    def rank(self, query: str, candidates: list[dict]) -> list[dict]:
        if (
            not isinstance(query, str)
            or not 1 <= len(query.strip()) <= 2000
            or not 1 <= len(candidates) <= 32
        ):
            raise WorkbenchError("INVALID_RERANK_INPUT")
        ids = [row["document_id"] for row in candidates]
        if len(set(ids)) != len(ids) or any(
            not isinstance(row["excerpt"], str) or not 1 <= len(row["excerpt"]) <= 1000
            for row in candidates
        ):
            raise WorkbenchError("INVALID_RERANK_INPUT")
        try:
            manifest = RerankerManifest.model_validate_json(self.manifest.model_dump_json())
        except (ValueError, TypeError):
            raise WorkbenchError("RERANK_CONFIGURATION_INVALID") from None
        packet = json.dumps(
            {
                "manifest": manifest.model_dump(),
                "query": query,
                "texts": [r["excerpt"] for r in candidates],
            }
        ).encode()
        with admission(), tempfile.TemporaryFile() as output:
            try:
                result = subprocess.run(
                    [sys.executable, "-I", "-m", "osint_workbench.rerank_process"],
                    input=packet,
                    stdout=output,
                    stderr=subprocess.DEVNULL,
                    timeout=45,
                    env={
                        "OMP_NUM_THREADS": str(manifest.threads),
                        "OPENBLAS_NUM_THREADS": "1",
                        "TOKENIZERS_PARALLELISM": "false",
                        PARENT_ENV: str(os.getpid()),
                    },
                    check=False,
                )
            except subprocess.TimeoutExpired:
                raise WorkbenchError("RERANK_TIMEOUT") from None
            output.seek(0)
            data = output.read(65537)
        if result.returncode != 0:
            try:
                decoded = json.loads(data) if result.returncode > 0 else None
            except ValueError:
                decoded = None
            code = decoded.get("error") if isinstance(decoded, dict) else None
            if code not in {
                "RERANK_INPUT_TOO_LONG",
                "MODEL_INTEGRITY_MISMATCH",
                "TOKENIZER_INTEGRITY_MISMATCH",
                "RERANK_INCOMPATIBLE",
                "INFERENCE_PARENT_UNBOUND",
            }:
                code = "RERANK_UNAVAILABLE"
            raise WorkbenchError(code)
        try:
            decoded = json.loads(data)
            if not isinstance(decoded, dict) or not isinstance(decoded.get("scores"), list):
                raise ValueError
            scores = decoded["scores"]
            import math

            if len(scores) != len(candidates) or any(
                type(v) not in (int, float) or not math.isfinite(v) for v in scores
            ):
                raise ValueError
        except (ValueError, KeyError, TypeError):
            raise WorkbenchError("RERANK_INVALID_RESULT") from None
        result = [
            {**row, "rerank_score": score} for row, score in zip(candidates, scores, strict=True)
        ]
        return sorted(result, key=lambda row: (-row["rerank_score"], row["document_id"]))
