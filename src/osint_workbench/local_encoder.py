"""Explicit local-only ONNX encoder contract. No hub client or automatic downloads."""

import json
import os
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from .contracts import StrictModel
from .errors import WorkbenchError
from .retrieval import EmbeddingSpace
from .text import digest

MAX_INPUT = 200000
MAX_RESULT = 16 * 1024 * 1024


@contextmanager
def admission():
    import fcntl

    path = os.environ.get("OW_INFERENCE_LOCK", f"/tmp/ow-inference-{os.getuid()}.lock")
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise WorkbenchError("INFERENCE_LOCK_UNSAFE")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise WorkbenchError("INFERENCE_BUSY") from None
        yield
    finally:
        os.close(fd)


class EncoderManifest(StrictModel):
    schema_version: Literal[1] = 1
    model_path: str = Field(repr=False)
    tokenizer_path: str = Field(repr=False)
    model_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    tokenizer_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    space: EmbeddingSpace
    max_tokens: int = Field(ge=16, le=8192)
    overlap_tokens: int = Field(ge=0, le=1024)
    output_name: str = Field(min_length=1, max_length=100)
    threads: int = Field(default=1, ge=1, le=8)

    @model_validator(mode="after")
    def supported(self):
        s = self.space
        if (
            s.model_revision != self.model_sha256
            or s.tokenizer_revision != self.tokenizer_sha256
            or s.pooling not in {"mean", "cls", "pooled"}
            or s.precision != "float32"
            or s.metric != "cosine"
            or not s.normalized
        ):
            raise ValueError("unsupported encoder identity or numerical contract")
        if self.overlap_tokens >= self.max_tokens // 2:
            raise ValueError("overlap exceeds supported budget")
        for template in (s.query_template, s.document_template):
            if len(template) > 1000 or template.count("{text}") != 1:
                raise ValueError("template must contain exactly one text slot")
        return self

    def identity(self):
        data = self.model_dump(exclude={"model_path", "tokenizer_path", "threads"})
        return digest(json.dumps(data, sort_keys=True).encode())


class LocalEncoder:
    def __init__(self, manifest: EncoderManifest):
        self.manifest = manifest

    def invoke(self, text: str, *, operation: Literal["query", "document", "chunks"]):
        if not isinstance(text, str) or not text.strip() or len(text) > MAX_INPUT:
            raise WorkbenchError("INVALID_ENCODER_INPUT")
        packet = json.dumps(
            {"manifest": self.manifest.model_dump(), "text": text, "operation": operation}
        ).encode()
        # No credentials, DSNs, hub tokens or ambient proxy configuration enter the child.
        env = {
            "PYTHONIOENCODING": "utf-8",
            "TOKENIZERS_PARALLELISM": "false",
            "OMP_NUM_THREADS": str(self.manifest.threads),
            "OPENBLAS_NUM_THREADS": "1",
            "MKL_NUM_THREADS": "1",
            "RAYON_NUM_THREADS": str(self.manifest.threads),
        }
        with admission(), tempfile.TemporaryFile() as output:
            try:
                result = subprocess.run(
                    [sys.executable, "-I", "-m", "osint_workbench.encoder_process"],
                    input=packet,
                    stdout=output,
                    stderr=subprocess.DEVNULL,
                    env=env,
                    timeout=45,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                raise WorkbenchError("ENCODER_TIMEOUT") from None
            output.seek(0)
            data = output.read(MAX_RESULT + 1)
        if len(data) > MAX_RESULT:
            raise WorkbenchError("ENCODER_RESULT_LIMIT")
        try:
            decoded = json.loads(data)
            if result.returncode != 0:
                code = decoded.get("error") if isinstance(decoded, dict) else None
                if code not in {
                    "MODEL_INTEGRITY_MISMATCH",
                    "TOKENIZER_INTEGRITY_MISMATCH",
                    "ENCODER_INPUT_TOO_LONG",
                    "ENCODER_INCOMPATIBLE",
                    "INVALID_EMBEDDING_VECTOR",
                    "INVALID_EMBEDDING_NORM",
                    "TOKEN_OFFSETS_UNSUPPORTED",
                    "ENCODER_CHUNK_LIMIT",
                }:
                    code = "ENCODER_UNAVAILABLE"
                raise WorkbenchError(code)
            if decoded["encoder_id"] != self.manifest.identity():
                raise ValueError
            for row in decoded["results"]:
                self.manifest.space.validate_vector(row["vector"])
            return decoded["results"]
        except (ValueError, KeyError, TypeError):
            raise WorkbenchError("ENCODER_INVALID_RESULT") from None

    def query(self, text):
        return self.invoke(text, operation="query")[0]["vector"]

    def chunks(self, text):
        return self.invoke(text, operation="chunks")


def verified_file(path: str, sha: str, maximum: int, code: str) -> bytes:
    fd = os.open(Path(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        import stat

        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise WorkbenchError(code)
        value = stream.read(maximum + 1)
    if len(value) > maximum or digest(value) != sha:
        raise WorkbenchError(code)
    return value
