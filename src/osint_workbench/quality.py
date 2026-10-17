"""Explicit bounded local diagnostic execution; no semantic acceptance authority."""

import hashlib
import importlib.metadata
import json
import math
import os
import re
import sys
import time
import unicodedata
from pathlib import Path

from .errors import WorkbenchError
from .evaluation import Suite, digest, evaluate, parse_predictions
from .local_encoder import LocalEncoder

MAX_DOCUMENTS = 32
MAX_QUERIES = 32
MAX_FILE_BYTES = 8 * 1024 * 1024
LEXICAL_POLICY = {
    "version": 1,
    "normalization": "NFKC-casefold",
    "tokens": "unicode-alphanumeric-distinct",
    "score": "intersection-count",
    "ties": "document-id-ascending",
    "abstention": "zero-positive-overlap",
}
MODEL_POLICY = {
    "version": 1,
    "score": "exhaustive-normalized-dot-product",
    "ties": "document-id-ascending",
    "abstention": "none-rank-only",
    "document_operation": "document",
    "query_operation": "query",
    "truncation": "forbidden",
}
SAFE_ERRORS = {
    "MODEL_INTEGRITY_MISMATCH",
    "TOKENIZER_INTEGRITY_MISMATCH",
    "ENCODER_INPUT_TOO_LONG",
    "ENCODER_INCOMPATIBLE",
    "INVALID_EMBEDDING_VECTOR",
    "INVALID_EMBEDDING_NORM",
    "ENCODER_TIMEOUT",
    "ENCODER_RESULT_LIMIT",
    "ENCODER_UNAVAILABLE",
    "ENCODER_INVALID_RESULT",
    "INFERENCE_LOCK_UNSAFE",
    "INFERENCE_BUSY",
    "INFERENCE_OUTCOME_UNKNOWN",
    "QUALITY_BUDGET_EXHAUSTED",
    "QUALITY_ENCODER_RESULT_INVALID",
}


def _json(value):
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":")
    ).encode()


def _sha(value):
    return hashlib.sha256(_json(value)).hexdigest()


def _write(directory_fd, name, value):
    data = _json(value)
    if len(data) > MAX_FILE_BYTES:
        raise WorkbenchError("QUALITY_OUTPUT_LIMIT")
    staging = ".staging-" + name
    fd = os.open(
        staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd
    )
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(
            staging, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd, follow_symlinks=False
        )
        os.fsync(directory_fd)
    finally:
        os.unlink(staging, dir_fd=directory_fd)
        os.fsync(directory_fd)


def _tokens(text):
    return set(re.findall(r"[^\W_]+", unicodedata.normalize("NFKC", text).casefold()))


def _versions():
    result = {"python": sys.version.split()[0]}
    for package in ("osint-workbench", "onnxruntime", "tokenizers"):
        try:
            result[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            result[package] = "not-installed"
    return result


def _vector(encoder, rows):
    if len(rows) != 1 or not isinstance(rows[0], dict) or "vector" not in rows[0]:
        raise WorkbenchError("QUALITY_ENCODER_RESULT_INVALID")
    vector = rows[0]["vector"]
    encoder.manifest.space.validate_vector(vector)
    return vector


def run(
    suite: Suite,
    output: Path,
    encoder: LocalEncoder | None = None,
    budget_seconds=120,
    source_revision=None,
) -> dict:
    """Run frozen lexical and optional local-model diagnostics into a new private dir.

    Budget is cooperative: checked before each call; one native encoder call can
    take up to its existing 45-second timeout beyond that budget. Loading encoder
    artifacts and input validation are outside this execution timer. Never retry
    into an existing output directory. Incomplete journals require operator review.
    """
    if (
        not isinstance(suite, Suite)
        or len(suite.corpus) > MAX_DOCUMENTS
        or len(suite.queries) > MAX_QUERIES
        or isinstance(budget_seconds, bool)
        or not isinstance(budget_seconds, (int, float))
        or not math.isfinite(budget_seconds)
        or not 0 < budget_seconds <= 3600
        or (
            source_revision is not None
            and (
                not isinstance(source_revision, str)
                or not re.fullmatch(r"[0-9a-f]{40}", source_revision)
            )
        )
        or (encoder is not None and not isinstance(encoder, LocalEncoder))
    ):
        raise WorkbenchError("QUALITY_CONFIGURATION_INVALID")
    # Revalidate even an operator-created model_copy, before creating any outputs.
    from .evaluation import parse_suite

    suite = parse_suite(suite.model_dump_json().encode())
    protocol = {
        "format": 1,
        "kind": "frozen_local_quality_protocol",
        "suite_sha256": digest(suite),
        "source_revision": source_revision,
        "budget_seconds": budget_seconds,
        "lexical_policy": dict(LEXICAL_POLICY),
        "encoder_policy": dict(MODEL_POLICY),
        "encoder_identity": encoder.manifest.identity() if encoder else None,
        "encoder_threads": encoder.manifest.threads if encoder else None,
        "software_versions": _versions(),
        "max_documents": MAX_DOCUMENTS,
        "max_queries": MAX_QUERIES,
        "native_call_timeout_seconds": 45,
        "deadline_policy": "check-before-call-no-interrupt",
        "semantic_acceptance": "not_established_by_public_diagnostic",
    }
    protocol_sha = _sha(protocol)
    try:
        os.mkdir(output, 0o700)
    except FileExistsError:
        raise WorkbenchError("QUALITY_OUTPUT_EXISTS") from None
    directory_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parent_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        _write(directory_fd, "suite.json", suite.model_dump(mode="json"))
        _write(directory_fd, "protocol.json", {"payload": protocol, "sha256": protocol_sha})
        started = time.monotonic()
        results = {}
        progress = {
            "phase": "lexical",
            "completed_lexical_queries": 0,
            "completed_encoder_documents": 0,
            "completed_encoder_queries": 0,
        }

        def check_budget():
            if time.monotonic() - started >= budget_seconds:
                raise WorkbenchError("QUALITY_BUDGET_EXHAUSTED")

        def persist(system_id, manifest_sha, rankings, scores, elapsed):
            prediction_data = {
                "format": 1,
                "suite_sha256": digest(suite),
                "system_id": system_id,
                "system_manifest_sha256": manifest_sha,
                "rankings": rankings,
            }
            prediction = parse_predictions(_json(prediction_data))
            receipt = evaluate(suite, prediction)
            _write(directory_fd, system_id + "-predictions.json", prediction_data)
            _write(
                directory_fd,
                system_id + "-scores.json",
                {
                    "protocol_sha256": protocol_sha,
                    "predictions_sha256": digest(prediction),
                    "elapsed_seconds": elapsed,
                    "queries": scores,
                },
            )
            _write(directory_fd, system_id + "-evaluation.json", receipt)
            results[system_id] = {
                "receipt_sha256": receipt["sha256"],
                "all_targets_met": all(
                    s["all_targets_met"] for s in receipt["payload"]["splits"].values()
                ),
            }

        try:
            lexical_started = time.monotonic()
            documents = {d.document_id: _tokens(d.text) for d in suite.corpus}
            rankings, scores = [], []
            for query in suite.queries:
                check_budget()
                query_started = time.monotonic()
                words = _tokens(query.text)
                scored = sorted(
                    (
                        (identifier, float(len(words & tokens)))
                        for identifier, tokens in documents.items()
                    ),
                    key=lambda row: (-row[1], row[0]),
                )
                hits = [identifier for identifier, score in scored if score > 0][: suite.cutoff]
                rankings.append(
                    {"query_id": query.query_id, "abstained": not hits, "document_ids": hits}
                )
                scores.append(
                    {
                        "query_id": query.query_id,
                        "scores": scored,
                        "elapsed_seconds": time.monotonic() - query_started,
                    }
                )
                progress["completed_lexical_queries"] += 1
            persist(
                "lexical",
                _sha(LEXICAL_POLICY),
                rankings,
                scores,
                time.monotonic() - lexical_started,
            )
            if encoder is not None:
                model_started = time.monotonic()
                vectors = {}
                document_timings = []
                progress["phase"] = "encoder_documents"
                for ordinal, document in enumerate(suite.corpus):
                    check_budget()
                    call_started = time.monotonic()
                    vectors[document.document_id] = _vector(
                        encoder, encoder.invoke(document.text, operation="document")
                    )
                    observation = {
                        "protocol_sha256": protocol_sha,
                        "document_id": document.document_id,
                        "elapsed_seconds": time.monotonic() - call_started,
                    }
                    _write(directory_fd, f"encoder-document-{ordinal:03d}.json", observation)
                    document_timings.append(observation)
                    progress["completed_encoder_documents"] += 1
                rankings, scores = [], []
                progress["phase"] = "encoder_queries"
                for ordinal, query in enumerate(suite.queries):
                    check_budget()
                    query_started = time.monotonic()
                    vector = encoder.query(query.text)
                    encoder.manifest.space.validate_vector(vector)
                    scored = sorted(
                        (
                            (
                                identifier,
                                math.fsum(a * b for a, b in zip(vector, other, strict=True)),
                            )
                            for identifier, other in vectors.items()
                        ),
                        key=lambda row: (-row[1], row[0]),
                    )
                    rankings.append(
                        {
                            "query_id": query.query_id,
                            "abstained": False,
                            "document_ids": [
                                identifier for identifier, _ in scored[: suite.cutoff]
                            ],
                        }
                    )
                    observation = {
                        "protocol_sha256": protocol_sha,
                        "query_id": query.query_id,
                        "scores": scored,
                        "elapsed_seconds": time.monotonic() - query_started,
                    }
                    _write(directory_fd, f"encoder-query-{ordinal:03d}.json", observation)
                    scores.append(observation)
                    progress["completed_encoder_queries"] += 1
                progress["phase"] = "encoder_receipts"
                _write(
                    directory_fd,
                    "encoder-document-timings.json",
                    {"protocol_sha256": protocol_sha, "documents": document_timings},
                )
                persist(
                    "encoder",
                    encoder.manifest.identity(),
                    rankings,
                    scores,
                    time.monotonic() - model_started,
                )
            progress["phase"] = "completed"
            outcome = {
                "format": 1,
                "status": "completed",
                "progress": dict(progress),
                "protocol_sha256": protocol_sha,
                "elapsed_seconds": time.monotonic() - started,
                "systems": results,
                "all_targets_met": all(r["all_targets_met"] for r in results.values()),
                "semantic_acceptance": "not_established_by_public_diagnostic",
            }
            _write(directory_fd, "completed.json", outcome)
            return outcome
        except Exception as error:
            code = error.code if isinstance(error, WorkbenchError) else "QUALITY_EXECUTION_FAILED"
            if code not in SAFE_ERRORS:
                code = "QUALITY_EXECUTION_FAILED"
            outcome = {
                "format": 1,
                "status": "failed",
                "error": code,
                "progress": dict(progress),
                "protocol_sha256": protocol_sha,
                "systems": results,
                "elapsed_seconds": time.monotonic() - started,
                "all_targets_met": False,
                "semantic_acceptance": "not_established_by_public_diagnostic",
            }
            _write(directory_fd, "failed.json", outcome)
            return outcome
    finally:
        os.close(directory_fd)
