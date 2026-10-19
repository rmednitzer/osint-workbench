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
from .local_reranker import LocalReranker, RerankerManifest

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
RERANKER_POLICY = {
    "version": 1,
    "candidates": "complete-corpus",
    "text": "complete-untruncated",
    "score": "manifest-selected-output-descending",
    "ties": "document-id-ascending",
    "abstention": "none-rank-only",
    "max_document_characters": 1000,
    "max_query_characters": 2000,
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
    "RERANK_INPUT_TOO_LONG",
    "RERANK_INCOMPATIBLE",
    "RERANK_TIMEOUT",
    "RERANK_INVALID_RESULT",
    "RERANK_UNAVAILABLE",
    "QUALITY_RERANK_RESULT_INVALID",
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


def _versions(extra=()):
    result = {"python": sys.version.split()[0]}
    for package in ("osint-workbench", "onnxruntime", "tokenizers", *extra):
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


def _rerank_scores(rows, expected_ids):
    """Bind every numeric observation to exactly the submitted corpus."""
    try:
        if not isinstance(rows, list) or len(rows) != len(expected_ids):
            raise ValueError
        values = [(row["document_id"], row["rerank_score"]) for row in rows]
        if {identifier for identifier, _ in values} != expected_ids or any(
            type(score) not in (int, float) or not math.isfinite(score) for _, score in values
        ):
            raise ValueError
        return sorted(values, key=lambda row: (-row[1], row[0]))
    except (ValueError, TypeError, KeyError, OverflowError):
        raise WorkbenchError("QUALITY_RERANK_RESULT_INVALID") from None


def run(
    suite: Suite,
    output: Path,
    encoder: LocalEncoder | None = None,
    budget_seconds=120,
    source_revision=None,
    *,
    reranker: LocalReranker | None = None,
) -> dict:
    """Run frozen lexical and optional local-model diagnostics into a new private dir.

    Budget is cooperative: checked before each call; one native model call can
    take up to its existing 45-second timeout beyond that budget. Suite validation
    and protocol-file setup precede the timer; native artifact verification/loading
    occurs inside each timed model call. Never retry
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
        or (reranker is not None and not isinstance(reranker, LocalReranker))
    ):
        raise WorkbenchError("QUALITY_CONFIGURATION_INVALID")
    # Revalidate even an operator-created model_copy, before creating any outputs.
    from .evaluation import parse_suite

    suite = parse_suite(suite.model_dump_json().encode())
    if reranker is not None:
        try:
            # Own a validated snapshot: caller mutation cannot rebind a frozen run.
            reranker = LocalReranker(
                RerankerManifest.model_validate_json(reranker.manifest.model_dump_json())
            )
        except (ValueError, TypeError):
            raise WorkbenchError("QUALITY_CONFIGURATION_INVALID") from None
    if reranker is not None and (
        any(len(d.text) > RERANKER_POLICY["max_document_characters"] for d in suite.corpus)
        or any(
            not q.text.strip() or len(q.text) > RERANKER_POLICY["max_query_characters"]
            for q in suite.queries
        )
    ):
        raise WorkbenchError("QUALITY_RERANK_INPUT_INVALID")
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
        "software_versions": _versions(("numpy",) if reranker is not None else ()),
        "max_documents": MAX_DOCUMENTS,
        "max_queries": MAX_QUERIES,
        "native_call_timeout_seconds": 45,
        "deadline_policy": "check-before-call-no-interrupt",
        "semantic_acceptance": "not_established_by_public_diagnostic",
    }
    if reranker is not None:
        # Preserve the existing v1 protocol when no reranker is selected.
        protocol.update(
            {
                "format": 2,
                "reranker_policy": dict(RERANKER_POLICY),
                "reranker_identity": reranker.manifest.identity(),
                "reranker_threads": reranker.manifest.threads,
            }
        )
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
        if reranker is not None:
            progress["completed_reranker_queries"] = 0

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
            if reranker is not None:
                rerank_started = time.monotonic()
                progress["phase"] = "reranker_queries"
                candidates = [
                    {"document_id": d.document_id, "excerpt": d.text}
                    for d in sorted(suite.corpus, key=lambda d: d.document_id)
                ]
                expected_ids = {d.document_id for d in suite.corpus}
                rankings, scores = [], []
                for ordinal, query in enumerate(suite.queries):
                    check_budget()
                    query_started = time.monotonic()
                    scored = _rerank_scores(reranker.rank(query.text, candidates), expected_ids)
                    observation = {
                        "protocol_sha256": protocol_sha,
                        "query_id": query.query_id,
                        "scores": scored,
                        "elapsed_seconds": time.monotonic() - query_started,
                    }
                    _write(directory_fd, f"reranker-query-{ordinal:03d}.json", observation)
                    scores.append(observation)
                    rankings.append(
                        {
                            "query_id": query.query_id,
                            "abstained": False,
                            "document_ids": [
                                identifier for identifier, _ in scored[: suite.cutoff]
                            ],
                        }
                    )
                    progress["completed_reranker_queries"] += 1
                progress["phase"] = "reranker_receipts"
                persist(
                    "reranker",
                    _sha(
                        {
                            "model_identity": protocol["reranker_identity"],
                            "ranking_policy": protocol["reranker_policy"],
                        }
                    ),
                    rankings,
                    scores,
                    time.monotonic() - rerank_started,
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
