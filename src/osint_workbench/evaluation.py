"""Bounded, offline ranking replay. Scorer success is not semantic acceptance.

Recall@k counts positive judged documents recovered / all positive judgments.
MRR@k is reciprocal rank of the first positive hit (zero when absent).
nDCG@k uses gain 2**grade-1 and log2(rank+1), with ideal order over the
complete judged corpus. Macro means exclude unanswerable queries; those have a
separate explicit-abstention rate. Returning no hits without abstaining is failure.
"""

import hashlib
import json
import math
import unicodedata
from typing import Annotated, Literal

from pydantic import ConfigDict, Field, ValidationError, model_validator

from .contracts import Digest, Identifier, StrictModel
from .errors import WorkbenchError

MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_JUDGMENTS = 20_000
SCORER_VERSION = "ranking-replay-v1"
Grade = Annotated[int, Field(ge=0, le=3)]
UnitInterval = Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]


class FrozenModel(StrictModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class CorpusDocument(FrozenModel):
    document_id: Identifier
    text: str = Field(min_length=1, max_length=100_000, repr=False)


class Judgment(FrozenModel):
    document_id: Identifier
    grade: Grade


class Query(FrozenModel):
    query_id: Identifier
    split: Literal["development", "held_out"]
    leakage_group: Identifier
    text: str = Field(min_length=1, max_length=4096, repr=False)
    answerable: bool
    judgments: tuple[Judgment, ...] = Field(min_length=1, max_length=200)


class Targets(FrozenModel):
    recall_at_k: UnitInterval
    mrr_at_k: UnitInterval
    ndcg_at_k: UnitInterval
    unanswerable_abstention_rate: UnitInterval


class Suite(FrozenModel):
    format: Literal[1]
    suite_id: Identifier
    label_origin: Literal["synthetic", "independently_labelled"]
    label_protocol: str = Field(min_length=1, max_length=2000)
    cutoff: int = Field(ge=1, le=100)
    targets: Targets
    corpus: tuple[CorpusDocument, ...] = Field(min_length=1, max_length=200)
    queries: tuple[Query, ...] = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def complete_judgments_and_disjoint_queries(self):
        document_ids = {d.document_id for d in self.corpus}
        if len(document_ids) != len(self.corpus):
            raise ValueError("duplicate corpus identifier")
        if len({q.query_id for q in self.queries}) != len(self.queries):
            raise ValueError("duplicate query identifier")
        if sum(len(q.judgments) for q in self.queries) > MAX_JUDGMENTS:
            raise ValueError("judgment budget exceeded")
        groups = {}
        texts = {}
        for query in self.queries:
            judged = {j.document_id for j in query.judgments}
            if judged != document_ids or len(judged) != len(query.judgments):
                raise ValueError("complete unique corpus judgments required")
            if query.answerable != any(j.grade > 0 for j in query.judgments):
                raise ValueError("answerability disagrees with judgments")
            normalized = " ".join(unicodedata.normalize("NFKC", query.text).casefold().split())
            if not normalized:
                raise ValueError("empty normalized query")
            for mapping, key in ((groups, query.leakage_group), (texts, normalized)):
                if key in mapping and mapping[key] != query.split:
                    raise ValueError("cross-split leakage")
                mapping[key] = query.split
        return self


class Ranking(FrozenModel):
    query_id: Identifier
    abstained: bool
    document_ids: tuple[Identifier, ...] = Field(max_length=100)

    @model_validator(mode="after")
    def unique_ranking(self):
        if len(set(self.document_ids)) != len(self.document_ids):
            raise ValueError("duplicate ranking identifier")
        if self.abstained and self.document_ids:
            raise ValueError("abstention cannot return documents")
        return self


class Predictions(FrozenModel):
    format: Literal[1]
    suite_sha256: Digest
    system_id: Identifier
    system_manifest_sha256: Digest
    rankings: tuple[Ranking, ...] = Field(min_length=1, max_length=500)


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def digest(model: FrozenModel) -> str:
    """SHA256 of canonical validated JSON, independent of input whitespace/key order."""
    return hashlib.sha256(_canonical(model.model_dump(mode="json"))).hexdigest()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _constant(_value):
    raise ValueError("nonfinite JSON number")


def _parse(data: bytes, model):
    if not isinstance(data, bytes) or len(data) > MAX_INPUT_BYTES:
        raise WorkbenchError("EVALUATION_INPUT_INVALID")
    try:
        value = json.loads(data, object_pairs_hook=_pairs, parse_constant=_constant)
        return model.model_validate_json(_canonical(value))
    except (ValueError, TypeError, RecursionError, ValidationError, UnicodeError):
        raise WorkbenchError("EVALUATION_INPUT_INVALID") from None


def parse_suite(data: bytes) -> Suite:
    return _parse(data, Suite)


def parse_predictions(data: bytes) -> Predictions:
    return _parse(data, Predictions)


def _mean(values):
    return math.fsum(values) / len(values) if values else None


def evaluate(suite: Suite, predictions: Predictions) -> dict:
    """Evaluate an exact, suite-bound replay; perform no IO or model execution.

    Manifest digests identify operator-supplied model/config provenance; this
    evaluator does not independently attest their contents or detect paraphrases.
    Targets are hashed with the suite, never inferred from observed rankings.
    """
    if predictions.suite_sha256 != digest(suite):
        raise WorkbenchError("EVALUATION_SUITE_MISMATCH")
    rankings = {r.query_id: r for r in predictions.rankings}
    if len(rankings) != len(predictions.rankings) or set(rankings) != {
        q.query_id for q in suite.queries
    }:
        raise WorkbenchError("EVALUATION_QUERY_MISMATCH")
    corpus_ids = {d.document_id for d in suite.corpus}
    results = []
    for query in suite.queries:
        ranking = rankings[query.query_id]
        if not set(ranking.document_ids) <= corpus_ids:
            raise WorkbenchError("EVALUATION_UNKNOWN_DOCUMENT")
        grades = {j.document_id: j.grade for j in query.judgments}
        hits = ranking.document_ids[: suite.cutoff]
        recall = mrr = ndcg = None
        if query.answerable:
            positives = sum(g > 0 for g in grades.values())
            recall = sum(grades[d] > 0 for d in hits) / positives
            mrr = next((1 / rank for rank, d in enumerate(hits, 1) if grades[d] > 0), 0.0)
            dcg = math.fsum(
                (2 ** grades[d] - 1) / math.log2(rank + 1) for rank, d in enumerate(hits, 1)
            )
            ideal = sorted(grades.values(), reverse=True)[: suite.cutoff]
            idcg = math.fsum(
                (2**grade - 1) / math.log2(rank + 1) for rank, grade in enumerate(ideal, 1)
            )
            ndcg = dcg / idcg
        results.append(
            {
                "query_id": query.query_id,
                "split": query.split,
                "answerable": query.answerable,
                "recall_at_k": recall,
                "mrr_at_k": mrr,
                "ndcg_at_k": ndcg,
                "correct_abstention": None if query.answerable else ranking.abstained,
            }
        )
    summaries = {}
    for split in ("development", "held_out"):
        rows = [r for r in results if r["split"] == split]
        answerable = [r for r in rows if r["answerable"]]
        unanswerable = [r for r in rows if not r["answerable"]]
        metrics = {
            name: _mean([r[name] for r in answerable])
            for name in ("recall_at_k", "mrr_at_k", "ndcg_at_k")
        }
        metrics["unanswerable_abstention_rate"] = _mean(
            [int(r["correct_abstention"]) for r in unanswerable]
        )
        gates = {
            name: None if value is None else value >= getattr(suite.targets, name)
            for name, value in metrics.items()
        }
        summaries[split] = {
            "answerable_queries": len(answerable),
            "unanswerable_queries": len(unanswerable),
            "metrics": metrics,
            "gates": gates,
            "all_targets_met": all(v is True for v in gates.values()),
        }
    receipt = {
        "format": 1,
        "kind": "offline_ranking_evaluation",
        "scorer": SCORER_VERSION,
        "suite_sha256": digest(suite),
        "predictions_sha256": digest(predictions),
        "system_id": predictions.system_id,
        "system_manifest_sha256": predictions.system_manifest_sha256,
        "label_origin": suite.label_origin,
        "cutoff": suite.cutoff,
        "semantic_acceptance": "not_established_by_ranking_replay",
        "splits": summaries,
        "queries": results,
    }
    return {"payload": receipt, "sha256": hashlib.sha256(_canonical(receipt)).hexdigest()}


def compare(suite_data: bytes, baseline_data: bytes, candidate_data: bytes) -> dict:
    """Describe paired changes from bounded serialized JSON; never adopt a model.

    Accept bytes only: do not serialize caller-owned constructed Python models.
    Pair by query identity, never prediction order. No population uncertainty
    estimate is inferred from these fixed cases.
    """
    suite = parse_suite(suite_data)
    baseline = parse_predictions(baseline_data)
    candidate = parse_predictions(candidate_data)
    receipts = {"baseline": evaluate(suite, baseline), "candidate": evaluate(suite, candidate)}
    rows = {
        side: {row["query_id"]: row for row in receipt["payload"]["queries"]}
        for side, receipt in receipts.items()
    }
    metrics = ("recall_at_k", "mrr_at_k", "ndcg_at_k", "unanswerable_abstention_rate")
    queries = []
    for query in suite.queries:
        changes = {}
        for metric in metrics:
            field = "correct_abstention" if metric == "unanswerable_abstention_rate" else metric
            before = rows["baseline"][query.query_id][field]
            after = rows["candidate"][query.query_id][field]
            changes[metric] = {
                "baseline": before,
                "candidate": after,
                "delta": None if before is None or after is None else float(after) - float(before),
            }
        queries.append(
            {
                "query_id": query.query_id,
                "split": query.split,
                "answerable": query.answerable,
                "metrics": changes,
            }
        )
    splits = {}
    for split in ("development", "held_out"):
        summaries = {
            side: receipt["payload"]["splits"][split] for side, receipt in receipts.items()
        }
        deltas, paired = {}, {}
        for metric in metrics:
            before = summaries["baseline"]["metrics"][metric]
            after = summaries["candidate"]["metrics"][metric]
            deltas[metric] = None if before is None or after is None else after - before
            values = [
                row["metrics"][metric]["delta"]
                for row in queries
                if row["split"] == split and row["metrics"][metric]["delta"] is not None
            ]
            paired[metric] = {
                "improved": sum(value > 0 for value in values),
                "regressed": sum(value < 0 for value in values),
                "unchanged": sum(value == 0 for value in values),
                "count": len(values),
            }
        splits[split] = {**summaries, "candidate_minus_baseline": deltas, "paired_counts": paired}
    payload = {
        "format": 1,
        "kind": "paired_ranking_comparison",
        "comparison_policy": "paired-ranking-replay-v1",
        "scorer": SCORER_VERSION,
        "suite_sha256": digest(suite),
        "label_origin": suite.label_origin,
        "cutoff": suite.cutoff,
        "systems": {
            side: {
                "system_id": receipt["payload"]["system_id"],
                "system_manifest_sha256": receipt["payload"]["system_manifest_sha256"],
                "predictions_sha256": receipt["payload"]["predictions_sha256"],
                "evaluation_sha256": receipt["sha256"],
            }
            for side, receipt in receipts.items()
        },
        "semantic_acceptance": "not_established_by_paired_replay",
        "uncertainty": "not_estimated_fixed_suite_description_only",
        "splits": splits,
        "queries": queries,
    }
    return {"payload": payload, "sha256": hashlib.sha256(_canonical(payload)).hexdigest()}
