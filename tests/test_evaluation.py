import hashlib
import json
import math

import pytest

from osint_workbench.errors import WorkbenchError
from osint_workbench.evaluation import digest, evaluate, parse_predictions, parse_suite


def suite_input():
    corpus = [{"document_id": f"doc{i}", "text": f"Synthetic passage {i}."} for i in range(3)]
    queries = []
    for split in ("development", "held_out"):
        for answerable in (True, False):
            identity = f"{split}_{answerable}"
            queries.append(
                {
                    "query_id": identity,
                    "split": split,
                    "leakage_group": identity,
                    "text": f"Synthetic question {identity}",
                    "answerable": answerable,
                    "judgments": [
                        {"document_id": f"doc{i}", "grade": [3, 1, 0][i] if answerable else 0}
                        for i in range(3)
                    ],
                }
            )
    return {
        "format": 1,
        "suite_id": "synthetic_scoring",
        "label_origin": "synthetic",
        "label_protocol": "Authored scorer oracle; not a pretrained quality benchmark.",
        "cutoff": 2,
        "targets": {
            "recall_at_k": 0.5,
            "mrr_at_k": 0.5,
            "ndcg_at_k": 0.5,
            "unanswerable_abstention_rate": 1.0,
        },
        "corpus": corpus,
        "queries": queries,
    }


def load(value):
    return parse_suite(json.dumps(value).encode())


def predictions(suite, answerable_ids=("doc2", "doc1"), abstain=True):
    return parse_predictions(
        json.dumps(
            {
                "format": 1,
                "suite_sha256": digest(suite),
                "system_id": "synthetic",
                "system_manifest_sha256": "0" * 64,
                "rankings": [
                    {
                        "query_id": q.query_id,
                        "abstained": not q.answerable and abstain,
                        "document_ids": list(answerable_ids) if q.answerable else [],
                    }
                    for q in suite.queries
                ],
            }
        ).encode()
    )


def test_independent_graded_oracle_and_hashes():
    suite = load(suite_input())
    replay = predictions(suite)
    receipt = evaluate(suite, replay)
    metrics = receipt["payload"]["splits"]["held_out"]["metrics"]
    assert metrics["recall_at_k"] == 0.5
    assert metrics["mrr_at_k"] == 0.5
    assert metrics["ndcg_at_k"] == pytest.approx((1 / math.log2(3)) / (7 + 1 / math.log2(3)))
    assert metrics["unanswerable_abstention_rate"] == 1
    assert receipt["payload"]["splits"]["held_out"]["all_targets_met"] is False
    encoded = json.dumps(
        receipt["payload"],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()
    assert receipt["sha256"] == hashlib.sha256(encoded).hexdigest()
    assert receipt == evaluate(suite, replay)
    assert digest(parse_suite(json.dumps(suite_input(), indent=2).encode())) == digest(suite)


def test_perfect_rankings_empty_result_not_implicit_abstention_and_missing_population():
    suite = load(suite_input())
    perfect = evaluate(suite, predictions(suite, ("doc0", "doc1")))
    assert perfect["payload"]["splits"]["held_out"]["all_targets_met"] is True
    empty = evaluate(suite, predictions(suite, (), False))
    metrics = empty["payload"]["splits"]["held_out"]["metrics"]
    assert list(metrics.values()) == [0, 0, 0, 0]
    value = suite_input()
    value["queries"] = value["queries"][:1]
    suite = load(value)
    result = evaluate(suite, predictions(suite))
    held = result["payload"]["splits"]["held_out"]
    assert all(v is None for v in held["metrics"].values())
    assert held["all_targets_met"] is False
    assert (
        result["payload"]["splits"]["development"]["gates"]["unanswerable_abstention_rate"] is None
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda v: v.update(unexpected="ignored"),
        lambda v: v["corpus"].append(v["corpus"][0]),
        lambda v: v["queries"].append(v["queries"][0]),
        lambda v: v["queries"][0]["judgments"].pop(),
        lambda v: v["queries"][0]["judgments"].append(v["queries"][0]["judgments"][0]),
        lambda v: v["queries"][0].update(answerable=False),
        lambda v: v["queries"][2].update(leakage_group=v["queries"][0]["leakage_group"]),
        lambda v: v["queries"][2].update(text="  SYNTHETIC QUESTION development_True  "),
        lambda v: v["queries"][0]["judgments"][0].update(grade=True),
        lambda v: v["targets"].update(recall_at_k=float("nan")),
        lambda v: v.update(cutoff=101),
    ],
)
def test_contract_rejects_ambiguous_or_leaking_cases(mutation):
    value = suite_input()
    mutation(value)
    with pytest.raises(WorkbenchError, match="EVALUATION_INPUT_INVALID"):
        load(value)


@pytest.mark.parametrize(
    "data",
    [
        b'{"format":1,"format":1}',
        b'{"x":NaN}',
        b'{"x":1e999}',
        b"\xff",
        b"[" * 2000,
        b" " * (8 * 1024 * 1024 + 1),
    ],
)
def test_bounded_json_rejects_duplicates_nonfinite_and_depth(data):
    with pytest.raises(WorkbenchError, match="EVALUATION_INPUT_INVALID"):
        parse_suite(data)


@pytest.mark.parametrize(
    "mutation,code",
    [
        (lambda v: v.update(suite_sha256="f" * 64), "EVALUATION_SUITE_MISMATCH"),
        (lambda v: v["rankings"].pop(), "EVALUATION_QUERY_MISMATCH"),
        (lambda v: v["rankings"].append(v["rankings"][0]), "EVALUATION_QUERY_MISMATCH"),
        (
            lambda v: v["rankings"][0].update(document_ids=["unknown"]),
            "EVALUATION_UNKNOWN_DOCUMENT",
        ),
    ],
)
def test_hash_and_prediction_coverage_required(mutation, code):
    suite = load(suite_input())
    value = predictions(suite).model_dump(mode="json")
    mutation(value)
    replay = parse_predictions(json.dumps(value).encode())
    with pytest.raises(WorkbenchError, match=code):
        evaluate(suite, replay)


@pytest.mark.parametrize(
    "change",
    [
        {"document_ids": ["doc0", "doc0"]},
        {"abstained": True, "document_ids": ["doc0"]},
        {"score": float("inf")},
    ],
)
def test_invalid_ranking_rejected(change):
    suite = load(suite_input())
    value = predictions(suite).model_dump(mode="json")
    value["rankings"][0].update(change)
    with pytest.raises(WorkbenchError, match="EVALUATION_INPUT_INVALID"):
        parse_predictions(json.dumps(value).encode())


def test_bounds_are_semantic_not_only_byte_count():
    value = suite_input()
    value["corpus"] = [{"document_id": f"d{i}", "text": "Synthetic"} for i in range(200)]
    value["queries"] = [
        {
            "query_id": f"q{i}",
            "split": "held_out",
            "leakage_group": f"g{i}",
            "text": f"Question {i}",
            "answerable": True,
            "judgments": [{"document_id": f"d{j}", "grade": 1} for j in range(200)],
        }
        for i in range(101)
    ]
    with pytest.raises(WorkbenchError, match="EVALUATION_INPUT_INVALID"):
        load(value)
