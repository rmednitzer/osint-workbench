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


def compare_models(suite, baseline, candidate):
    from osint_workbench.evaluation import compare

    return compare(*(value.model_dump_json().encode() for value in (suite, baseline, candidate)))


def test_paired_comparison_uses_query_identity_and_independent_deltas():
    suite = load(suite_input())
    baseline = predictions(suite, abstain=False)
    candidate = predictions(suite, ("doc0", "doc1"))
    candidate = candidate.model_copy(update={"rankings": tuple(reversed(candidate.rankings))})
    receipt = compare_models(suite, baseline, candidate)
    payload = receipt["payload"]
    expected_ndcg = (1 / math.log2(3)) / (7 + 1 / math.log2(3))
    for split in ("development", "held_out"):
        summary = payload["splits"][split]
        assert summary["candidate_minus_baseline"] == pytest.approx(
            {
                "recall_at_k": 0.5,
                "mrr_at_k": 0.5,
                "ndcg_at_k": 1 - expected_ndcg,
                "unanswerable_abstention_rate": 1,
            }
        )
        assert all(
            counts == {"improved": 1, "regressed": 0, "unchanged": 0, "count": 1}
            for counts in summary["paired_counts"].values()
        )
    reverse = compare_models(suite, candidate, baseline)["payload"]
    assert reverse["splits"]["held_out"]["candidate_minus_baseline"]["recall_at_k"] == -0.5
    assert reverse["splits"]["held_out"]["paired_counts"]["recall_at_k"]["regressed"] == 1
    assert (
        payload["systems"]["baseline"]["evaluation_sha256"] == evaluate(suite, baseline)["sha256"]
    )
    assert payload["systems"]["candidate"]["predictions_sha256"] == digest(candidate)
    assert "not_established" in payload["semantic_acceptance"]
    assert (
        receipt["sha256"]
        == hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest()
    )


def test_paired_ties_and_missing_populations_do_not_become_improvements():
    value = suite_input()
    value["queries"] = value["queries"][:1]
    suite = load(value)
    replay = predictions(suite)
    result = compare_models(suite, replay, replay)["payload"]
    dev = result["splits"]["development"]
    assert dev["paired_counts"]["recall_at_k"] == {
        "improved": 0,
        "regressed": 0,
        "unchanged": 1,
        "count": 1,
    }
    assert dev["candidate_minus_baseline"]["unanswerable_abstention_rate"] is None
    held = result["splits"]["held_out"]
    assert set(held["candidate_minus_baseline"].values()) == {None}
    assert all(counts["count"] == 0 for counts in held["paired_counts"].values())
    assert held["candidate"]["all_targets_met"] is False


@pytest.mark.parametrize("side", ["baseline", "candidate"])
def test_paired_comparison_refuses_mismatched_suite_on_either_side(side):
    suite = load(suite_input())
    valid = predictions(suite)
    invalid = valid.model_copy(update={"suite_sha256": "f" * 64})
    with pytest.raises(WorkbenchError, match="EVALUATION_SUITE_MISMATCH"):
        compare_models(
            suite, **{side: invalid, "candidate" if side == "baseline" else "baseline": valid}
        )


def test_paired_cli_is_offline_and_never_overwrites_output(tmp_path):
    import os
    import subprocess
    import sys

    suite = load(suite_input())
    suite_file = tmp_path / "suite.json"
    prediction_file = tmp_path / "predictions.json"
    output = tmp_path / "comparison.json"
    suite_file.write_text(suite.model_dump_json())
    prediction_file.write_text(predictions(suite).model_dump_json())
    fifo = tmp_path / "private-canary"
    os.mkfifo(fifo)
    env = dict(os.environ, OW_READER_DSN="invalid", OW_ENCODER_MANIFEST=str(fifo))
    command = [
        sys.executable,
        "-m",
        "osint_workbench.cli",
        "evaluate",
        "compare",
        "--suite",
        str(suite_file),
        "--baseline",
        str(prediction_file),
        "--candidate",
        str(prediction_file),
        "--file",
        str(output),
    ]
    result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0 and result.stderr == ""
    original = output.read_bytes()
    receipt = json.loads(original)
    assert receipt["payload"]["splits"]["held_out"]["candidate"]["all_targets_met"] is False
    assert output.stat().st_mode & 0o777 == 0o600
    assert "private-canary" not in result.stdout and str(tmp_path) not in result.stdout
    again = subprocess.run(command, env=env, capture_output=True, text=True, timeout=15)
    assert again.returncode == 1 and output.read_bytes() == original


@pytest.mark.parametrize("side", range(3))
def test_paired_api_rejects_model_objects_without_serializing_them(side, monkeypatch):
    from osint_workbench.evaluation import compare

    suite = load(suite_input())
    valid = predictions(suite)
    models = (suite, valid, valid)
    values = [value.model_dump_json().encode() for value in models]
    # Undeclared attributes must not disappear through schema serialization.
    values[side] = models[side].model_copy(update={"unexpected": object()})

    def forbidden(*args, **kwargs):
        raise AssertionError("caller-owned model must not be serialized")

    monkeypatch.setattr(type(models[side]), "model_dump_json", forbidden)
    with pytest.raises(WorkbenchError, match="^EVALUATION_INPUT_INVALID$"):
        compare(*values)


@pytest.mark.parametrize("side", range(3))
def test_paired_api_rejects_oversized_bytes_on_either_prediction_or_suite(side):
    from osint_workbench.evaluation import MAX_INPUT_BYTES, compare

    suite = load(suite_input())
    valid = predictions(suite)
    values = [value.model_dump_json().encode() for value in (suite, valid, valid)]
    values[side] = b" " * (MAX_INPUT_BYTES + 1)
    with pytest.raises(WorkbenchError, match="^EVALUATION_INPUT_INVALID$"):
        compare(*values)


def test_paired_api_refuses_undeclared_nested_wire_fields():
    from osint_workbench.evaluation import compare

    suite = load(suite_input())
    valid = predictions(suite)
    value = valid.model_dump(mode="json")
    value["rankings"][0]["unexpected"] = "private-canary"
    with pytest.raises(WorkbenchError, match="^EVALUATION_INPUT_INVALID$"):
        compare(
            suite.model_dump_json().encode(),
            valid.model_dump_json().encode(),
            json.dumps(value).encode(),
        )
