import json
import os
from pathlib import Path

import pytest

from osint_workbench.errors import WorkbenchError
from osint_workbench.evaluation import digest, parse_suite
from osint_workbench.quality import run


def suite():
    corpus = [
        {"document_id": "storage", "text": "storage disk"},
        {"document_id": "security", "text": "vulnerability patch"},
    ]
    queries = []
    for split in ("development", "held_out"):
        for answerable in (True, False):
            identifier = f"{split}_{answerable}"
            text = (
                ("storage" if split == "development" else "disk")
                if answerable
                else ("absent" if split == "development" else "missing")
            )
            queries.append(
                {
                    "query_id": identifier,
                    "text": text,
                    "split": split,
                    "leakage_group": identifier,
                    "answerable": answerable,
                    "judgments": [
                        {
                            "document_id": d["document_id"],
                            "grade": 3 if answerable and d["document_id"] == "storage" else 0,
                        }
                        for d in corpus
                    ],
                }
            )
    return parse_suite(
        json.dumps(
            {
                "format": 1,
                "suite_id": "synthetic",
                "label_origin": "synthetic",
                "label_protocol": "Authored execution oracle only.",
                "cutoff": 1,
                "targets": {
                    "recall_at_k": 1.0,
                    "mrr_at_k": 1.0,
                    "ndcg_at_k": 1.0,
                    "unanswerable_abstention_rate": 1.0,
                },
                "corpus": corpus,
                "queries": queries,
            }
        ).encode()
    )


def read(path, name):
    return json.loads((path / name).read_bytes())


def test_lexical_protocol_receipts_permissions_nooverwrite(tmp_path):
    output = tmp_path / "diagnostic"
    result = run(suite(), output, source_revision="a" * 40)
    assert result["status"] == "completed"
    assert result["all_targets_met"] is True
    assert result["semantic_acceptance"] == "not_established_by_public_diagnostic"
    protocol = read(output, "protocol.json")
    assert protocol["sha256"] == result["protocol_sha256"]
    assert protocol["payload"]["suite_sha256"] == digest(suite())
    assert protocol["payload"]["source_revision"] == "a" * 40
    assert protocol["payload"]["encoder_identity"] is None
    assert protocol["payload"]["format"] == 1
    assert "reranker_identity" not in protocol["payload"]
    assert digest(parse_suite((output / "suite.json").read_bytes())) == digest(suite())
    assert (
        read(output, "lexical-evaluation.json")["sha256"]
        == result["systems"]["lexical"]["receipt_sha256"]
    )
    assert read(output, "completed.json") == result
    assert output.stat().st_mode & 0o777 == 0o700
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in output.iterdir())
    before = {p.name: p.read_bytes() for p in output.iterdir()}
    with pytest.raises(WorkbenchError, match="QUALITY_OUTPUT_EXISTS"):
        run(suite(), output)
    assert before == {p.name: p.read_bytes() for p in output.iterdir()}


def test_lexical_rankings_and_receipts_deterministic_but_timings_observed(tmp_path):
    left, right = tmp_path / "a", tmp_path / "b"
    run(suite(), left)
    run(suite(), right)
    for name in (
        "suite.json",
        "protocol.json",
        "lexical-predictions.json",
        "lexical-evaluation.json",
    ):
        assert (left / name).read_bytes() == (right / name).read_bytes()


@pytest.mark.parametrize(
    "options",
    [
        {"budget_seconds": 0},
        {"budget_seconds": True},
        {"budget_seconds": float("nan")},
        {"budget_seconds": 3601},
        {"source_revision": "private-host.invalid"},
    ],
)
def test_configuration_refused_before_output(tmp_path, options):
    output = tmp_path / "output"
    with pytest.raises(WorkbenchError, match="QUALITY_CONFIGURATION_INVALID"):
        run(suite(), output, **options)
    assert not output.exists()


def test_budget_failure_retains_frozen_protocol_before_calls(tmp_path, monkeypatch):
    output = tmp_path / "output"
    times = iter((0, 0, 2, 2))
    monkeypatch.setattr("osint_workbench.quality.time.monotonic", lambda: next(times))
    outcome = run(suite(), output, budget_seconds=1)
    assert outcome["status"] == "failed"
    assert outcome["error"] == "QUALITY_BUDGET_EXHAUSTED"
    assert read(output, "protocol.json")["payload"]["suite_sha256"] == digest(suite())
    assert read(output, "failed.json") == outcome
    assert not (output / "completed.json").exists()


def test_native_onnx_rank_only_has_no_unvalidated_abstention(encoder_bundle, tmp_path):
    # Unanswerable text must still have nonzero vectors for the numerical fixture.
    value = suite().model_dump(mode="json")
    value["queries"][1]["text"] = "patch"
    value["queries"][3]["text"] = "vulnerability"
    frozen = parse_suite(json.dumps(value).encode())
    output = tmp_path / "native"
    outcome = run(frozen, output, encoder_bundle)
    assert outcome["status"] == "completed"
    assert outcome["systems"]["encoder"]["all_targets_met"] is False
    assert outcome["all_targets_met"] is False
    protocol = read(output, "protocol.json")["payload"]
    assert protocol["encoder_identity"] == encoder_bundle.manifest.identity()
    assert protocol["encoder_policy"]["abstention"] == "none-rank-only"
    predictions = read(output, "encoder-predictions.json")
    assert all(not r["abstained"] for r in predictions["rankings"])
    assert predictions["rankings"][0]["document_ids"] == ["storage"]
    scores = read(output, "encoder-scores.json")["queries"][0]["scores"]
    assert scores == [["storage", pytest.approx(1.0)], ["security", pytest.approx(0.0)]]
    assert len(read(output, "encoder-document-timings.json")["documents"]) == 2


def test_native_integrity_failure_does_not_erase_lexical_results(encoder_bundle, tmp_path):
    Path(encoder_bundle.manifest.model_path).write_bytes(b"synthetic corrupted model")
    output = tmp_path / "failure"
    outcome = run(suite(), output, encoder_bundle)
    assert outcome["status"] == "failed"
    assert outcome["error"] == "MODEL_INTEGRITY_MISMATCH"
    assert "lexical" in outcome["systems"]
    assert (output / "lexical-evaluation.json").exists()
    assert (output / "protocol.json").stat().st_mtime_ns <= (
        output / "failed.json"
    ).stat().st_mtime_ns
    assert str(tmp_path) not in (output / "failed.json").read_text()
    assert not (output / "completed.json").exists()


def test_existing_symlink_is_never_followed(tmp_path):
    victim = tmp_path / "victim"
    victim.mkdir()
    output = tmp_path / "output"
    output.symlink_to(victim, target_is_directory=True)
    with pytest.raises(WorkbenchError, match="QUALITY_OUTPUT_EXISTS"):
        run(suite(), output)
    assert list(victim.iterdir()) == []


def test_os_failure_has_private_safe_receipt(tmp_path, monkeypatch):
    output = tmp_path / "output"

    def fail(_text):
        raise OSError("secret-host.invalid /private/secret")

    monkeypatch.setattr("osint_workbench.quality._tokens", fail)
    result = run(suite(), output)
    assert result["error"] == "QUALITY_EXECUTION_FAILED"
    assert "secret" not in (output / "failed.json").read_text()


def test_no_overwrite_atomic_file_primitive(tmp_path):
    from osint_workbench.quality import _write

    descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        _write(descriptor, "receipt.json", {"first": True})
        with pytest.raises(FileExistsError):
            _write(descriptor, "receipt.json", {"second": True})
    finally:
        os.close(descriptor)
    assert read(tmp_path, "receipt.json") == {"first": True}
    assert list(tmp_path.iterdir()) == [tmp_path / "receipt.json"]


def test_native_input_exceeds_tokens_fails_without_truncation(encoder_bundle, tmp_path):
    value = suite().model_dump(mode="json")
    value["corpus"][0]["text"] = "storage " * 20
    frozen = parse_suite(json.dumps(value).encode())
    output = tmp_path / "too-long"
    outcome = run(frozen, output, encoder_bundle)
    assert outcome["status"] == "failed"
    assert outcome["error"] == "ENCODER_INPUT_TOO_LONG"
    assert read(output, "suite.json")["corpus"][0]["text"] == "storage " * 20
    assert not (output / "encoder-predictions.json").exists()


def test_suite_work_bound_before_creating_outputs(tmp_path):
    value = suite().model_dump(mode="json")
    value["queries"] = [
        {**value["queries"][0], "query_id": f"q{i}", "text": f"disk {i}", "leakage_group": f"g{i}"}
        for i in range(33)
    ]
    frozen = parse_suite(json.dumps(value).encode())
    output = tmp_path / "large"
    with pytest.raises(WorkbenchError, match="QUALITY_CONFIGURATION_INVALID"):
        run(frozen, output)
    assert not output.exists()


def test_later_native_query_failure_preserves_completed_observations(encoder_bundle, tmp_path):
    value = suite().model_dump(mode="json")
    value["queries"][1]["text"] = "storage " * 20
    frozen = parse_suite(json.dumps(value).encode())
    output = tmp_path / "partial-query"
    outcome = run(frozen, output, encoder_bundle)
    assert outcome["status"] == "failed"
    assert outcome["error"] == "ENCODER_INPUT_TOO_LONG"
    assert outcome["progress"] == {
        "phase": "encoder_queries",
        "completed_lexical_queries": 4,
        "completed_encoder_documents": 2,
        "completed_encoder_queries": 1,
    }
    first = read(output, "encoder-query-000.json")
    assert first["query_id"] == frozen.queries[0].query_id
    assert first["protocol_sha256"] == outcome["protocol_sha256"]
    assert first["scores"] == [["storage", pytest.approx(1.0)], ["security", pytest.approx(0.0)]]
    assert first["elapsed_seconds"] >= 0
    assert not (output / "encoder-query-001.json").exists()
    assert read(output, "encoder-document-000.json")["document_id"] == "storage"
    assert read(output, "encoder-document-001.json")["document_id"] == "security"
    assert "vector" not in (output / "encoder-document-000.json").read_text()
    assert read(output, "failed.json")["progress"] == outcome["progress"]
    assert not (output / "encoder-evaluation.json").exists()
    assert not (output / "completed.json").exists()
    assert "encoder" not in outcome["systems"]
    assert "lexical" in outcome["systems"]


def test_installed_reranker_diagnostic_preserves_negative_abstention_gate(
    reranker_bundle, tmp_path
):
    import subprocess
    import sys

    frozen = tmp_path / "suite.json"
    frozen.write_text(suite().model_dump_json())
    manifest = tmp_path / "reranker.json"
    manifest.write_text(reranker_bundle.manifest.model_dump_json())
    output = tmp_path / "rank-only"
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            "osint_workbench.cli",
            "evaluate",
            "local",
            "--suite",
            str(frozen),
            "--output",
            str(output),
            "--reranker-manifest",
            str(manifest),
        ],
        env={
            **{k: v for k, v in os.environ.items() if not k.startswith("OW_")},
            "OW_INFERENCE_LOCK": str(tmp_path / "admission.lock"),
        },
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 2 and result.stderr == ""
    outcome = json.loads(result.stdout)
    assert outcome["status"] == "completed" and not outcome["all_targets_met"]
    assert set(outcome["systems"]) == {"lexical", "reranker"}
    assert outcome["progress"]["completed_reranker_queries"] == 4
    protocol = read(output, "protocol.json")["payload"]
    assert protocol["format"] == 2
    assert protocol["reranker_identity"] == reranker_bundle.manifest.identity()
    assert protocol["reranker_threads"] == reranker_bundle.manifest.threads
    assert protocol["reranker_policy"]["candidates"] == "complete-corpus"
    predictions = read(output, "reranker-predictions.json")
    assert all(
        not r["abstained"] and r["document_ids"] == ["storage"] for r in predictions["rankings"]
    )
    assert read(output, "reranker-query-000.json")["scores"] == [
        ["storage", 2.0],
        ["security", -2.0],
    ]
    assert (
        read(output, "reranker-evaluation.json")["sha256"]
        == outcome["systems"]["reranker"]["receipt_sha256"]
    )
    assert str(tmp_path) not in (output / "protocol.json").read_text()
    assert output.stat().st_mode & 0o777 == 0o700
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in output.iterdir())


@pytest.mark.parametrize("field,text", [("corpus", "x" * 1001), ("queries", "x" * 2001)])
def test_reranker_complete_text_limits_precede_outputs(reranker_bundle, tmp_path, field, text):
    value = suite().model_dump(mode="json")
    value[field][0]["text"] = text
    output = tmp_path / "refused"
    with pytest.raises(WorkbenchError, match="QUALITY_RERANK_INPUT_INVALID"):
        run(parse_suite(json.dumps(value).encode()), output, reranker=reranker_bundle)
    assert not output.exists()


def test_late_reranker_integrity_failure_preserves_other_systems_and_query_journal(
    encoder_bundle, reranker_bundle, tmp_path, monkeypatch
):
    from osint_workbench.local_reranker import LocalReranker

    value = suite().model_dump(mode="json")
    value["queries"][1]["text"] = "patch"
    value["queries"][3]["text"] = "vulnerability"
    frozen = parse_suite(json.dumps(value).encode())
    rank = LocalReranker.rank
    calls = []

    def corrupt_after_first(self, query, candidates):
        result = rank(self, query, candidates)
        calls.append(True)
        Path(self.manifest.model_path).write_bytes(b"synthetic changed model")
        return result

    monkeypatch.setattr(LocalReranker, "rank", corrupt_after_first)
    monkeypatch.setenv("OW_INFERENCE_LOCK", str(tmp_path / "admission.lock"))
    output = tmp_path / "partial-rerank"
    outcome = run(frozen, output, encoder_bundle, reranker=reranker_bundle)
    assert outcome["status"] == "failed" and outcome["error"] == "MODEL_INTEGRITY_MISMATCH"
    assert calls == [True]
    assert set(outcome["systems"]) == {"lexical", "encoder"}
    assert outcome["progress"]["phase"] == "reranker_queries"
    assert outcome["progress"]["completed_reranker_queries"] == 1
    observation = read(output, "reranker-query-000.json")
    assert observation["protocol_sha256"] == outcome["protocol_sha256"]
    assert observation["scores"] == [["storage", 2.0], ["security", -2.0]]
    assert not (output / "reranker-query-001.json").exists()
    assert not (output / "reranker-evaluation.json").exists()
    assert not (output / "completed.json").exists()
    assert str(tmp_path) not in (output / "failed.json").read_text()


def test_reranker_observations_reject_an_unsubmitted_corpus_identity(
    reranker_bundle, tmp_path, monkeypatch
):
    from osint_workbench.local_reranker import LocalReranker

    monkeypatch.setattr(
        LocalReranker,
        "rank",
        lambda *_: [
            {"document_id": "storage", "rerank_score": 1.0},
            {"document_id": "unknown", "rerank_score": 2.0},
        ],
    )
    output = tmp_path / "invalid-correspondence"
    outcome = run(suite(), output, reranker=reranker_bundle)
    assert outcome["error"] == "QUALITY_RERANK_RESULT_INVALID"
    assert outcome["progress"]["completed_reranker_queries"] == 0
    assert not (output / "reranker-query-000.json").exists()
    assert not (output / "reranker-predictions.json").exists()


def test_reranker_protocol_owns_a_snapshot_of_the_caller_manifest(
    reranker_bundle, tmp_path, monkeypatch
):
    from osint_workbench.local_reranker import LocalReranker

    original = reranker_bundle.manifest.identity()
    rank = LocalReranker.rank
    observed = []

    def change_caller(self, query, candidates):
        observed.append(self.manifest.identity())
        result = rank(self, query, candidates)
        reranker_bundle.manifest = reranker_bundle.manifest.model_copy(
            update={"model_sha256": "0" * 64}
        )
        return result

    monkeypatch.setattr(LocalReranker, "rank", change_caller)
    monkeypatch.setenv("OW_INFERENCE_LOCK", str(tmp_path / "admission.lock"))
    output = tmp_path / "bound-manifest"
    outcome = run(suite(), output, reranker=reranker_bundle)
    assert outcome["status"] == "completed"
    assert observed == [original] * 4
    assert read(output, "protocol.json")["payload"]["reranker_identity"] == original
    assert reranker_bundle.manifest.identity() != original
