import pytest

from osint_workbench.errors import WorkbenchError


def test_actual_onnx_pair_scores_and_no_truncation(reranker_bundle):
    rows = [
        {"document_id": "b" * 64, "excerpt": "vulnerability patch"},
        {"document_id": "a" * 64, "excerpt": "storage disk"},
    ]
    result = reranker_bundle.rank("patch", rows)
    assert [r["document_id"] for r in result] == ["a" * 64, "b" * 64]
    assert [r["rerank_score"] for r in result] == [2.0, -2.0]
    with pytest.raises(WorkbenchError, match="INPUT_TOO_LONG"):
        reranker_bundle.rank("patch", [{"document_id": "c" * 64, "excerpt": "storage " * 100}])


def test_rank_uses_one_validated_manifest_across_admission(reranker_bundle, monkeypatch):
    import json
    from contextlib import contextmanager

    from osint_workbench import local_reranker

    admission = local_reranker.admission
    run = local_reranker.subprocess.run

    @contextmanager
    def change_caller():
        with admission():
            reranker_bundle.manifest.threads = 2
            reranker_bundle.manifest.output_name = "changed_after_packet"
            yield

    def dispatch(*args, **kwargs):
        packet = json.loads(kwargs["input"])
        assert kwargs["env"]["OMP_NUM_THREADS"] == str(packet["manifest"]["threads"])
        return run(*args, **kwargs)

    monkeypatch.setattr(local_reranker, "admission", change_caller)
    monkeypatch.setattr(local_reranker.subprocess, "run", dispatch)
    rows = [{"document_id": "a" * 64, "excerpt": "storage disk"}]
    assert reranker_bundle.rank("patch", rows)[0]["rerank_score"] == 2.0
    assert reranker_bundle.manifest.output_name == "changed_after_packet"


def test_invalid_manifest_is_refused_before_admission(reranker_bundle, monkeypatch):
    from osint_workbench import local_reranker

    def unexpected_admission():
        pytest.fail("invalid configuration reached admission")

    monkeypatch.setattr(local_reranker, "admission", unexpected_admission)
    reranker_bundle.manifest = reranker_bundle.manifest.model_copy(update={"threads": 0})
    with pytest.raises(WorkbenchError, match="^RERANK_CONFIGURATION_INVALID$"):
        reranker_bundle.rank("patch", [{"document_id": "a" * 64, "excerpt": "storage disk"}])
