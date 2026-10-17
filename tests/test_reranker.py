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
