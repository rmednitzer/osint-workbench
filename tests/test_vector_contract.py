import pytest

from osint_workbench.errors import WorkbenchError
from osint_workbench.vector_index import VectorIndex


def test_caller_template_mutation_cannot_rebind_index_native_vectors(
    encoder_bundle, tmp_path, monkeypatch
):
    monkeypatch.setenv("OW_INFERENCE_LOCK", str(tmp_path / "admission.lock"))
    index = VectorIndex(None, encoder_bundle)
    original = index.encoder.chunks("storage disk")[0]["vector"]
    encoder_bundle.manifest.space.document_template = "patch {text}"
    changed = index.encoder.chunks("storage disk")[0]["vector"]
    assert index.space_id == index.encoder.manifest.identity()
    assert changed == pytest.approx(original)


def test_index_rejects_invalid_nested_encoder_before_database_work(encoder_bundle):
    encoder_bundle.manifest = encoder_bundle.manifest.model_copy(
        update={"space": encoder_bundle.manifest.space.model_copy(update={"dimensions": 0})}
    )
    # No database is supplied: configuration refusal must precede any SQL work.
    with pytest.raises(WorkbenchError, match="^RETRIEVAL_CONFIGURATION_INVALID$"):
        VectorIndex(None, encoder_bundle)
