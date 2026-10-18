"""Real ONNX execution with a synthetic mathematical oracle, not semantic quality evidence."""

import json

import pytest

from osint_workbench.errors import WorkbenchError
from osint_workbench.local_encoder import EncoderManifest
from osint_workbench.text import digest


def test_actual_cpu_onnx_vectors_and_unicode_token_chunks(encoder_bundle):
    encoder = encoder_bundle
    assert encoder.query("storage disk") == [1.0, 0.0, 0.0]
    assert encoder.query("vulnerability patch") == [0.0, 1.0, 0.0]
    assert encoder.query("Straße") == [0.0, 0.0, 1.0]
    text = "  Straße storage disk " * 30
    chunks = encoder.chunks(text)
    assert len(chunks) > 1 and chunks[0]["start"] == 0 and chunks[-1]["end"] == len(text)
    for i, part in enumerate(chunks):
        assert digest(text[part["start"] : part["end"]].encode()) == part["sha256"]
        if i:
            assert part["start"] <= chunks[i - 1]["end"]
        encoder.manifest.space.validate_vector(part["vector"])


def test_model_tamper_and_no_silent_truncation(encoder_bundle):
    encoder = encoder_bundle
    with pytest.raises(WorkbenchError, match="INPUT_TOO_LONG"):
        encoder.query("storage " * 100)
    with pytest.raises(WorkbenchError, match="EMBEDDING_NORM"):
        encoder.query("unrecognized")
    from pathlib import Path

    Path(encoder.manifest.model_path).write_bytes(b"tampered")
    with pytest.raises(WorkbenchError, match="MODEL_INTEGRITY_MISMATCH"):
        encoder.query("storage")


def test_bundle_identity_is_path_independent_and_parameter_sensitive(encoder_bundle):
    m = encoder_bundle.manifest
    assert m.identity() == m.model_copy(update={"model_path": "/synthetic/other"}).identity()
    assert m.identity() != m.model_copy(update={"max_tokens": 32}).identity()
    values = m.model_dump()
    values["space"]["tokenizer_revision"] = "wrong-revision"
    with pytest.raises(ValueError):
        EncoderManifest.model_validate_json(json.dumps(values))


def test_shared_admission_refuses_overlap_and_recovers(encoder_bundle, tmp_path, monkeypatch):
    import fcntl
    import os

    path = tmp_path / "admission.lock"
    monkeypatch.setenv("OW_INFERENCE_LOCK", str(path))
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(WorkbenchError, match="INFERENCE_BUSY"):
            encoder_bundle.query("storage")
    finally:
        os.close(fd)
    assert encoder_bundle.query("storage") == [1.0, 0.0, 0.0]


def _variant(encoder_bundle, tmp_path, weights):
    """Rebuild the synthetic oracle with altered weights; same tokenizer and graph."""
    import numpy as np
    from onnx import TensorProto, helper, numpy_helper

    from osint_workbench.local_encoder import LocalEncoder

    graph = helper.make_graph(
        [helper.make_node("Gather", ["weights", "input_ids"], ["tokens"], axis=0)],
        "synthetic-variant",
        [helper.make_tensor_value_info("input_ids", TensorProto.INT64, [1, "sequence"])],
        [helper.make_tensor_value_info("tokens", TensorProto.FLOAT, [1, "sequence", 3])],
        [numpy_helper.from_array(np.asarray(weights, dtype=np.float32), "weights")],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 17)], ir_version=10)
    data = model.SerializeToString()
    path = tmp_path / "variant.onnx"
    path.write_bytes(data)
    manifest = encoder_bundle.manifest
    space = manifest.space.model_copy(update={"model_revision": digest(data)})
    return LocalEncoder(
        manifest.model_copy(
            update={"model_path": str(path), "model_sha256": digest(data), "space": space}
        )
    )


def test_non_finite_model_output_is_a_runtime_fault_not_a_content_refusal(encoder_bundle, tmp_path):
    inf = float("inf")
    weights = [
        [0, 0, 0],
        [0, 0, 0],
        [0, 0, 0],
        [1, 0, 0],
        [1, 0, 0],
        [0, 1, 0],
        [inf, 0, 0],
        [0, 0, 1],
    ]
    encoder = _variant(encoder_bundle, tmp_path, weights)
    with pytest.raises(WorkbenchError, match="^INVALID_EMBEDDING_VECTOR$"):
        encoder.query("patch")
    # A finite zero vector from unknown-only content stays a content refusal.
    with pytest.raises(WorkbenchError, match="^INVALID_EMBEDDING_NORM$"):
        encoder.query("unrecognized")


def test_manifest_without_chunk_budget_is_incompatible(encoder_bundle):
    from osint_workbench.local_encoder import LocalEncoder

    # Template overhead, not document content, leaves no room for a chunk.
    base = encoder_bundle.manifest
    space = base.space.model_copy(update={"document_template": "{text} storage disk patch storage"})
    manifest = base.model_copy(update={"overlap_tokens": 7, "space": space})
    with pytest.raises(WorkbenchError, match="^ENCODER_INCOMPATIBLE$"):
        LocalEncoder(manifest).chunks("storage disk")
