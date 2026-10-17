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
