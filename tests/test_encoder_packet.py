"""Actual isolated encoder-child packet handling, without pretrained artifacts."""

import json
import os
import subprocess
import sys

import pytest

from osint_workbench.errors import WorkbenchError
from osint_workbench.local_encoder import MAX_INPUT, MAX_PACKET_BYTES, EncoderManifest, LocalEncoder


def invoke_child(packet):
    result = subprocess.run(
        [sys.executable, "-I", "-m", "osint_workbench.encoder_process"],
        input=packet,
        capture_output=True,
        timeout=10,
        check=False,
        env={
            "PYTHONIOENCODING": "utf-8",
            "OMP_NUM_THREADS": "1",
            "OPENBLAS_NUM_THREADS": "1",
            "MKL_NUM_THREADS": "1",
            "TOKENIZERS_PARALLELISM": "false",
            "OW_INFERENCE_PARENT": str(os.getpid()),
        },
    )
    assert len(result.stdout) < 16384 and result.stderr == b""
    return result.returncode, json.loads(result.stdout)


def packet(manifest, text="storage", operation="query"):
    return json.dumps(
        {"manifest": manifest.model_dump(), "text": text, "operation": operation},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def mismatched_model(encoder_bundle):
    values = encoder_bundle.manifest.model_dump()
    values["model_sha256"] = values["space"]["model_revision"] = "f" * 64
    return EncoderManifest.model_validate(values)


def test_maximum_astral_text_reaches_integrity_admission_in_actual_child(encoder_bundle):
    # Under ASCII-escaped JSON this valid codepoint input exceeded the child's
    # old 2MiB read. A deliberately wrong hash proves successful packet parsing
    # without admitting the model session or pretending this is a useful query.
    encoder = LocalEncoder(mismatched_model(encoder_bundle))
    with pytest.raises(WorkbenchError, match="^MODEL_INTEGRITY_MISMATCH$"):
        encoder.query("\U0001f680" * MAX_INPUT)


def test_actual_native_child_accepts_utf8_and_exact_packet_byte_limit(encoder_bundle):
    assert encoder_bundle.query("Straße storage") == pytest.approx([2**-0.5, 0.0, 2**-0.5])
    raw = packet(mismatched_model(encoder_bundle))
    padded = raw + b" " * (MAX_PACKET_BYTES - len(raw))
    assert len(padded) == MAX_PACKET_BYTES
    code, output = invoke_child(padded)
    assert code == 1 and output == {"error": "MODEL_INTEGRITY_MISMATCH"}


def test_child_rejects_oversize_complete_json_without_accepting_its_valid_prefix(encoder_bundle):
    raw = packet(encoder_bundle.manifest)
    oversized = raw + b" " * (MAX_PACKET_BYTES - len(raw) + 1)
    code, output = invoke_child(oversized)
    assert code == 1 and output == {"error": "ENCODER_PACKET_TOO_LARGE"}


@pytest.mark.parametrize(
    "malformed",
    [
        b"",
        b'{"manifest":',
        b"{}",
        b"[]",
        b'{"manifest":{},"text":"storage","operation":"query"}',
        b'{"manifest":{},"manifest":{},"text":"storage","operation":"query"}',
        b'{"manifest":{},"text":"\\ud800","operation":"query"}',
        b'{"manifest":{},"text":"storage","operation":"query","extra":true}',
        b'{"manifest":{},"text":NaN,"operation":"query"}',
        '{"manifest":{},"text":"storage","operation":"query"}'.encode("utf-16"),
    ],
    ids=[
        "empty",
        "truncated",
        "missing",
        "array",
        "manifest",
        "duplicate",
        "surrogate",
        "extra",
        "nonfinite",
        "utf16",
    ],
)
def test_actual_child_rejects_malformed_packet_before_runtime(malformed):
    code, output = invoke_child(malformed)
    assert code == 1 and output == {"error": "INVALID_ENCODER_PACKET"}


@pytest.mark.parametrize(
    ("text", "operation"),
    [(" ", "query"), ("x" * (MAX_INPUT + 1), "query"), ("storage", "unsupported")],
    ids=["blank", "too-many-codepoints", "operation"],
)
def test_actual_child_validates_semantic_input_before_model_admission(
    encoder_bundle, text, operation
):
    code, output = invoke_child(packet(mismatched_model(encoder_bundle), text, operation))
    assert code == 1 and output == {"error": "INVALID_ENCODER_INPUT"}


@pytest.mark.parametrize("fault", ["packet-bytes", "surrogate", "operation"])
def test_parent_refuses_invalid_packet_before_creating_admission_lock(
    encoder_bundle, tmp_path, monkeypatch, fault
):
    lock = tmp_path / "must-not-be-created.lock"
    monkeypatch.setenv("OW_INFERENCE_LOCK", str(lock))
    values = encoder_bundle.manifest.model_dump()
    text, operation = "storage", "query"
    expected = "INVALID_ENCODER_INPUT"
    if fault == "packet-bytes":
        values["model_path"] = "/synthetic/" + "x" * MAX_PACKET_BYTES
        expected = "ENCODER_PACKET_TOO_LARGE"
    elif fault == "surrogate":
        text = "\ud800"
        expected = "INVALID_ENCODER_PACKET"
    else:
        operation = "unsupported"
    encoder = LocalEncoder(EncoderManifest.model_validate(values))
    with pytest.raises(WorkbenchError, match="^" + expected + "$"):
        encoder.invoke(text, operation=operation)
    assert not lock.exists()
