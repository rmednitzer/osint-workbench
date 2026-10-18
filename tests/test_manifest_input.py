"""Bounded regular manifest files, including the actual installed CLI entry path."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from osint_workbench import cli
from osint_workbench.errors import WorkbenchError
from osint_workbench.local_encoder import EncoderManifest


def test_regular_manifest_load_preserves_identity_without_loading_model(encoder_bundle, tmp_path):
    original = encoder_bundle.manifest
    values = original.model_dump()
    values["model_path"] = "/synthetic/absent/model.onnx"
    manifest = EncoderManifest.model_validate(values)
    path = tmp_path / "regular-manifest.json"
    path.write_text(manifest.model_dump_json())
    loaded = cli._manifest(path, EncoderManifest)
    assert loaded == manifest and loaded.identity() == original.identity()


def test_exact_manifest_byte_limit_is_accepted(encoder_bundle, tmp_path):
    path = tmp_path / "maximum-manifest.json"
    data = encoder_bundle.manifest.model_dump_json().encode()
    path.write_bytes(data + b" " * (65536 - len(data)))
    assert path.stat().st_size == 65536
    assert cli._manifest(path, EncoderManifest) == encoder_bundle.manifest


def test_manifest_growth_after_stat_is_still_bounded(encoder_bundle, tmp_path, monkeypatch):
    path = tmp_path / "growing-manifest.json"
    data = encoder_bundle.manifest.model_dump_json().encode()
    path.write_bytes(data + b" " * (65536 - len(data)))
    original_fstat = os.fstat
    observed = []

    def grow_after_inspection(fd):
        info = original_fstat(fd)
        with path.open("ab") as stream:
            stream.write(b" ")
            stream.flush()
        observed.append(info.st_size)
        return info

    monkeypatch.setattr(cli.os, "fstat", grow_after_inspection)
    with pytest.raises(WorkbenchError, match="^MODEL_CONFIGURATION_TOO_LARGE$"):
        cli._manifest(path, EncoderManifest)
    assert observed == [65536] and path.stat().st_size == 65537


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        ("fifo", "MODEL_CONFIGURATION_INVALID"),
        ("symlink", "MODEL_CONFIGURATION_UNAVAILABLE"),
        ("directory", "MODEL_CONFIGURATION_INVALID"),
        ("missing", "MODEL_CONFIGURATION_UNAVAILABLE"),
        ("oversize", "MODEL_CONFIGURATION_TOO_LARGE"),
        ("malformed", "INVALID_CONFIGURATION_OR_INPUT"),
    ],
)
def test_actual_cli_refuses_unsafe_manifest_without_blocking_or_disclosing_input(
    encoder_bundle, tmp_path, kind, expected
):
    path = tmp_path / "synthetic-private-manifest-path-canary"
    target = tmp_path / "regular-target.json"
    original = encoder_bundle.manifest.model_dump_json().encode()
    target.write_bytes(original)
    if kind == "fifo":
        os.mkfifo(path, 0o600)
    elif kind == "symlink":
        path.symlink_to(target)
    elif kind == "directory":
        path.mkdir()
    elif kind == "oversize":
        path.write_bytes(original + b" " * (65537 - len(original)))
    elif kind == "malformed":
        path.write_text('{"synthetic-private-content-canary":')
    output = tmp_path / "must-not-be-created"
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            "osint_workbench.cli",
            "evaluate",
            "local",
            "--suite",
            str(Path(__file__).resolve().parents[1] / "config/evaluation.example.json"),
            "--output",
            str(output),
            "--encoder-manifest",
            str(path),
        ],
        capture_output=True,
        text=True,
        timeout=4,
        check=False,
    )
    assert result.returncode == 1 and result.stdout == ""
    assert json.loads(result.stderr) == {"error": expected}
    assert str(path) not in result.stderr
    assert "synthetic-private-content-canary" not in result.stderr
    assert not output.exists() and target.read_bytes() == original
