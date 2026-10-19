"""Installed CLI admission for operator-selected feed configuration and text."""

import json
import os
import subprocess
import sys

import pytest

from osint_workbench import cli
from osint_workbench.errors import WorkbenchError


@pytest.mark.parametrize("command", ["collect", "import-text"])
@pytest.mark.parametrize(
    "kind", ["fifo", "symlink", "directory", "missing", "device", "oversize", "invalid"]
)
def test_installed_cli_refuses_unsafe_operator_input_before_effects(tmp_path, command, kind):
    path = tmp_path / "synthetic-private-input-canary"
    target = tmp_path / "regular-target"
    target.write_bytes(b"unchanged synthetic fixture")
    if kind == "fifo":
        os.mkfifo(path, 0o600)
    elif kind == "symlink":
        path.symlink_to(target)
    elif kind == "directory":
        path.mkdir()
    elif kind == "device":
        path = type(path)("/dev/null")
    elif kind == "oversize":
        with path.open("wb") as stream:
            stream.truncate(8 * 1024 * 1024 + 1 if command == "collect" else 4_000_001)
    elif kind == "invalid":
        path.write_bytes(b"\xffsynthetic-private-content-canary")
    args = (
        ["collect", "--config", str(path)]
        if command == "collect"
        else ["import-text", "--file", str(path), "--source-id", "fixture", "--title", "Fixture"]
    )
    result = subprocess.run(
        [sys.executable, "-I", "-m", "osint_workbench.cli", *args],
        capture_output=True,
        text=True,
        timeout=4,
        env={key: value for key, value in os.environ.items() if not key.startswith("OW_")},
        check=False,
    )
    error = "INVALID_CONFIGURATION_OR_INPUT"
    if kind == "oversize":
        error = (
            "SOURCE_CONFIGURATION_TOO_LARGE" if command == "collect" else "IMPORT_INPUT_TOO_LARGE"
        )
    assert result.returncode == 1 and result.stdout == ""
    assert json.loads(result.stderr) == {"error": error}
    assert (
        str(path) not in result.stderr and "synthetic-private-content-canary" not in result.stderr
    )
    assert target.read_bytes() == b"unchanged synthetic fixture"


def test_exact_source_byte_limit_keeps_empty_core_without_database(tmp_path):
    path = tmp_path / "sources.json"
    data = b'{"sources":[]}'
    path.write_bytes(data + b" " * (8 * 1024 * 1024 - len(data)))
    result = subprocess.run(
        [sys.executable, "-I", "-m", "osint_workbench.cli", "collect", "--config", str(path)],
        capture_output=True,
        text=True,
        timeout=4,
        env={key: value for key, value in os.environ.items() if not key.startswith("OW_")},
        check=False,
    )
    assert result.returncode == 0 and result.stderr == ""
    assert json.loads(result.stdout) == {"status": "unconfigured", "sources": 0}


def test_text_byte_limit_preserves_maximum_four_byte_unicode_input(tmp_path):
    path = tmp_path / "text.txt"
    text = "\U0001f98a" * 1_000_000
    path.write_bytes(text.encode("utf-8"))
    assert path.stat().st_size == 4_000_000
    assert cli._operator_bytes(path, profile="text").decode("utf-8") == text


@pytest.mark.parametrize(
    ("profile", "maximum", "error"),
    [
        ("sources", 8 * 1024 * 1024, "SOURCE_CONFIGURATION_TOO_LARGE"),
        ("text", 4_000_000, "IMPORT_INPUT_TOO_LARGE"),
    ],
)
def test_operator_input_growth_after_stat_cannot_bypass_byte_bound(
    tmp_path, monkeypatch, profile, maximum, error
):
    path = tmp_path / "growing-input"
    with path.open("wb") as stream:
        stream.truncate(maximum)
    original = os.fstat

    def grow_after_stat(fd):
        info = original(fd)
        with path.open("ab") as stream:
            stream.write(b"x")
        return info

    monkeypatch.setattr(cli.os, "fstat", grow_after_stat)
    with pytest.raises(WorkbenchError, match=f"^{error}$"):
        cli._operator_bytes(path, profile=profile)
