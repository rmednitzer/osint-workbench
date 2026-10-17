import json
import os
import subprocess
import sys

import pytest


@pytest.mark.parametrize("limit", [0, 1, 32, 129])
def test_manual_collection_never_silently_ignores_explicit_cap(tmp_path, limit):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "osint_workbench.cli",
            "collect",
            "--config",
            str(tmp_path / "absent.json"),
            "--max-sources",
            str(limit),
        ],
        capture_output=True,
        text=True,
        env={k: v for k, v in os.environ.items() if not k.startswith("OW_")},
    )
    assert result.returncode == 1 and result.stdout == ""
    assert json.loads(result.stderr) == {"error": "MAX_SOURCES_REQUIRES_DUE_ONLY"}


@pytest.mark.parametrize("limit", [0, 129])
def test_due_limit_validation_precedes_configuration_and_database(tmp_path, limit):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "osint_workbench.cli",
            "collect",
            "--config",
            str(tmp_path / "absent.json"),
            "--due-only",
            "--max-sources",
            str(limit),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1 and result.stdout == ""
    assert json.loads(result.stderr) == {"error": "INVALID_COLLECTION_LIMIT"}


def test_local_evaluation_replay_keeps_negative_gates_and_no_overwrite(tmp_path):
    from tests.test_evaluation import suite_input

    suite = tmp_path / "suite.json"
    suite.write_text(json.dumps(suite_input()))
    output = tmp_path / "diagnostic"
    local = subprocess.run(
        [
            sys.executable,
            "-m",
            "osint_workbench.cli",
            "evaluate",
            "local",
            "--suite",
            str(suite),
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
    )
    assert local.returncode == 2
    outcome = json.loads(local.stdout)
    assert outcome["status"] == "completed" and not outcome["all_targets_met"]
    receipt = tmp_path / "replayed.json"
    command = [
        sys.executable,
        "-m",
        "osint_workbench.cli",
        "evaluate",
        "replay",
        "--suite",
        str(suite),
        "--predictions",
        str(output / "lexical-predictions.json"),
        "--file",
        str(receipt),
    ]
    replay = subprocess.run(command, capture_output=True, text=True)
    assert replay.returncode == 2 and not json.loads(replay.stdout)["all_targets_met"]
    original = receipt.read_bytes()
    repeated = subprocess.run(command, capture_output=True, text=True)
    assert repeated.returncode == 1 and receipt.read_bytes() == original


def test_evaluation_rejects_symlink_before_creating_output(tmp_path):
    suite = tmp_path / "suite.json"
    suite.write_text("{}")
    link = tmp_path / "input-link"
    link.symlink_to(suite)
    output = tmp_path / "diagnostic"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "osint_workbench.cli",
            "evaluate",
            "local",
            "--suite",
            str(link),
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1 and not output.exists()


def test_parser_response_cannot_expand_configured_source_authority(monkeypatch):
    from types import SimpleNamespace

    from osint_workbench.collection import feed_documents
    from osint_workbench.errors import WorkbenchError

    def different_source(command, *, stdout, **kwargs):
        stdout.write(
            json.dumps(
                [
                    {
                        "source_id": "other-source",
                        "external_id": "one",
                        "title": "Forged",
                        "text": "Cross-source result",
                    }
                ]
            ).encode()
        )
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("osint_workbench.collection.subprocess.run", different_source)
    with pytest.raises(WorkbenchError, match="FEED_PARSE_FAILED"):
        feed_documents(b"synthetic child protocol fixture", "configured-source")
