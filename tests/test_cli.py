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


def test_collection_requires_separate_collector_dsn_without_writer_fallback(tmp_path):
    config = tmp_path / "sources.json"
    config.write_text(
        json.dumps({"sources": [{"source_id": "fixture", "url": "https://example.invalid/feed"}]})
    )
    result = subprocess.run(
        [sys.executable, "-m", "osint_workbench.cli", "collect", "--config", str(config)],
        capture_output=True,
        text=True,
        env={
            **{k: v for k, v in os.environ.items() if not k.startswith("OW_")},
            "OW_WRITER_DSN": "invalid-not-used",
        },
        timeout=10,
    )
    assert result.returncode == 1 and result.stdout == ""
    assert json.loads(result.stderr) == {"error": "DATABASE_CONFIGURATION_REQUIRED"}


def _cli(*arguments, env=None):
    result = subprocess.run(
        [sys.executable, "-m", "osint_workbench.cli", *arguments],
        capture_output=True,
        text=True,
        env={
            **{k: v for k, v in os.environ.items() if not k.startswith("OW_")},
            **(env or {}),
        },
    )
    return result.returncode, result.stdout, result.stderr


@pytest.mark.parametrize(
    "arguments",
    [
        ["enrich", "work-once"],
        ["enrich", "work-once", "--manifest", "m.json", "--route", "r"],
    ],
)
def test_enrichment_requires_exactly_one_generator_selection(tmp_path, arguments):
    code, out, err = _cli(*arguments, env={"OW_WRITER_DSN": "postgresql:///never-used"})
    assert code == 1 and out == ""
    assert json.loads(err) == {"error": "GENERATOR_SELECTION_REQUIRED"}


def test_routed_enrichment_requires_a_policy_file(tmp_path):
    code, out, err = _cli(
        "enrich", "work-once", "--route", "r", env={"OW_WRITER_DSN": "postgresql:///never-used"}
    )
    assert code == 1 and json.loads(err) == {"error": "CLOUD_POLICY_REQUIRED"}


def test_cloud_policy_symlink_and_float_money_are_refused(tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"schema_version": 1, "routes": [{"route_id": "r", "cap": 1.0}]}))
    link = tmp_path / "link.json"
    link.symlink_to(policy)
    code, _, err = _cli("cloud-exposure", "--cloud-policy", str(link))
    assert code == 1 and json.loads(err) == {"error": "MODEL_CONFIGURATION_UNAVAILABLE"}
    code, _, err = _cli("cloud-exposure", "--cloud-policy", str(policy))
    assert code == 1 and json.loads(err) == {"error": "CLOUD_POLICY_INVALID"}


def test_empty_example_policy_reports_no_routes_without_a_database_write(tmp_path):
    from pathlib import Path

    example = Path(__file__).resolve().parents[1] / "config" / "cloud-policy.example.json"
    code, out, err = _cli(
        "cloud-exposure",
        "--cloud-policy",
        str(example),
        env={"OW_WRITER_DSN": "postgresql:///never-used"},
    )
    assert code == 0 and json.loads(out)["routes"] == []
