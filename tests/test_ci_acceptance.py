"""Execute acceptance and hosted-runner guards with synthetic event states."""

import os
import subprocess
from pathlib import Path

import pytest
import yaml

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github/workflows"


def workflow(name):
    return yaml.safe_load((WORKFLOWS / name).read_text())


@pytest.mark.parametrize(
    ("audit", "compose", "accepted"),
    [
        ("success", "success", True),
        ("failure", "success", False),
        ("success", "failure", False),
        ("skipped", "success", False),
        ("success", "cancelled", False),
        ("", "success", False),
    ],
)
def test_actual_acceptance_gate_refuses_incomplete_or_failed_work(audit, compose, accepted):
    gate = workflow("ci.yml")["jobs"]["acceptance"]
    result = subprocess.run(
        ["bash", "-eu", "-c", gate["steps"][0]["run"]],
        env={**os.environ, "AUDIT_RESULT": audit, "COMPOSE_RESULT": compose},
        timeout=5,
    )
    assert (result.returncode == 0) == accepted


@pytest.mark.parametrize(
    ("event", "acknowledged", "runner", "accepted"),
    [
        ("pull_request", "true", "github-hosted", True),
        ("push", "true", "github-hosted", True),
        ("workflow_dispatch", "true", "github-hosted", True),
        ("workflow_dispatch", "false", "github-hosted", False),
        ("pull_request", "false", "github-hosted", False),
        ("pull_request", "true", "self-hosted", False),
        ("issue_comment", "true", "github-hosted", False),
    ],
)
def test_compose_execution_guard_keeps_manual_and_host_boundaries(
    event, acknowledged, runner, accepted
):
    guard = workflow("compose-core.yml")["jobs"]["synthetic-core"]["steps"][0]["run"]
    result = subprocess.run(
        ["bash", "-eu", "-c", guard],
        env={
            **os.environ,
            "EVENT_NAME": event,
            "ACKNOWLEDGED": acknowledged,
            "RUNNER_ENVIRONMENT": runner,
        },
        timeout=5,
    )
    assert (result.returncode == 0) == accepted


def test_acceptance_is_wired_to_real_reusable_jobs_and_signing():
    jobs = workflow("ci.yml")["jobs"]
    assert jobs["dependency-audit"]["uses"] == "./.github/workflows/dependency-audit.yml"
    assert jobs["compose-core"]["uses"] == "./.github/workflows/compose-core.yml"
    assert set(jobs["acceptance"]["needs"]) == {"dependency-audit", "compose-core"}
    assert jobs["acceptance"]["if"] == "${{ always() }}"
    assert "acceptance" in jobs["attest-builds"]["needs"]
    for name in ("dependency-audit.yml", "compose-core.yml", "copilot-setup-steps.yml"):
        assert workflow(name)["permissions"] == {"contents": "read"}
