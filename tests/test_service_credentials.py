"""Privilege guards and diagnostics; ordinary pytest never starts service units."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest


def _helper():
    script = Path(__file__).resolve().parents[1] / "scripts/test_service_credentials.py"
    spec = importlib.util.spec_from_file_location("credential_service_fixture_test", script)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    return helper


@pytest.mark.parametrize(
    "uid,github,runner,code",
    [
        (1000, "true", "github-hosted", "ROOT_REQUIRED"),
        (0, "false", "github-hosted", "GITHUB_ACTIONS_REQUIRED"),
        (0, "true", "self-hosted", "HOSTED_RUNNER_REQUIRED"),
    ],
)
def test_harness_refuses_unguarded_execution_before_acceptance(
    monkeypatch, capsys, uid, github, runner, code
):
    helper = _helper()
    monkeypatch.setattr(helper.os, "geteuid", lambda: uid)
    monkeypatch.setenv("GITHUB_ACTIONS", github)
    monkeypatch.setenv("RUNNER_ENVIRONMENT", runner)
    monkeypatch.setattr(sys, "argv", ["fixture", "--core-venv", "/tmp/ow-reference-core"])

    def forbidden(*args, **kwargs):
        raise AssertionError("privileged mutation before guard acceptance")

    monkeypatch.setattr(helper, "acceptance", forbidden)
    assert helper.main() == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err) == {"accepted": False, "error": code}


def test_actual_child_failure_does_not_publish_stdout_stderr_or_arguments(capsys):
    helper = _helper()
    canary = "synthetic-service-credential-canary"
    with pytest.raises(helper.Rejected, match="^FIXTURE_COMMAND_FAILED$"):
        helper.run(
            [
                sys.executable,
                "-c",
                "import sys;print(sys.argv[1]);print(sys.argv[1],file=sys.stderr);sys.exit(1)",
                canary,
            ]
        )
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
