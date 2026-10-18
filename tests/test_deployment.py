"""Native unit parsing and diagnostic redaction; no privileged deployment execution."""

import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load_deployment_helper():
    script = ROOT / "scripts/test_reference_deployment.py"
    spec = importlib.util.spec_from_file_location("deployment_redaction_test", script)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    return helper


def diagnostic_output(capsys):
    captured = capsys.readouterr()
    prefix = "PUBLIC_DEPLOYMENT_DIAGNOSTIC="
    assert captured.err == "" and captured.out.count("\n") == 1
    assert captured.out.startswith(prefix) and len(captured.out.encode()) < 1024
    return json.loads(captured.out.removeprefix(prefix)), captured.out


def test_actual_command_failure_diagnostic_excludes_arguments_and_paths(capsys):
    helper = load_deployment_helper()
    credential_canary = "synthetic-credential-redaction-canary"
    path_canary = "/synthetic/private/path-redaction-canary"
    with pytest.raises(helper.Rejected, match="^NATIVE_COMMAND_FAILED$"):
        helper.command(["/usr/bin/false", credential_canary, path_canary])
    diagnostic, text = diagnostic_output(capsys)
    assert credential_canary not in text and path_canary not in text
    assert "/usr/bin/false" not in text
    assert diagnostic == {
        "kind": "native_command_failed",
        "executable": "other",
        "action": "other",
        "returncode": 1,
    }


def test_actual_filesystem_exception_diagnostic_keeps_only_known_frame(tmp_path, capsys):
    helper = load_deployment_helper()
    target = tmp_path / "synthetic-private-path-canary"
    target.write_text("synthetic-existing-private-content-canary")
    try:
        helper.write_private(target, "replacement-must-not-be-written")
    except FileExistsError as error:
        helper.exception_diagnostic(error)
    else:
        pytest.fail("existing private output was unexpectedly overwritten")
    diagnostic, text = diagnostic_output(capsys)
    assert target.name not in text and str(tmp_path) not in text and str(ROOT) not in text
    assert "synthetic-existing-private-content-canary" not in text
    assert "replacement-must-not-be-written" not in text
    assert set(diagnostic) == {"kind", "exception_type", "frame_file", "frame_line"}
    assert diagnostic["kind"] == "unexpected_exception"
    assert diagnostic["exception_type"] == "FileExistsError"
    assert diagnostic["frame_file"] == "test_reference_deployment.py"
    assert type(diagnostic["frame_line"]) is int and 1 <= diagnostic["frame_line"] <= 20000
    assert target.read_text() == "synthetic-existing-private-content-canary"


class SyntheticPrivateExceptionName(RuntimeError):
    pass


@pytest.mark.parametrize(
    ("exception_class", "expected_type"),
    [(ValueError, "ValueError"), (SyntheticPrivateExceptionName, "other")],
)
def test_external_exception_diagnostic_excludes_message_class_and_external_frame(
    capsys, exception_class, expected_type
):
    helper = load_deployment_helper()
    canary = "synthetic-exception-message-canary"
    try:
        raise exception_class(canary)
    except exception_class as error:
        helper.exception_diagnostic(error)
    diagnostic, text = diagnostic_output(capsys)
    assert canary not in text and "SyntheticPrivateExceptionName" not in text
    assert str(ROOT) not in text and "test_deployment.py" not in text
    assert diagnostic == {"kind": "unexpected_exception", "exception_type": expected_type}


@pytest.mark.parametrize("invalid_directive", [False, True])
@pytest.mark.parametrize("shared_cas", [False, True])
def test_systemd_reference_units_native_verifier(tmp_path, invalid_directive, shared_cas):
    verifier = shutil.which("systemd-analyze")
    if not verifier:
        pytest.fail("systemd-analyze is required for reference-unit verification")
    unit_dir = tmp_path / "etc/systemd/system"
    unit_dir.mkdir(parents=True)
    units = sorted((ROOT / "config/systemd").glob("*.service"))
    units += sorted((ROOT / "config/systemd").glob("*.timer"))
    assert units, "No reference deployment units were selected"
    for unit in units:
        shutil.copyfile(unit, unit_dir / unit.name)
    if shared_cas:
        dropin = unit_dir / "osint-workbench-collect.service.d"
        dropin.mkdir()
        shutil.copyfile(
            ROOT / "config/systemd/osint-workbench-collect-shared.conf", dropin / "shared.conf"
        )
    if invalid_directive:
        with (unit_dir / "osint-workbench-collect.service").open("a") as stream:
            stream.write("UnsupportedWorkbenchDirective=yes\n")
    # Native verification requires executable and target existence. This empty,
    # non-runnable marker supplies only that prerequisite inside the isolated root;
    # it is never executed and establishes no installed-wheel runtime claim.
    executable = tmp_path / "opt/osint-workbench/venv/bin/osint-workbench"
    executable.parent.mkdir(parents=True)
    executable.write_text("not executable program content\n")
    executable.chmod(0o755)
    for target in ("sysinit.target", "basic.target", "shutdown.target", "network-online.target"):
        (unit_dir / target).write_text("[Unit]\nDescription=Verifier prerequisite\n")
    env = {**os.environ, "SYSTEMD_LOG_LEVEL": "warning"}
    env.pop("SYSTEMD_UNIT_PATH", None)
    result = subprocess.run(
        [verifier, "verify", "--man=no", f"--root={tmp_path}"] + [unit.name for unit in units],
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if invalid_directive:
        assert "UnsupportedWorkbenchDirective" in result.stderr
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        assert not result.stderr.strip(), result.stderr
