"""Native unit parsing, not execution or a deployed sandbox acceptance test."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("invalid_directive", [False, True])
def test_systemd_reference_units_native_verifier(tmp_path, invalid_directive):
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
