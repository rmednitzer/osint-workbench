import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_deployment_templates.py"
spec = importlib.util.spec_from_file_location("deployment_templates", SCRIPT)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def install(tmp_path, profiles):
    for profile in profiles:
        for name in checker.PROFILES[profile]:
            target = tmp_path / checker.DROP_INS.get(name, "") / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((checker.ROOT / name).read_bytes())


def test_cli_all_profiles_and_no_private_output(tmp_path):
    install(tmp_path, checker.PROFILES)
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--installed-root", str(tmp_path)]
        + [arg for profile in checker.PROFILES for arg in ("--profile", profile)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0 and result.stderr == ""
    report = json.loads(result.stdout)
    assert len(report["templates"]) == 12
    assert {item["state"] for item in report["templates"]} == {"matches"}
    assert str(tmp_path) not in result.stdout


def test_changed_missing_fifo_symlink_and_size_are_bounded(tmp_path):
    install(tmp_path, ["shared"])
    names = checker.PROFILES["shared"]
    (tmp_path / checker.DROP_INS[names[0]] / names[0]).write_bytes(b"private-canary")
    (tmp_path / names[1]).unlink()
    (tmp_path / names[2]).unlink()
    os.mkfifo(tmp_path / names[2])
    (tmp_path / names[3]).unlink()
    (tmp_path / names[3]).symlink_to(checker.ROOT / names[3])
    (tmp_path / names[4]).write_bytes(b"x" * (checker.MAX_BYTES + 1))
    report, code = checker.check(["shared"], tmp_path)
    states = {item["template"]: item["state"] for item in report["templates"]}
    assert code == 1
    assert [states[name] for name in names] == ["changed", "missing", "unsafe", "unsafe", "unsafe"]
    assert "private-canary" not in json.dumps(report)


def test_symlink_dropin_and_root_are_refused(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    install(real, ["shared"])
    root_link = tmp_path / "link"
    root_link.symlink_to(real, target_is_directory=True)
    report, code = checker.check(["shared"], root_link)
    assert code == 1 and {item["state"] for item in report["templates"]} == {"unsafe"}
    dropin = real / checker.DROP_INS[checker.PROFILES["shared"][0]]
    dropin.rename(real / "moved")
    dropin.symlink_to(real / "moved", target_is_directory=True)
    report, code = checker.check(["shared"], real)
    assert code == 1
    assert report["templates"][0]["state"] == "unsafe"


def test_reference_failure_is_distinct_and_unavailable_errors_sanitized(tmp_path, monkeypatch):
    report, code = checker.check(["collector"], tmp_path, reference_root=tmp_path / "absent")
    assert code == 2
    assert {item["state"] for item in report["templates"]} == {"reference_unavailable_or_unsafe"}

    def denied(*args, **kwargs):
        raise PermissionError(13, "private-canary")

    monkeypatch.setattr(checker.os, "open", denied)
    assert checker.read_template(tmp_path, "fixed.service", installed=True) == ("unavailable", None)


def test_unselected_profiles_and_local_overrides_are_not_read(tmp_path):
    install(tmp_path, ["collector"])
    extras = tmp_path / "osint-workbench-collect.service.d"
    extras.mkdir()
    os.mkfifo(extras / "private-override.conf")
    report, code = checker.check(["collector", "collector"], tmp_path)
    assert code == 0 and len(report["templates"]) == 2
