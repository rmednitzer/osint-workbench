"""Run the actual isolated signer admission script against synthetic data files."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

SHA = "a" * 40
REPORTS = {
    "sbom.cdx.json",
    "licence-review.json",
    "native-review.json",
    "missing-wheel-notices.txt",
}


def encode(document):
    return (json.dumps(document, sort_keys=True, indent=2) + "\n").encode()


def write_manifest(leg, document):
    raw = encode(document)
    (leg / "build-evidence/manifest.json").write_bytes(raw)
    (leg / "build-evidence/manifest.sha256").write_text(hashlib.sha256(raw).hexdigest() + "\n")


def record(path):
    raw = path.read_bytes()
    return {"filename": path.name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


@pytest.fixture
def signer_fixture(tmp_path):
    # These are deliberately opaque data fixtures, not valid wheels or SBOMs.
    # Producer gates own semantic checks; this isolated job checks identity/bytes.
    for runner, minor in [
        ("ubuntu-24.04", "3.12"),
        ("ubuntu-26.04", "3.14"),
    ]:
        leg = tmp_path / "evidence" / f"build-evidence-{runner}-python{minor}-{SHA}"
        for name in ("dist", "assurance", "build-evidence"):
            (leg / name).mkdir(parents=True)
        for name in ("osint_workbench-1-py3-none-any.whl", "osint_workbench-1.tar.gz"):
            (leg / "dist" / name).write_bytes(b"synthetic artifact bytes")
        for name in REPORTS:
            (leg / "assurance" / name).write_bytes(b"synthetic evidence bytes")
        document = {
            "format": "osint-workbench-build-evidence-v3",
            "assurance_profile": "python-sbom-native-and-notices",
            "source": {"commit": SHA, "tree": "b" * 40},
            "workflow": {"run_id": "42", "run_attempt": "1"},
            "runtime": {"implementation": "CPython", "python": minor + ".0", "os": runner},
            "artifacts": [record(p) for p in sorted((leg / "dist").iterdir())],
            "related_evidence": [record(p) for p in sorted((leg / "assurance").iterdir())],
        }
        write_manifest(leg, document)
        shutil.copytree(leg / "dist", tmp_path / "originals" / ("distributions-" + leg.name))
    workflow = yaml.safe_load(
        (Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml").read_text()
    )
    script = next(
        step["run"]
        for step in workflow["jobs"]["attest-builds"]["steps"]
        if step.get("name") == "Validate the complete evidence set without executing it"
    )
    env = {
        **os.environ,
        "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"],
        "SOURCE_SHA": SHA,
        "RUN_ID": "42",
        "RUN_ATTEMPT": "1",
        "PYTHONOPTIMIZE": "2",
        "PYTHONPATH": "/not-a-python-package-directory",
    }

    def run():
        return subprocess.run(
            ["bash", "-c", script], cwd=tmp_path, env=env, capture_output=True, timeout=10
        )

    leg = next((tmp_path / "evidence").iterdir())
    return leg, json.loads((leg / "build-evidence/manifest.json").read_text()), run


def test_signer_accepts_complete_set_even_with_optimization_requested(signer_fixture):
    _, _, run = signer_fixture
    assert run().returncode == 0


@pytest.mark.parametrize(
    "case",
    [
        "missing-leg",
        "extra-optional-leg",
        "optional-runtime",
        "missing-report",
        "extra-file",
        "symlink",
        "fifo",
        "changed-bytes",
        "oversize-report",
        "wrong-source",
        "wrong-run",
        "wrong-attempt",
        "wrong-runtime",
        "wrong-os",
        "legacy-format",
        "legacy-profile",
        "missing-report-record",
        "path-selector",
    ],
)
def test_signer_refuses_invalid_evidence_before_signing(signer_fixture, case):
    leg, document, run = signer_fixture
    report = leg / "assurance/native-review.json"
    if case == "missing-leg":
        other = next(p for p in leg.parent.iterdir() if p != leg)
        shutil.rmtree(other)
    elif case == "extra-optional-leg":
        shutil.copytree(leg, leg.parent / f"build-evidence-ubuntu-24.04-python3.13-{SHA}")
    elif case == "optional-runtime":
        document["runtime"]["python"] = "3.13.0"
    elif case == "missing-report":
        report.unlink()
    elif case == "extra-file":
        (leg / "unexpected.txt").write_bytes(b"unexpected")
    elif case == "symlink":
        report.unlink()
        report.symlink_to(leg / "assurance/sbom.cdx.json")
    elif case == "fifo":
        report.unlink()
        os.mkfifo(report)
    elif case == "changed-bytes":
        report.write_bytes(b"substituted")
    elif case == "oversize-report":
        report.write_bytes(b"x" * (4 * 1024 * 1024 + 1))
        document["related_evidence"] = [record(p) for p in sorted((leg / "assurance").iterdir())]
    elif case == "wrong-source":
        document["source"]["commit"] = "c" * 40
    elif case == "wrong-run":
        document["workflow"]["run_id"] = "43"
    elif case == "wrong-attempt":
        document["workflow"]["run_attempt"] = "2"
    elif case == "wrong-runtime":
        document["runtime"]["python"] = "3.15.0"
    elif case == "wrong-os":
        document["runtime"]["os"] = "ubuntu-22.04"
    elif case == "legacy-format":
        document["format"] = "osint-workbench-build-evidence-v2"
    elif case == "legacy-profile":
        document["assurance_profile"] = "python-sbom-and-licence-review"
    elif case == "missing-report-record":
        document["related_evidence"].pop()
    elif case == "path-selector":
        document["artifacts"][0]["filename"] = "../outside.whl"
    write_manifest(leg, document)
    result = run()
    assert result.returncode != 0
    assert b"EVIDENCE_SET_REFUSED" in result.stderr


@pytest.mark.parametrize("outcome", ["success", "failure", "cancelled", "skipped"])
def test_required_aggregate_rejects_incomplete_or_failed_profiles(outcome, tmp_path):
    workflow = yaml.safe_load(
        (Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml").read_text()
    )
    script = workflow["jobs"]["installed-artifact"]["steps"][0]["run"]
    result = subprocess.run(
        ["bash", "-c", script],
        cwd=tmp_path,
        env={**os.environ, "MATRIX_RESULT": outcome},
        capture_output=True,
        timeout=10,
    )
    assert (result.returncode == 0) == (outcome == "success")


@pytest.mark.parametrize(
    "profile, accepted",
    [
        (("ubuntu-24.04", "24.04", "3.12", "build-evidence"), True),
        (("ubuntu-26.04", "26.04", "3.14", "build-evidence"), True),
        (("ubuntu-24.04", "24.04", "3.13", "compatibility-evidence"), True),
        (("ubuntu-24.04", "24.04", "3.13", "build-evidence"), False),
        (("ubuntu-26.04", "26.04", "3.15", "build-evidence"), False),
        (("ubuntu-26.04", "26.04", "3.12", "build-evidence"), False),
    ],
)
def test_reusable_profile_admission_keeps_optional_evidence_separate(profile, accepted, tmp_path):
    workflow = yaml.safe_load(
        (
            Path(__file__).resolve().parents[1] / ".github/workflows/installed-profile.yml"
        ).read_text()
    )
    script = workflow["jobs"]["verify"]["steps"][0]["run"]
    env = {
        **os.environ,
        **dict(
            zip(
                ("PROFILE_RUNNER", "PROFILE_UBUNTU", "PROFILE_PYTHON", "ARTIFACT_PREFIX"),
                profile,
                strict=True,
            )
        ),
    }
    result = subprocess.run(
        ["bash", "-c", script],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        timeout=10,
    )
    assert (result.returncode == 0) == accepted
    if not accepted:
        assert b"VERIFICATION_PROFILE_REFUSED" in result.stderr


def test_runtime_workflow_wiring_preserves_lts_qualification_and_optional_authority():
    root = Path(__file__).resolve().parents[1] / ".github/workflows"
    required = yaml.safe_load((root / "ci.yml").read_text())
    optional = yaml.safe_load((root / "python-compatibility.yml").read_text())
    shared = yaml.safe_load((root / "installed-profile.yml").read_text())
    matrix = required["jobs"]["installed-artifact-matrix"]
    profiles = matrix["strategy"]["matrix"]["include"]
    assert {(p["runner"], p["ubuntu"], p["python"]) for p in profiles} == {
        ("ubuntu-24.04", "24.04", "3.12"),
        ("ubuntu-26.04", "26.04", "3.14"),
    }
    assert len(profiles) == 2
    assert required["jobs"]["installed-artifact"]["needs"] == "installed-artifact-matrix"
    assert set(required["jobs"]["attest-builds"]["needs"]) == {
        "repository-policy",
        "renovate-policy",
        "installed-artifact",
        "acceptance",
    }
    # PyYAML's YAML 1.1 reader parses the unquoted Actions `on` key as True.
    triggers = optional.get("on", optional.get(True))
    assert set(triggers) == {"schedule", "workflow_dispatch"}
    assert optional["permissions"] == shared["permissions"] == {"contents": "read"}
    compatibility = optional["jobs"]["compatibility-3-13"]
    assert matrix["uses"] == compatibility["uses"] == "./.github/workflows/installed-profile.yml"
    assert compatibility["with"]["artifact-prefix"] == "compatibility-evidence"
    assert "secrets" not in compatibility and "permissions" not in compatibility
    for job in shared["jobs"].values():
        assert "permissions" not in job
        assert not any("actions/attest@" in step.get("uses", "") for step in job["steps"])


@pytest.mark.parametrize("suffix", [".whl", ".tar.gz"])
def test_signer_refuses_replacement_even_with_matching_post_test_receipt(signer_fixture, suffix):
    leg, document, run = signer_fixture
    artifact = next(p for p in (leg / "dist").iterdir() if p.name.endswith(suffix))
    artifact.write_bytes(b"replacement never installed by tests")
    document["artifacts"] = [record(p) for p in sorted((leg / "dist").iterdir())]
    write_manifest(leg, document)
    result = run()
    assert result.returncode != 0 and b"EVIDENCE_SET_REFUSED" in result.stderr
