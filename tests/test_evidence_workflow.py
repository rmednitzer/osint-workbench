"""Run the actual isolated signer admission script against synthetic data files."""

import hashlib
import json
import os
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
        ("ubuntu-24.04", "3.13"),
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
    if case == "missing-report":
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
