"""Consumer admission refuses substituted source/run identities and bytes."""

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
SHA = "a" * 40


@pytest.fixture
def consumer(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(SCRIPTS))
    spec = importlib.util.spec_from_file_location("verify_download", SCRIPTS / "verify_download.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    evidence, bundle = tmp_path / "evidence", tmp_path / "signature"
    bundle.mkdir()
    (bundle / "bundle.jsonl").write_text("synthetic verifier input")
    for os_name, version in module.PROFILES:
        leg = evidence / f"build-evidence-{os_name}-python{version}-{SHA}"
        for directory in ("dist", "assurance", "build-evidence"):
            (leg / directory).mkdir(parents=True)
        records = {}
        for directory, names in [
            ("dist", ["osint_workbench-1-py3-none-any.whl", "osint_workbench-1.tar.gz"]),
            ("assurance", module.SUPPLEMENTS),
        ]:
            records[directory] = []
            for name in names:
                path = leg / directory / name
                path.write_bytes(b"synthetic immutable bytes")
                records[directory].append(
                    {
                        "filename": name,
                        "bytes": path.stat().st_size,
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    }
                )
        document = {
            "format": module.FORMAT,
            "assurance_profile": "python-sbom-native-and-notices",
            "source": {"commit": SHA},
            "workflow": {"run_id": "42", "run_attempt": "1"},
            "runtime": {"implementation": "CPython", "os": os_name, "python": version + ".0"},
            "artifacts": records["dist"],
            "related_evidence": records["assurance"],
        }
        raw = json.dumps(document).encode()
        (leg / "build-evidence/manifest.json").write_bytes(raw)
        (leg / "build-evidence/manifest.sha256").write_text(hashlib.sha256(raw).hexdigest() + "\n")
    monkeypatch.setattr(module, "signature", lambda *args: None)
    return module, evidence, bundle


def test_consumer_accepts_complete_two_profile_set(consumer):
    module, evidence, bundle = consumer
    assert module.verify(evidence, bundle, SHA, "42", "1")["distributions"] == 4


@pytest.mark.parametrize("field", ["commit", "run_id", "run_attempt"])
def test_signed_manifest_still_needs_the_expected_source_and_run(consumer, field):
    module, evidence, bundle = consumer
    leg = next(evidence.iterdir())
    path = leg / "build-evidence/manifest.json"
    document = json.loads(path.read_text())
    document["source" if field == "commit" else "workflow"][field] = (
        "b" * 40 if field == "commit" else "2"
    )
    raw = json.dumps(document).encode()
    path.write_bytes(raw)
    (leg / "build-evidence/manifest.sha256").write_text(hashlib.sha256(raw).hexdigest() + "\n")
    with pytest.raises(module.DownloadError, match="MISMATCH"):
        module.verify(evidence, bundle, SHA, "42", "1")


@pytest.mark.parametrize("mutation", ["modified", "extra", "symlink", "traversal"])
def test_consumer_refuses_substituted_artifacts(consumer, mutation):
    module, evidence, bundle = consumer
    leg = next(evidence.iterdir())
    wheel = next((leg / "dist").glob("*.whl"))
    if mutation == "modified":
        wheel.write_bytes(b"substituted")
    elif mutation == "extra":
        (leg / "dist/extra").write_bytes(b"unexpected")
    elif mutation == "symlink":
        wheel.unlink()
        wheel.symlink_to(leg / "assurance/sbom.cdx.json")
    else:
        path = leg / "build-evidence/manifest.json"
        document = json.loads(path.read_text())
        document["artifacts"][0]["filename"] = "../escape.whl"
        raw = json.dumps(document).encode()
        path.write_bytes(raw)
        (leg / "build-evidence/manifest.sha256").write_text(hashlib.sha256(raw).hexdigest() + "\n")
    with pytest.raises(module.DownloadError):
        module.verify(evidence, bundle, SHA, "42", "1")


def test_real_signature_adapter_enforces_identity_and_refuses_verifier_failure(
    consumer, monkeypatch, tmp_path
):
    module, _, bundle = consumer
    # Reload to use the real adapter, while substituting only the external CLI.
    spec = importlib.util.spec_from_file_location("real_verifier", SCRIPTS / "verify_download.py")
    real = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(real)
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        kwargs["stdout"].write(b"[{}]")
        return type("Result", (), {"returncode": 0 if len(calls) == 1 else 1})()

    monkeypatch.setattr(real.subprocess, "run", run)
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}")
    real.signature(manifest, bundle / "bundle.jsonl", SHA, tmp_path)
    command = calls[0]
    for flag, expected in [
        ("--source-digest", SHA),
        ("--signer-digest", SHA),
        ("--source-ref", "refs/heads/main"),
        ("--signer-workflow", real.WORKFLOW),
        ("--repo", real.REPOSITORY),
    ]:
        assert command[command.index(flag) + 1] == expected
    assert "--deny-self-hosted-runners" in command
    with pytest.raises(real.DownloadError, match="DOWNLOAD_SIGNATURE_REFUSED"):
        real.signature(manifest, bundle / "bundle.jsonl", SHA, tmp_path)
