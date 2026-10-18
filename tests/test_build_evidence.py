import hashlib
import importlib.util
from email.message import Message
from pathlib import Path
from types import SimpleNamespace

import pytest


def evidence():
    path = Path(__file__).resolve().parents[1] / "scripts/build_evidence.py"
    spec = importlib.util.spec_from_file_location("build_evidence", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def distribution(name, expression=None):
    metadata = Message()
    metadata["Name"] = name
    metadata["License"] = "/private/operator-file"
    metadata["Author-email"] = "private@example.invalid"
    metadata["Classifier"] = "License :: OSI Approved :: MIT License"
    if expression is not None:
        metadata["License-Expression"] = expression
    return SimpleNamespace(metadata=metadata, version="1.0")


def test_inventory_preserves_declarations_and_marks_missing_expressions():
    result = evidence().inventory(
        [distribution("osint-workbench", "Apache-2.0"), distribution("legacy")]
    )
    assert result["unresolved_license_expressions"] == [
        {"name": "legacy", "reason": "missing-declared-license-expression"}
    ]
    app = next(row for row in result["distributions"] if row["name"] == "osint-workbench")
    assert app["declared_license_expression"] == "Apache-2.0"
    assert app["declared_license_classifiers"] == ["License :: OSI Approved :: MIT License"]
    assert "private" not in str(result)


def test_inventory_refuses_ambiguous_names_and_unsafe_metadata():
    module = evidence()
    with pytest.raises(module.EvidenceError, match="AMBIGUOUS"):
        module.inventory([distribution("osint-workbench"), distribution("osint_workbench")])
    with pytest.raises(module.EvidenceError, match="METADATA_REFUSED"):
        module.inventory([distribution("osint-workbench", "/private/operator-file")])


def test_receipt_detects_changed_artifact_even_after_checksum_is_recomputed(tmp_path):
    module = evidence()
    artifact = tmp_path / "artifact.whl"
    artifact.write_bytes(b"original")
    original = {"artifact": module.file_identity(artifact)}
    output = tmp_path / "receipt"
    module.write_evidence(original, output)
    module.verify_evidence(original, output)
    artifact.write_bytes(b"tampered")
    with pytest.raises(module.EvidenceError, match="INTEGRITY_MISMATCH"):
        module.verify_evidence({"artifact": module.file_identity(artifact)}, output)
    forged = module.encoded({"artifact": {"sha256": "forged"}})
    (output / "manifest.json").write_bytes(forged)
    (output / "manifest.sha256").write_text(hashlib.sha256(forged).hexdigest() + "\n")
    with pytest.raises(module.EvidenceError, match="INTEGRITY_MISMATCH"):
        module.verify_evidence(original, output)


def test_artifact_selection_refuses_symlinks_and_extra_files(tmp_path):
    module = evidence()
    wheel = tmp_path / "osint_workbench-1-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    source = tmp_path / "osint_workbench-1.tar.gz"
    source.write_bytes(b"source")
    assert len(module.artifact_inventory(tmp_path)) == 2
    wheel.unlink()
    wheel.symlink_to(source)
    with pytest.raises(module.EvidenceError, match="INPUT_REFUSED"):
        module.artifact_inventory(tmp_path)
    (tmp_path / "unexpected.json").write_text("{}")
    with pytest.raises(module.EvidenceError, match="ARTIFACT_SET_REFUSED"):
        module.artifact_inventory(tmp_path)


def test_source_identity_rejects_dirty_or_different_checkout(monkeypatch, tmp_path):
    module = evidence()
    env = {"OW_EVIDENCE_COMMIT": "a" * 40, "OW_EVIDENCE_TREE": "b" * 40}
    answers = iter(["a" * 40 + "\n" + "b" * 40 + "\n", " M tracked.py\n"])
    monkeypatch.setattr(module.subprocess, "check_output", lambda *a, **kw: next(answers))
    with pytest.raises(module.EvidenceError, match="SOURCE_MISMATCH"):
        module.source_identity(tmp_path, env)
    answers = iter(["c" * 40 + "\n" + "b" * 40 + "\n", ""])
    with pytest.raises(module.EvidenceError, match="SOURCE_MISMATCH"):
        module.source_identity(tmp_path, env)


def test_runtime_identity_checks_actual_os_and_python(monkeypatch):
    module = evidence()
    monkeypatch.setattr(module.platform, "python_implementation", lambda: "CPython")
    monkeypatch.setattr(
        module.platform, "freedesktop_os_release", lambda: {"ID": "ubuntu", "VERSION_ID": "26.04"}
    )
    env = {
        "OW_EVIDENCE_PYTHON": f"{module.sys.version_info.major}.{module.sys.version_info.minor}",
        "OW_EVIDENCE_OS": "ubuntu-26.04",
    }
    assert module.runtime_identity(env)["os"] == "ubuntu-26.04"
    env["OW_EVIDENCE_OS"] = "ubuntu-24.04"
    with pytest.raises(module.EvidenceError, match="OS_MISMATCH"):
        module.runtime_identity(env)
