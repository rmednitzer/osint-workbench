"""Exact offline supplementary texts, with filesystem and policy tamper failures."""

import copy
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def module():
    spec = importlib.util.spec_from_file_location(
        "build_notices", ROOT / "scripts/build_notices.py"
    )
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


@pytest.fixture
def checkout(tmp_path):
    root = tmp_path / "synthetic-checkout"
    source = root / "docs/security/notices"
    source.mkdir(parents=True)
    for path in (ROOT / "docs/security/notices").iterdir():
        shutil.copyfile(path, source / path.name)
    policy = json.loads((ROOT / "docs/security/dependency-licences.json").read_bytes())
    return root, policy


def encoded(policy):
    return (json.dumps(policy, indent=2) + "\n").encode()


def run_cli(operation, policy, output):
    return subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/build_notices.py"),
            operation,
            "--policy",
            str(policy),
            "--output",
            str(output),
        ],
        capture_output=True,
        timeout=3,
        check=False,
    )


def test_deterministic_bundle_preserves_each_exact_source_byte_and_origin(checkout):
    root, policy = checkout
    builder = module()
    raw = encoded(policy)
    data = builder.bundle(raw, root)
    assert data == builder.bundle(raw, root)
    assert hashlib.sha256(raw).hexdigest().encode() in data
    assert b"No full NOTICE, copyright, native/source closure or redistribution clearance." in data
    assert b"synthetic-checkout" not in data
    for name, selection in builder.SELECTION.items():
        text = (root / f"docs/security/notices/{name}-{selection['version']}.LICENSE").read_bytes()
        assert len(text) == selection["bytes"]
        assert hashlib.sha256(text).hexdigest() == selection["sha256"]
        start = data.index(b"Verbatim source follows;", data.index(f"=== BEGIN {name} ".encode()))
        start = data.index(b"\n\n", start) + 2
        assert data[start : start + len(text)] == text
        assert data[start + len(text) :].startswith(f"\n=== END {name} ".encode())
        assert selection["commit"].encode() in data and selection["sha256"].encode() in data


@pytest.mark.parametrize("change", ["schema", "version", "commit", "hash", "origin", "outcome"])
def test_policy_drift_cannot_relabel_vendored_text(checkout, change):
    root, policy = checkout
    builder = module()
    selected = next(row for row in policy["distributions"] if row["name"] == "tokenizers")
    if change == "schema":
        policy["schema_version"] = 2
    elif change == "version":
        selected["version"] = "0.23.4"
    elif change == "commit":
        selected["upstream_evidence"]["commit"] = "0" * 40
    elif change == "hash":
        selected["upstream_evidence"]["sha256"] = "0" * 64
    elif change == "origin":
        selected["upstream_evidence"]["url"] = "https://unapproved.invalid/source"
    else:
        selected["outcome"] = "declared-and-shipped-text"
    with pytest.raises(builder.NoticeError, match="^NOTICE_(POLICY_REFUSED|SELECTION_MISMATCH)$"):
        builder.bundle(encoded(policy), root)


@pytest.mark.parametrize("change", ["missing", "duplicate", "third-missing"])
def test_exact_two_component_selection_cannot_silently_expand_or_shrink(checkout, change):
    root, policy = checkout
    builder = module()
    selected = next(row for row in policy["distributions"] if row["name"] == "flatbuffers")
    if change == "missing":
        policy["distributions"].remove(selected)
    elif change == "duplicate":
        policy["distributions"].append(copy.deepcopy(selected))
    else:
        row = copy.deepcopy(selected)
        row["name"] = "synthetic-third-component"
        policy["distributions"].append(row)
    with pytest.raises(builder.NoticeError, match="^NOTICE_(POLICY_REFUSED|SELECTION_MISMATCH)$"):
        builder.bundle(encoded(policy), root)


@pytest.mark.parametrize("change", ["bytes", "missing", "symlink", "directory", "oversize"])
def test_changed_missing_or_unsafe_source_cannot_produce_a_bundle(checkout, change):
    root, policy = checkout
    builder = module()
    source = root / "docs/security/notices/tokenizers-0.23.3.LICENSE"
    original = source.read_bytes()
    source.unlink()
    if change == "bytes":
        source.write_bytes(b"X" + original[1:])
    elif change == "symlink":
        target = root / "unselected-target"
        target.write_bytes(original)
        source.symlink_to(target)
    elif change == "directory":
        source.mkdir()
    elif change == "oversize":
        source.write_bytes(original + b" ")
    with pytest.raises(builder.NoticeError, match="^NOTICE_(INPUT_REFUSED|SOURCE_MISMATCH)$"):
        builder.bundle(encoded(policy), root)


def test_source_directory_symlink_is_not_followed(checkout):
    root, policy = checkout
    source = root / "docs/security/notices"
    relocated = source.with_name("relocated")
    source.rename(relocated)
    source.symlink_to(relocated, target_is_directory=True)
    builder = module()
    with pytest.raises(builder.NoticeError, match="^NOTICE_INPUT_REFUSED$"):
        builder.bundle(encoded(policy), root)


def test_actual_cli_generates_verifies_and_refuses_bundle_mutation(tmp_path):
    policy = ROOT / "docs/security/dependency-licences.json"
    output = tmp_path / "missing-wheel-notices.txt"
    generated = run_cli("generate", policy, output)
    assert generated.returncode == 0 and generated.stdout == b"NOTICE_SUPPLEMENT_GENERATED\n"
    assert generated.stderr == b""
    original = output.read_bytes()
    verified = run_cli("verify", policy, output)
    assert verified.returncode == 0 and verified.stdout == b"NOTICE_SUPPLEMENT_VERIFIED\n"
    assert verified.stderr == b"" and output.read_bytes() == original
    output.write_bytes(original + b"tamper")
    refused = run_cli("verify", policy, output)
    assert refused.returncode == 1 and refused.stderr == b"NOTICE_BUNDLE_MISMATCH\n"
    assert refused.stdout == b"" and output.read_bytes() == original + b"tamper"


@pytest.mark.parametrize("kind", ["existing", "symlink", "fifo"])
def test_actual_cli_never_overwrites_or_blocks_on_output(tmp_path, kind):
    policy = ROOT / "docs/security/dependency-licences.json"
    output = tmp_path / "synthetic-private-path-canary"
    target = tmp_path / "unrelated-target"
    target.write_bytes(b"synthetic private content canary")
    if kind == "existing":
        output.write_bytes(b"existing output canary")
    elif kind == "symlink":
        output.symlink_to(target)
    else:
        os.mkfifo(output, 0o600)
    result = run_cli("generate", policy, output)
    assert result.returncode == 1 and result.stderr == b"NOTICE_OUTPUT_REFUSED\n"
    assert result.stdout == b"" and target.read_bytes() == b"synthetic private content canary"
    if kind == "existing":
        assert output.read_bytes() == b"existing output canary"


def test_actual_cli_fifo_policy_is_bounded_and_sanitized(tmp_path):
    policy = tmp_path / "synthetic-private-policy-canary"
    os.mkfifo(policy, 0o600)
    output = tmp_path / "must-not-exist"
    result = run_cli("generate", policy, output)
    assert result.returncode == 1 and result.stderr == b"NOTICE_INPUT_REFUSED\n"
    assert result.stdout == b"" and not output.exists()


def test_duplicate_policy_json_keys_are_rejected(checkout):
    root, _ = checkout
    builder = module()
    with pytest.raises(builder.NoticeError, match="^NOTICE_POLICY_REFUSED$"):
        builder.bundle(b'{"schema_version":1,"schema_version":2,"distributions":[]}', root)


def test_actual_cli_refuses_fifo_source_before_creating_output(checkout, tmp_path):
    root, policy = checkout
    scripts = root / "scripts"
    scripts.mkdir()
    script = scripts / "build_notices.py"
    shutil.copyfile(ROOT / "scripts/build_notices.py", script)
    source = root / "docs/security/notices/flatbuffers-25.12.19.LICENSE"
    source.unlink()
    os.mkfifo(source, 0o600)
    policy_path = root / "policy.json"
    policy_path.write_bytes(encoded(policy))
    output = tmp_path / "must-not-exist"
    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "generate",
            "--policy",
            str(policy_path),
            "--output",
            str(output),
        ],
        capture_output=True,
        timeout=3,
        check=False,
    )
    assert result.returncode == 1 and result.stderr == b"NOTICE_INPUT_REFUSED\n"
    assert result.stdout == b"" and not output.exists()


def test_actual_cli_refuses_symlink_output_parent_without_writing_elsewhere(tmp_path):
    actual = tmp_path / "actual"
    actual.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(actual, target_is_directory=True)
    result = run_cli("generate", ROOT / "docs/security/dependency-licences.json", alias / "output")
    assert result.returncode == 1 and result.stderr == b"NOTICE_OUTPUT_REFUSED\n"
    assert result.stdout == b"" and list(actual.iterdir()) == []
