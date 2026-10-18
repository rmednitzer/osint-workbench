import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


def module():
    spec = importlib.util.spec_from_file_location(
        "check_licences", Path(__file__).resolve().parents[1] / "scripts/check_licences.py"
    )
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


@pytest.fixture
def fixture(tmp_path):
    metadata = tmp_path / "sample.dist-info" / "METADATA"
    metadata.parent.mkdir()
    metadata.write_bytes(b"public metadata")
    licence = metadata.parent / "LICENSE"
    licence.write_bytes(b"public licence")
    files = ["sample.dist-info/METADATA", "sample.dist-info/LICENSE"]
    dist = SimpleNamespace(
        metadata={
            "Name": "sample",
            "License-Expression": "MIT",
            "Author-email": "private@example.invalid",
        },
        version="1.0",
        files=files,
        locate_file=lambda f: tmp_path / f,
    )
    evidence = [
        {
            "path": f,
            "sha256": hashlib.sha256((tmp_path / f).read_bytes()).hexdigest(),
            "bytes": len((tmp_path / f).read_bytes()),
            "kind": "metadata" if f.endswith("METADATA") else "licence-text",
        }
        for f in files
    ]
    policy = {
        "schema_version": 1,
        "distributions": [
            {
                "name": "sample",
                "version": "1.0",
                "declared_expression": "MIT",
                "outcome": "declared-and-shipped-text",
                "native_bundle_review": "unresolved-transitive-native-closure",
                "evidence": evidence,
            }
        ],
    }
    return policy, dist


def test_exact_inventory_reports_no_approval_or_contact_data(fixture):
    policy, dist = fixture
    report = module().verify(policy, [dist])
    assert report["legal_approval"] is False
    assert report["distributions"][0]["native_bundle_review"].startswith("unresolved")
    assert "private" not in json.dumps(report)


@pytest.mark.parametrize(
    "change,code",
    [
        ("version", "METADATA"),
        ("expression", "METADATA"),
        ("hash", "EVIDENCE"),
        ("missing-file", "EVIDENCE"),
        ("extra-dist", "INVENTORY"),
        ("duplicate", "INVENTORY"),
        ("missing-dist", "INVENTORY"),
    ],
)
def test_changed_or_unaccounted_inputs_fail(fixture, change, code):
    policy, dist = fixture
    distributions = [dist]
    if change == "version":
        dist.version = "2.0"
    elif change == "expression":
        dist.metadata["License-Expression"] = "BSD-3-Clause"
    elif change == "hash":
        dist.locate_file(dist.files[0]).write_bytes(b"changed")
    elif change == "missing-file":
        dist.files.pop()
    elif change == "extra-dist":
        other = copy.copy(dist)
        other.metadata = {"Name": "unexpected"}
        distributions.append(other)
    elif change == "duplicate":
        distributions.append(dist)
    elif change == "missing-dist":
        distributions = []
    m = module()
    with pytest.raises(m.ReviewError, match="LICENCE_" + code + "_MISMATCH"):
        m.verify(policy, distributions)


def test_variant_must_match_as_whole(fixture):
    policy, dist = fixture
    row = policy["distributions"][0]
    first = copy.deepcopy(row["evidence"])
    second = copy.deepcopy(first)
    first[0]["sha256"] = "0" * 64
    second[1]["sha256"] = "0" * 64
    row["evidence_variants"] = [{"evidence": first}, {"evidence": second}]
    m = module()
    with pytest.raises(m.ReviewError, match="EVIDENCE_MISMATCH"):
        m.verify(policy, [dist])
    row["evidence_variants"].append({"evidence": row["evidence"]})
    assert m.verify(policy, [dist])["legal_approval"] is False


def test_missing_expression_and_text_remain_explicit(fixture):
    policy, dist = fixture
    row = policy["distributions"][0]
    row["declared_expression"] = None
    dist.metadata.pop("License-Expression")
    row["evidence"] = row["evidence"][:1]
    row["outcome"] = "declaration-only-missing-shipped-text"
    assert module().verify(policy, [dist])["distributions"][0]["outcome"] == row["outcome"]


@pytest.mark.parametrize("path", ["../outside", "/absolute"])
def test_unsafe_policy_paths_are_refused(fixture, path):
    policy, dist = fixture
    policy["distributions"][0]["evidence"][0]["path"] = path
    m = module()
    with pytest.raises(m.ReviewError, match="POLICY_REFUSED"):
        m.verify(policy, [dist])


def test_policy_read_refuses_symlink_and_fifo_without_blocking(tmp_path):
    import os

    m = module()
    original = tmp_path / "policy"
    original.write_text("{}")
    link = tmp_path / "link"
    link.symlink_to(original)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    for path in (link, fifo):
        with pytest.raises(m.ReviewError, match="INPUT_REFUSED"):
            m.read_regular(path)


def test_cli_refuses_overwrite_and_redacts_failures(fixture, monkeypatch, tmp_path, capsys):
    import sys

    policy, dist = fixture
    m = module()
    source = tmp_path / "policy.json"
    source.write_text(json.dumps(policy))
    output = tmp_path / "report.json"
    monkeypatch.setattr(m.importlib.metadata, "distributions", lambda: [dist])
    monkeypatch.setattr(sys, "argv", ["check", "--policy", str(source), "--output", str(output)])
    assert m.main() == 0
    original = output.read_bytes()
    assert m.main() == 1
    assert output.read_bytes() == original
    assert capsys.readouterr().err == "LICENCE_REVIEW_FAILED\n"
    output.unlink()
    dist.version = "private-path-secret"
    assert m.main() == 1
    assert not output.exists()
    assert capsys.readouterr().err == "LICENCE_METADATA_MISMATCH\n"


def test_upstream_only_requires_immutable_proof(fixture):
    policy, dist = fixture
    policy["distributions"][0]["outcome"] = "upstream-only-missing-shipped-text"
    m = module()
    with pytest.raises(m.ReviewError, match="POLICY_REFUSED"):
        m.verify(policy, [dist])


@pytest.mark.parametrize("outcome", ["declared-and-shipped-text", "reviewed-shipped-text"])
@pytest.mark.parametrize("stripped_kind", ["metadata", "licence-text"])
@pytest.mark.parametrize("use_variant", [False, True])
def test_shipped_outcomes_require_text_and_actual_metadata_in_every_variant(
    fixture, outcome, stripped_kind, use_variant
):
    policy, dist = fixture
    row = policy["distributions"][0]
    row["outcome"] = outcome
    stripped = [e for e in row["evidence"] if e["kind"] != stripped_kind]
    if use_variant:
        # A valid alternative does not excuse an invalid, supposedly complete variant.
        row["evidence_variants"] = [{"evidence": row["evidence"]}, {"evidence": stripped}]
    else:
        row["evidence"] = stripped
    m = module()
    with pytest.raises(m.ReviewError, match="LICENCE_POLICY_REFUSED"):
        m.verify(policy, [dist])


@pytest.mark.parametrize("change", ["relabel", "wrong-file", "duplicate"])
def test_metadata_evidence_cannot_be_substituted(fixture, change):
    policy, dist = fixture
    entries = policy["distributions"][0]["evidence"]
    if change == "relabel":
        entries[0]["kind"] = "licence-text"
    elif change == "wrong-file":
        entries[0], entries[1] = entries[1], entries[0]
        entries[0]["kind"] = "metadata"
        entries[1]["kind"] = "licence-text"
    else:
        entries.append(copy.deepcopy(entries[0]))
    m = module()
    with pytest.raises(m.ReviewError, match="LICENCE_POLICY_REFUSED"):
        m.verify(policy, [dist])
