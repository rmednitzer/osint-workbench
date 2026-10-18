import os
from pathlib import Path

import pytest


@pytest.fixture
def generated_reports(tmp_path, monkeypatch):
    root = Path(__file__).resolve().parents[1]
    monkeypatch.syspath_prepend(str(root / "scripts"))
    import build_notices
    import check_publication

    directory = tmp_path / "assurance"
    directory.mkdir()
    policy = (root / "docs/security/dependency-licences.json").read_bytes()
    (directory / "missing-wheel-notices.txt").write_bytes(build_notices.bundle(policy, root=root))
    for name in ("sbom.cdx.json", "licence-review.json", "native-review.json"):
        (directory / name).write_text("{}\n")
    return check_publication, directory


def test_generated_notice_urls_require_exact_provenance(generated_reports):
    module, directory = generated_reports
    assert module.scan_generated_evidence(directory) == []
    content = (directory / "missing-wheel-notices.txt").read_text()
    assert module.inspect_text("missing-wheel-notices.txt", content) == ["unclassified-url"]


def test_notice_substitution_cannot_disable_private_checks(generated_reports):
    module, directory = generated_reports
    canary = "synthetic-sensitive-notice-host"
    path = directory / "missing-wheel-notices.txt"
    with path.open("a") as stream:
        stream.write(canary)
    findings = module.scan_generated_evidence(directory, [canary])
    categories = {item["category"] for item in findings}
    assert {"notice-provenance-mismatch", "unclassified-url", "private-identifier"} <= categories
    assert canary not in str(findings)


@pytest.mark.parametrize(
    "case", ["missing", "extra", "symlink", "fifo", "oversize", "invalid-utf8"]
)
def test_generated_evidence_refuses_unselected_or_unsafe_inputs(generated_reports, case):
    module, directory = generated_reports
    path = directory / "native-review.json"
    if case == "missing":
        path.unlink()
    elif case == "extra":
        (directory / "unexpected.json").write_text("{}")
    elif case == "symlink":
        path.unlink()
        path.symlink_to(directory / "sbom.cdx.json")
    elif case == "fifo":
        path.unlink()
        os.mkfifo(path)
    elif case == "oversize":
        path.write_bytes(b"x" * (4 * 1024 * 1024 + 1))
    elif case == "invalid-utf8":
        path.write_bytes(b"\xff")
    assert module.scan_generated_evidence(directory)


def test_generated_receipts_are_scanned_for_private_values(generated_reports, tmp_path):
    module, _ = generated_reports
    directory = tmp_path / "build-evidence"
    directory.mkdir()
    canary = "synthetic-sensitive-receipt-host"
    (directory / "manifest.json").write_text('{"value":"' + canary + '"}')
    (directory / "manifest.sha256").write_text("a" * 64 + "\n")
    assert module.scan_generated_evidence(directory, [canary]) == [
        {"path": "manifest.json", "category": "private-identifier"}
    ]
