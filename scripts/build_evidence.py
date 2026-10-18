"""Offline, bounded build integrity and installed dependency inventory; not an SBOM."""

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import stat
import subprocess
import sys
from pathlib import Path

FORMAT = "osint-workbench-build-evidence-v1"
MAX_MANIFEST = 4 * 1024 * 1024
MAX_PACKAGES = 512


class EvidenceError(ValueError):
    pass


def checked(value, pattern):
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        raise EvidenceError("EVIDENCE_METADATA_REFUSED")
    return value


def source_identity(root, environ):
    expected = {
        key: checked(environ.get("OW_EVIDENCE_" + key.upper()), r"[0-9a-f]{40}")
        for key in ("commit", "tree")
    }
    actual = subprocess.check_output(
        ["git", "rev-parse", "HEAD", "HEAD^{tree}"], cwd=root, text=True, stderr=subprocess.DEVNULL
    ).splitlines()
    dirty = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=root,
        text=True,
        stderr=subprocess.DEVNULL,
    )
    if actual != [expected["commit"], expected["tree"]] or dirty:
        raise EvidenceError("EVIDENCE_SOURCE_MISMATCH")
    return expected


def runtime_identity(environ):
    version = checked(environ.get("OW_EVIDENCE_PYTHON"), r"3\.[0-9]{1,2}")
    release = checked(environ.get("OW_EVIDENCE_OS"), r"ubuntu-(24|26)\.04")
    if platform.python_implementation() != "CPython" or version != (
        f"{sys.version_info.major}.{sys.version_info.minor}"
    ):
        raise EvidenceError("EVIDENCE_RUNTIME_MISMATCH")
    os_release = platform.freedesktop_os_release()
    if os_release.get("ID") != "ubuntu" or "ubuntu-" + os_release.get("VERSION_ID", "") != release:
        raise EvidenceError("EVIDENCE_OS_MISMATCH")
    return {"implementation": "CPython", "python": platform.python_version(), "os": release}


def inventory(distributions=None):
    rows = []
    unresolved = []
    for dist in importlib.metadata.distributions() if distributions is None else distributions:
        metadata = dist.metadata
        name = checked(metadata.get("Name"), r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
        version = checked(dist.version, r"[A-Za-z0-9][A-Za-z0-9.!+_-]{0,127}")
        expression = metadata.get("License-Expression")
        if expression is not None:
            expression = checked(expression, r"[A-Za-z0-9][A-Za-z0-9.():+ _-]{0,511}")
        classifiers = [
            checked(item, r"License :: [A-Za-z0-9.():+ /_-]{1,240}")
            for item in metadata.get_all("Classifier", [])
            if item.startswith("License :: ")
        ]
        rows.append(
            {
                "name": name,
                "version": version,
                "declared_license_expression": expression,
                "declared_license_classifiers": sorted(set(classifiers)),
            }
        )
        if expression is None:
            unresolved.append({"name": name, "reason": "missing-declared-license-expression"})
        if len(rows) > MAX_PACKAGES:
            raise EvidenceError("EVIDENCE_INVENTORY_LIMIT")
    rows.sort(key=lambda item: item["name"].lower())
    normalized = [re.sub(r"[-_.]+", "-", item["name"]).lower() for item in rows]
    if len(set(normalized)) != len(rows) or "osint-workbench" not in normalized:
        raise EvidenceError("EVIDENCE_INVENTORY_AMBIGUOUS")
    return {
        "distributions": rows,
        "unresolved_license_expressions": sorted(unresolved, key=lambda item: item["name"].lower()),
    }


def file_identity(path):
    if path.is_symlink() or not path.is_file():
        raise EvidenceError("EVIDENCE_INPUT_REFUSED")
    hasher = hashlib.sha256()
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > 256 * 1024 * 1024:
            raise EvidenceError("EVIDENCE_INPUT_REFUSED")
        while block := stream.read(1024 * 1024):
            hasher.update(block)
        after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise EvidenceError("EVIDENCE_INPUT_CHANGED")
    return {"filename": path.name, "bytes": before.st_size, "sha256": hasher.hexdigest()}


def artifact_inventory(directory):
    paths = sorted(path for path in directory.iterdir() if path.name != ".gitignore")
    if (
        len(paths) != 2
        or not any(path.name.endswith(".whl") for path in paths)
        or not any(path.name.endswith(".tar.gz") for path in paths)
    ):
        raise EvidenceError("EVIDENCE_ARTIFACT_SET_REFUSED")
    if any(
        re.fullmatch(r"osint_workbench-[A-Za-z0-9._+-]+\.(whl|tar\.gz)", p.name) is None
        for p in paths
    ):
        raise EvidenceError("EVIDENCE_ARTIFACT_NAME_REFUSED")
    return [file_identity(path) for path in paths]


def manifest(root, artifacts, lock, environ):
    if lock.name != "uv.lock":
        raise EvidenceError("EVIDENCE_LOCK_REFUSED")
    return {
        "format": FORMAT,
        "source": source_identity(root, environ),
        "runtime": runtime_identity(environ),
        "workflow": {
            "run_id": checked(environ.get("OW_EVIDENCE_RUN_ID"), r"[1-9][0-9]{0,23}"),
            "run_attempt": checked(environ.get("OW_EVIDENCE_RUN_ATTEMPT"), r"[1-9][0-9]{0,5}"),
        },
        "artifacts": artifact_inventory(artifacts),
        "lock": file_identity(lock),
        "inventory": inventory(),
        "inventory_scope": (
            "All installed distributions in a caller-prepared runtime+retrieval environment"
        ),
        "limitations": [
            "Integrity receipt, not a signature, attestation, or standards-conformant SBOM",
            "License metadata is publisher-declared and is not a reviewed legal disposition",
            "License expressions are recorded without SPDX syntax or identifier validation",
            "Inventory scope depends on the caller preparing the documented isolated environment",
        ],
    }


def encoded(document):
    return (json.dumps(document, sort_keys=True, indent=2) + "\n").encode()


def write_evidence(document, output):
    data = encoded(document)
    if len(data) > MAX_MANIFEST:
        raise EvidenceError("EVIDENCE_MANIFEST_LIMIT")
    output.mkdir(parents=True, exist_ok=False)
    (output / "manifest.json").write_bytes(data)
    (output / "manifest.sha256").write_text(hashlib.sha256(data).hexdigest() + "\n")


def verify_evidence(expected, output):
    path = output / "manifest.json"
    if path.is_symlink() or path.stat().st_size > MAX_MANIFEST:
        raise EvidenceError("EVIDENCE_MANIFEST_REFUSED")
    data = path.read_bytes()
    checksum = output / "manifest.sha256"
    if checksum.is_symlink() or checksum.stat().st_size != 65:
        raise EvidenceError("EVIDENCE_CHECKSUM_REFUSED")
    if checksum.read_text() != hashlib.sha256(data).hexdigest() + "\n" or data != encoded(expected):
        raise EvidenceError("EVIDENCE_INTEGRITY_MISMATCH")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("generate", "verify"))
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--lock", type=Path, default=Path("uv.lock"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        document = manifest(Path.cwd(), args.artifacts, args.lock, os.environ)
        if args.action == "generate":
            write_evidence(document, args.output)
        else:
            verify_evidence(document, args.output)
    except (EvidenceError, OSError, subprocess.SubprocessError) as error:
        category = str(error) if isinstance(error, EvidenceError) else "EVIDENCE_OPERATION_FAILED"
        print(json.dumps({"status": "failed", "category": category}))
        return 1
    print(
        json.dumps(
            {
                "status": "verified" if args.action == "verify" else "generated",
                "distributions": len(document["inventory"]["distributions"]),
                "unresolved_license_expressions": len(
                    document["inventory"]["unresolved_license_expressions"]
                ),
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
