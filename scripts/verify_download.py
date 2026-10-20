"""Verify downloaded v3 build sets against a trusted main revision and run identity."""

import argparse
import itertools
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from build_evidence import FORMAT, MAX_INPUT_BYTES, MAX_MANIFEST, SUPPLEMENTS, read_regular

REPOSITORY = "rmednitzer/osint-workbench"
WORKFLOW = REPOSITORY + "/.github/workflows/ci.yml"
PROFILES = (("ubuntu-24.04", "3.12"), ("ubuntu-26.04", "3.14"))


class DownloadError(ValueError):
    pass


def require(condition, category="DOWNLOAD_SET_REFUSED"):
    if not condition:
        raise DownloadError(category)


def children(directory, maximum):
    require(not directory.is_symlink() and directory.is_dir())
    paths = list(itertools.islice(directory.iterdir(), maximum + 1))
    require(len(paths) <= maximum)
    return paths


def signature(path, bundle, source_sha, workdir):
    """Only the caller-owned snapshots enter the external verifier."""
    output = workdir / "verification.json"
    with output.open("wb") as stream:
        try:
            result = subprocess.run(
                [
                    "gh",
                    "attestation",
                    "verify",
                    str(path),
                    "--bundle",
                    str(bundle),
                    "--repo",
                    REPOSITORY,
                    "--signer-workflow",
                    WORKFLOW,
                    "--source-ref",
                    "refs/heads/main",
                    "--source-digest",
                    source_sha,
                    "--signer-digest",
                    source_sha,
                    "--deny-self-hosted-runners",
                    "--format",
                    "json",
                ],
                stdout=stream,
                stderr=subprocess.DEVNULL,
                timeout=60,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            raise DownloadError("DOWNLOAD_VERIFIER_UNAVAILABLE") from None
    require(result.returncode == 0, "DOWNLOAD_SIGNATURE_REFUSED")
    _, _, raw = read_regular(output, MAX_MANIFEST, collect=True)
    verified = json.loads(raw)
    require(isinstance(verified, list) and bool(verified), "DOWNLOAD_SIGNATURE_REFUSED")


def verify(evidence, bundle_directory, source_sha, run_id, run_attempt):
    require(hasattr(os, "O_NOFOLLOW"), "DOWNLOAD_PLATFORM_UNSUPPORTED")
    require(re.fullmatch(r"[0-9a-f]{40}", source_sha), "DOWNLOAD_EXPECTATION_REFUSED")
    require(re.fullmatch(r"[1-9][0-9]{0,23}", run_id), "DOWNLOAD_EXPECTATION_REFUSED")
    require(re.fullmatch(r"[1-9][0-9]{0,5}", run_attempt), "DOWNLOAD_EXPECTATION_REFUSED")
    require(not evidence.is_symlink() and not bundle_directory.is_symlink())
    expected_legs = {
        f"build-evidence-{os_name}-python{version}-{source_sha}" for os_name, version in PROFILES
    }
    require({path.name for path in children(evidence, 2)} == expected_legs)
    bundles = children(bundle_directory, 1)
    require(len(bundles) == 1)
    _, _, bundle_bytes = read_regular(bundles[0], MAX_MANIFEST, collect=True)
    with tempfile.TemporaryDirectory(prefix="ow-consumer-") as temporary:
        workdir = Path(temporary)
        bundle = workdir / "bundle.jsonl"
        bundle.write_bytes(bundle_bytes)
        for os_name, version in PROFILES:
            leg = evidence / f"build-evidence-{os_name}-python{version}-{source_sha}"
            directories = children(leg, 3)
            require({path.name for path in directories} == {"dist", "assurance", "build-evidence"})
            paths = [path for directory in directories for path in children(directory, 4)]
            require(not any(path.is_symlink() for path in paths))
            _, digest, raw = read_regular(
                leg / "build-evidence/manifest.json", MAX_MANIFEST, collect=True
            )
            snapshot = workdir / "manifest.json"
            snapshot.write_bytes(raw)
            signature(snapshot, bundle, source_sha, workdir)
            _, _, checksum = read_regular(leg / "build-evidence/manifest.sha256", 65, collect=True)
            require(checksum == (digest + "\n").encode(), "DOWNLOAD_DIGEST_MISMATCH")
            receipt = json.loads(raw)
            require(receipt["format"] == FORMAT)
            require(receipt["assurance_profile"] == "python-sbom-native-and-notices")
            require(receipt["source"]["commit"] == source_sha, "DOWNLOAD_SOURCE_MISMATCH")
            require(
                receipt["workflow"] == {"run_id": run_id, "run_attempt": run_attempt},
                "DOWNLOAD_RUN_MISMATCH",
            )
            runtime = receipt["runtime"]
            require(runtime["implementation"] == "CPython" and runtime["os"] == os_name)
            require(re.fullmatch(re.escape(version) + r"\.[0-9]{1,3}", runtime["python"]))
            artifacts, supplements = receipt["artifacts"], receipt["related_evidence"]
            require(isinstance(artifacts, list) and isinstance(supplements, list))
            require(len(artifacts) == 2 and len(supplements) == 4)
            require(
                all(
                    isinstance(item, dict) and isinstance(item.get("filename"), str)
                    for item in artifacts + supplements
                )
            )
            names = [item["filename"] for item in artifacts]
            require(sum(name.endswith(".whl") for name in names) == 1)
            require(sum(name.endswith(".tar.gz") for name in names) == 1)
            require({item["filename"] for item in supplements} == SUPPLEMENTS)
            expected = {"build-evidence/manifest.json", "build-evidence/manifest.sha256"}
            for directory, records, limit in [
                ("dist", artifacts, MAX_INPUT_BYTES),
                ("assurance", supplements, MAX_MANIFEST),
            ]:
                for item in records:
                    name = item["filename"]
                    require(
                        isinstance(name, str)
                        and Path(name).name == name
                        and re.fullmatch(r"[A-Za-z0-9._+-]+", name)
                    )
                    path = leg / directory / name
                    size, actual_digest, _ = read_regular(path, limit)
                    require(
                        size == item["bytes"] and actual_digest == item["sha256"],
                        "DOWNLOAD_DIGEST_MISMATCH",
                    )
                    expected.add(directory + "/" + name)
            require(
                {path.relative_to(leg).as_posix() for path in paths if path.is_file()} == expected
            )
    return {
        "status": "verified",
        "source": source_sha,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "profiles": len(PROFILES),
        "distributions": 4,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--bundle-directory", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    args = parser.parse_args()
    try:
        result = verify(
            args.evidence, args.bundle_directory, args.source_sha, args.run_id, args.run_attempt
        )
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        category = str(error) if isinstance(error, DownloadError) else "DOWNLOAD_INPUT_REFUSED"
        print(json.dumps({"status": "failed", "category": category}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
