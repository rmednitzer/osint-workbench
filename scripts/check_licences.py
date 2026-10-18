"""Verify an exact, reviewed distribution inventory; never grant legal approval."""

import argparse
import hashlib
import importlib.metadata
import json
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath

MAX_BYTES = 4 * 1024 * 1024
OUTCOMES = {
    "declared-and-shipped-text",
    "reviewed-shipped-text",
    "declaration-only-missing-shipped-text",
    "upstream-only-missing-shipped-text",
}
NATIVE = {"unresolved-transitive-native-closure", "not-assessed-as-native-bundle"}


class ReviewError(Exception):
    pass


def read_regular(path):
    """Bound a final-component regular-file read; ancestors remain trusted."""
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ReviewError("LICENCE_INPUT_REFUSED")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ReviewError("LICENCE_INPUT_REFUSED")
        return data
    except OSError:
        raise ReviewError("LICENCE_INPUT_REFUSED") from None
    finally:
        if fd is not None:
            os.close(fd)


def normalize(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value):
        raise ReviewError("LICENCE_POLICY_REFUSED")
    return re.sub(r"[-_.]+", "-", value).lower()


def verify(policy, distributions):
    try:
        if policy["schema_version"] != 1 or isinstance(policy["schema_version"], bool):
            raise ReviewError("LICENCE_POLICY_REFUSED")
        rows = policy["distributions"]
        expected = {}
        for row in rows:
            name = normalize(row["name"])
            if name in expected or name != row["name"]:
                raise ReviewError("LICENCE_POLICY_REFUSED")
            if row["outcome"] not in OUTCOMES or row["native_bundle_review"] not in NATIVE:
                raise ReviewError("LICENCE_POLICY_REFUSED")
            if not isinstance(row["version"], str) or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9.!+_-]{0,127}", row["version"]
            ):
                raise ReviewError("LICENCE_POLICY_REFUSED")
            if row["outcome"] == "upstream-only-missing-shipped-text":
                proof = row["upstream_evidence"]
                if not re.fullmatch(r"[0-9a-f]{40}", proof["commit"]) or not re.fullmatch(
                    r"[0-9a-f]{64}", proof["sha256"]
                ):
                    raise ReviewError("LICENCE_POLICY_REFUSED")
            expected[name] = row
        actual = {}
        for dist in distributions:
            name = normalize(dist.metadata["Name"])
            if name in actual:
                raise ReviewError("LICENCE_INVENTORY_MISMATCH")
            actual[name] = dist
        if not expected or len(expected) > 256 or set(expected) != set(actual):
            raise ReviewError("LICENCE_INVENTORY_MISMATCH")
        report = []
        for name, row in sorted(expected.items()):
            dist = actual[name]
            if (
                dist.version != row["version"]
                or dist.metadata.get("License-Expression") != row["declared_expression"]
            ):
                raise ReviewError("LICENCE_METADATA_MISMATCH")
            # Require one COMPLETE reviewed evidence variant, never mix files from wheels.
            files = {str(f): f for f in dist.files or []}
            metadata_paths = {
                path
                for path in files
                if PurePosixPath(path).name == "METADATA"
                and PurePosixPath(path).parent.name.endswith(".dist-info")
            }
            if len(metadata_paths) != 1:
                raise ReviewError("LICENCE_EVIDENCE_MISMATCH")
            metadata_path = next(iter(metadata_paths))
            variants = row.get("evidence_variants", [{"evidence": row["evidence"]}])
            matched = False
            for variant in variants:
                evidence = variant["evidence"]
                metadata_entries = [e for e in evidence if e["kind"] == "metadata"]
                if (
                    len(metadata_entries) != 1
                    or metadata_entries[0]["path"] != metadata_path
                    or (
                        row["outcome"] in {"declared-and-shipped-text", "reviewed-shipped-text"}
                        and not any(e["kind"] == "licence-text" for e in evidence)
                    )
                ):
                    raise ReviewError("LICENCE_POLICY_REFUSED")
                ok = True
                seen = set()
                for item in evidence:
                    path = PurePosixPath(item["path"])
                    if path.is_absolute() or ".." in path.parts or str(path) in seen:
                        raise ReviewError("LICENCE_POLICY_REFUSED")
                    seen.add(str(path))
                    if str(path) == metadata_path and item["kind"] != "metadata":
                        raise ReviewError("LICENCE_POLICY_REFUSED")
                    if item["kind"] not in {"metadata", "licence-text"} or not re.fullmatch(
                        r"[0-9a-f]{64}", item["sha256"]
                    ):
                        raise ReviewError("LICENCE_POLICY_REFUSED")
                    if str(path) not in files:
                        ok = False
                        continue
                    data = read_regular(dist.locate_file(files[str(path)]))
                    if (
                        len(data) != item["bytes"]
                        or hashlib.sha256(data).hexdigest() != item["sha256"]
                    ):
                        ok = False
                matched |= ok
            if not matched:
                raise ReviewError("LICENCE_EVIDENCE_MISMATCH")
            report.append(
                {
                    "name": name,
                    "version": dist.version,
                    "outcome": row["outcome"],
                    "native_bundle_review": row["native_bundle_review"],
                }
            )
        return {
            "schema_version": 1,
            "legal_approval": False,
            "scope": "exact-installed-runtime-plus-retrieval-inventory",
            "distributions": report,
        }
    except (KeyError, TypeError, ValueError, AttributeError):
        raise ReviewError("LICENCE_POLICY_REFUSED") from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        raw = read_regular(args.policy)
        policy = json.loads(raw)
        report = verify(policy, importlib.metadata.distributions())
        report["policy_sha256"] = hashlib.sha256(raw).hexdigest()
        encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
        with args.output.open("xb") as stream:
            stream.write(encoded)
    except (ReviewError, OSError, ValueError, RecursionError) as exc:
        print(
            str(exc) if isinstance(exc, ReviewError) else "LICENCE_REVIEW_FAILED", file=sys.stderr
        )
        return 1
    print("LICENCE_REVIEW_ACCOUNTED_NOT_APPROVED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
