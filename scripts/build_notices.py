"""Offline exact upstream text supplement; not complete redistribution clearance."""

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
MAX_POLICY_BYTES = 4 * 1024 * 1024
MAX_BUNDLE_BYTES = 64 * 1024
SELECTION = {
    "flatbuffers": {
        "version": "25.12.19",
        "repo": "google/flatbuffers",
        "tag": "v25.12.19",
        "commit": "7e163021e59cca4f8e1e35a7c828b5c6b7915953",
        "path": "LICENSE",
        "sha256": "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
        "bytes": 11358,
    },
    "tokenizers": {
        "version": "0.23.3",
        "repo": "huggingface/tokenizers",
        "tag": "v0.23.3",
        "commit": "301277072263fb3830eb66eec7e47adadf76f1dc",
        "path": "LICENSE",
        "sha256": "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4",
        "bytes": 11357,
    },
}


class NoticeError(ValueError):
    pass


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise NoticeError("NOTICE_POLICY_REFUSED")
        result[key] = value
    return result


def _directory(path):
    # The build checkout/operator is trusted. Refuse component symlinks rather
    # than silently reading/writing outside the selected directory tree.
    path = Path(path)
    if ".." in path.parts:
        raise NoticeError("NOTICE_INPUT_REFUSED")
    path = path.absolute()
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        for part in path.parts[1:]:
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd
            )
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_regular(path, maximum):
    directory = fd = None
    try:
        path = Path(path)
        directory = _directory(path.parent)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= maximum:
            raise NoticeError("NOTICE_INPUT_REFUSED")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(maximum + 1)
            after = os.fstat(fd)

        def identity(info):
            return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

        if len(data) != before.st_size or identity(before) != identity(after):
            raise NoticeError("NOTICE_INPUT_REFUSED")
        return data
    except OSError:
        raise NoticeError("NOTICE_INPUT_REFUSED") from None
    finally:
        if fd is not None:
            os.close(fd)
        if directory is not None:
            os.close(directory)


def _selection(policy):
    try:
        if type(policy["schema_version"]) is not int or policy["schema_version"] != 1:
            raise NoticeError("NOTICE_POLICY_REFUSED")
        rows = policy["distributions"]
        if not isinstance(rows, list) or not 1 <= len(rows) <= 256:
            raise NoticeError("NOTICE_POLICY_REFUSED")
        names = set()
        selected = {}
        for row in rows:
            name = row["name"]
            if not isinstance(name, str) or name in names:
                raise NoticeError("NOTICE_POLICY_REFUSED")
            names.add(name)
            missing = row["outcome"] in {
                "upstream-only-missing-shipped-text",
                "declaration-only-missing-shipped-text",
            }
            if missing != (name in SELECTION):
                raise NoticeError("NOTICE_SELECTION_MISMATCH")
            if name not in SELECTION:
                continue
            expected = SELECTION[name]
            proof = {
                key: value for key, value in expected.items() if key not in {"version", "bytes"}
            }
            actual_proof = dict(row["upstream_evidence"])
            public_url = actual_proof.pop("url")
            origin = urlsplit(public_url)
            if (
                origin.geturl() != public_url
                or origin.scheme != "https"
                or origin.netloc != "github.com"
                or origin.path
                != f"/{expected['repo']}/blob/{expected['commit']}/{expected['path']}"
                or origin.query
                or origin.fragment
            ):
                raise NoticeError("NOTICE_SELECTION_MISMATCH")
            if (
                row["version"] != expected["version"]
                or row["outcome"] != "upstream-only-missing-shipped-text"
                or actual_proof != proof
                or not isinstance(row["evidence"], list)
                or not row["evidence"]
                or any(item["kind"] != "metadata" for item in row["evidence"])
            ):
                raise NoticeError("NOTICE_SELECTION_MISMATCH")
            selected[name] = expected
        if set(selected) != set(SELECTION):
            raise NoticeError("NOTICE_SELECTION_MISMATCH")
        return selected
    except NoticeError:
        raise
    except (KeyError, TypeError, AttributeError, ValueError):
        raise NoticeError("NOTICE_POLICY_REFUSED") from None


def bundle(policy_raw, root=ROOT):
    if not isinstance(policy_raw, bytes) or not 1 <= len(policy_raw) <= MAX_POLICY_BYTES:
        raise NoticeError("NOTICE_POLICY_REFUSED")
    try:
        policy = json.loads(policy_raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (ValueError, UnicodeError, RecursionError):
        raise NoticeError("NOTICE_POLICY_REFUSED") from None
    selected = _selection(policy)
    chunks = [
        b"OSINT Workbench supplementary upstream licence texts (format 1)\n"
        b"Scope: flatbuffers 25.12.19 and tokenizers 0.23.3 only.\n"
        b"Reviewed wheels omit these texts; the supplement does not modify those wheels.\n"
        b"No full NOTICE, copyright, native/source closure or redistribution clearance.\n",
        f"Policy SHA-256: {hashlib.sha256(policy_raw).hexdigest()}\n".encode(),
    ]
    for name, expected in sorted(selected.items()):
        source = Path(root) / "docs/security/notices" / f"{name}-{expected['version']}.LICENSE"
        data = read_regular(source, expected["bytes"])
        if len(data) != expected["bytes"] or hashlib.sha256(data).hexdigest() != expected["sha256"]:
            raise NoticeError("NOTICE_SOURCE_MISMATCH")
        chunks.append(
            (
                f"\n=== BEGIN {name} {expected['version']} upstream LICENSE ===\n"
                f"Origin repository: {expected['repo']}\n"
                f"Release tag: {expected['tag']}\n"
                f"Immutable commit: {expected['commit']}\n"
                f"Upstream path: {expected['path']}\n"
                f"Source SHA-256: {expected['sha256']}\n"
                f"Source bytes: {expected['bytes']}\n"
                "Verbatim source follows; separator newline is outside the source bytes.\n\n"
            ).encode()
        )
        chunks.append(data)
        chunks.append(f"\n=== END {name} {expected['version']} upstream LICENSE ===\n".encode())
    return b"".join(chunks)


def generate(output, data):
    if not isinstance(data, bytes) or not 1 <= len(data) <= MAX_BUNDLE_BYTES:
        raise NoticeError("NOTICE_OUTPUT_REFUSED")
    directory = fd = None
    try:
        output = Path(output)
        directory = _directory(output.parent)
        fd = os.open(
            output.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o644,
            dir_fd=directory,
        )
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
        os.fsync(directory)
    except OSError:
        # Never unlink a possibly replaced output on failure. It must verify
        # before the caller may accept it as build evidence.
        raise NoticeError("NOTICE_OUTPUT_REFUSED") from None
    finally:
        if fd is not None:
            os.close(fd)
        if directory is not None:
            os.close(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["generate", "verify"])
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        expected = bundle(read_regular(args.policy, MAX_POLICY_BYTES))
        if args.operation == "generate":
            generate(args.output, expected)
        elif read_regular(args.output, MAX_BUNDLE_BYTES) != expected:
            raise NoticeError("NOTICE_BUNDLE_MISMATCH")
    except (NoticeError, OSError, ValueError, RecursionError) as exc:
        print(str(exc) if isinstance(exc, NoticeError) else "NOTICE_BUILD_FAILED", file=sys.stderr)
        return 1
    print(
        "NOTICE_SUPPLEMENT_GENERATED"
        if args.operation == "generate"
        else "NOTICE_SUPPLEMENT_VERIFIED"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
