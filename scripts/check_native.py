"""Bounded offline review of RECORD-listed ELF files; no loader or native execution."""

import argparse
import hashlib
import importlib.metadata
import io
import json
import os
import platform
import re
import resource
import stat
import struct
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

from build_evidence import EvidenceError, checked, encoded, source_identity

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 256 * 1024 * 1024
MAX_JSON = 4 * 1024 * 1024
MAX_RECORDS = 50000
MAX_ELFS = 512


def basename(value):
    return checked(value, r"[A-Za-z0-9_][A-Za-z0-9._+-]{0,191}")


def relative(value):
    checked(value, r"[A-Za-z0-9_.+/-]{1,384}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in value.split("/")):
        raise EvidenceError("NATIVE_PATH_REFUSED")
    return value


def extract_elf(data):
    from elftools.common.exceptions import ELFError
    from elftools.construct.core import ConstructError
    from elftools.elf.elffile import ELFFile

    if len(data) > MAX_BYTES or not data.startswith(b"\x7fELF"):
        raise EvidenceError("NATIVE_ELF_REFUSED")
    try:
        elf = ELFFile(io.BytesIO(data))
        if elf.num_sections() > 16384:
            raise EvidenceError("NATIVE_SECTION_LIMIT")
        if elf.num_segments() > 256:
            raise EvidenceError("NATIVE_SEGMENT_LIMIT")
        needed = set()
        soname = None
        for segment in elf.iter_segments():
            if segment["p_type"] != "PT_DYNAMIC":
                continue
            for count, tag in enumerate(segment.iter_tags()):
                if count >= 4096:
                    raise EvidenceError("NATIVE_TAG_LIMIT")
                if tag.entry.d_tag == "DT_NEEDED":
                    needed.add(basename(tag.needed))
                elif tag.entry.d_tag == "DT_SONAME":
                    value = basename(tag.soname)
                    if soname is not None and soname != value:
                        raise EvidenceError("NATIVE_SONAME_AMBIGUOUS")
                    soname = value
        return {
            "type": checked(elf["e_type"], r"ET_[A-Z0-9_]{1,48}"),
            "machine": checked(elf["e_machine"], r"EM_[A-Z0-9_]{1,48}"),
            "bits": elf.elfclass,
            "needed": sorted(needed),
            "soname": soname,
        }
    except (
        ELFError,
        ConstructError,
        ValueError,
        KeyError,
        IndexError,
        TypeError,
        AttributeError,
        UnicodeError,
        RecursionError,
        struct.error,
        OverflowError,
    ) as error:
        if isinstance(error, EvidenceError):
            raise
        raise EvidenceError("NATIVE_ELF_INVALID") from None


def normalize(name):
    return re.sub(r"[-_.]+", "-", checked(name, r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")).lower()


def open_record(prefix, location):
    """Walk every component relative to a trusted prefix, refusing directory links."""
    parts = PurePosixPath(relative(location)).parts
    directory = os.open(prefix, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(
            parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
        )
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise EvidenceError("NATIVE_RECORD_NOT_REGULAR")
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor
    finally:
        os.close(directory)


def probe():
    # This mode is run by the target interpreter and uses only the standard library.
    from build_evidence import inventory

    prefix = Path(sys.prefix).absolute()
    candidates = []
    wheel_tags = {}
    count = 0
    for dist in importlib.metadata.distributions():
        name = normalize(dist.metadata["Name"])
        version = checked(dist.version, r"[A-Za-z0-9][A-Za-z0-9.!+_-]{0,127}")
        tags = []
        if dist.files is None:
            raise EvidenceError("NATIVE_RECORD_MISSING")
        for item in dist.files:
            count += 1
            if count > MAX_RECORDS:
                raise EvidenceError("NATIVE_RECORD_LIMIT")
            location = Path(os.path.abspath(dist.locate_file(item))).relative_to(prefix).as_posix()
            if str(item).endswith(".dist-info/WHEEL"):
                headers = read_record(prefix, location, limit=65536).decode("utf-8")
                tags.extend(
                    checked(line[4:].strip(), r"[A-Za-z0-9_.-]{1,256}")
                    for line in headers.splitlines()
                    if line.startswith("Tag:")
                )
                if len(tags) > 64:
                    raise EvidenceError("NATIVE_WHEEL_TAG_LIMIT")
            descriptor = open_record(prefix, location)
            try:
                magic = os.read(descriptor, 4)
            finally:
                os.close(descriptor)
            if magic == b"\x7fELF":
                candidates.append(
                    {
                        "name": name,
                        "version": version,
                        "path": relative(str(item)),
                        "location": location,
                    }
                )
                if len(candidates) > MAX_ELFS:
                    raise EvidenceError("NATIVE_ELF_LIMIT")
        if not tags:
            raise EvidenceError("NATIVE_WHEEL_TAG_MISSING")
        wheel_tags[name] = sorted(set(tags))
    release = platform.freedesktop_os_release()
    print(
        json.dumps(
            {
                "inventory": inventory(),
                "runtime": {
                    "python": platform.python_version(),
                    "implementation": platform.python_implementation(),
                    "os": release["ID"] + "-" + release["VERSION_ID"],
                },
                "prefix": str(prefix),
                "candidates": candidates,
                "wheel_tags": wheel_tags,
            }
        )
    )


def read_record(prefix, location, *, limit=MAX_BYTES):
    descriptor = open_record(prefix, location)
    try:
        before = os.fstat(descriptor)
        if before.st_size > limit:
            raise EvidenceError("NATIVE_INPUT_LIMIT")
        data = bytearray()
        while True:
            block = os.read(descriptor, min(1024 * 1024, limit - len(data) + 1))
            if not block:
                break
            data.extend(block)
            if len(data) > limit:
                raise EvidenceError("NATIVE_INPUT_LIMIT")
        after = os.fstat(descriptor)
        if len(data) != before.st_size or (before.st_size, before.st_mtime_ns) != (
            after.st_size,
            after.st_mtime_ns,
        ):
            raise EvidenceError("NATIVE_INPUT_CHANGED")
        return bytes(data)
    finally:
        os.close(descriptor)


def inspect_candidates(probe_data):
    rows = {}
    for item in probe_data["inventory"]["distributions"]:
        name = normalize(item["name"])
        if name in rows:
            raise EvidenceError("NATIVE_DISTRIBUTION_AMBIGUOUS")
        rows[name] = {"name": name, "version": item["version"], "files": []}
    for candidate in probe_data["candidates"]:
        data = read_record(probe_data["prefix"], candidate["location"])
        row = rows[candidate["name"]]
        if row["version"] != candidate["version"]:
            raise EvidenceError("NATIVE_DISTRIBUTION_MISMATCH")
        row["files"].append(
            {
                "path": relative(candidate["path"]),
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "elf": extract_elf(data),
            }
        )
    for row in rows.values():
        row["files"].sort(key=lambda item: item["path"])
        if len({item["path"] for item in row["files"]}) != len(row["files"]):
            raise EvidenceError("NATIVE_FILE_AMBIGUOUS")
    return sorted(rows.values(), key=lambda item: item["name"])


def limits():
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_JSON, MAX_JSON))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    resource.setrlimit(resource.RLIMIT_AS, (1536 * 1024 * 1024, 1536 * 1024 * 1024))


def run_worker(python, expression, arguments, output):
    with output.open("xb") as stream:
        subprocess.run(
            [
                str(python),
                "-I",
                "-c",
                "import sys; sys.path.insert(0,sys.argv[1]); " + expression,
                str(ROOT / "scripts"),
                *arguments,
            ],
            cwd=ROOT,
            stdout=stream,
            stderr=subprocess.DEVNULL,
            timeout=90,
            check=True,
            env={"PATH": os.defpath, "PYTHONNOUSERSITE": "1", "LC_ALL": "C.UTF-8"},
            preexec_fn=limits,
        )


def parse_worker(path):
    from build_evidence import read_regular

    _, _, data = read_regular(Path(path), MAX_JSON, collect=True)
    result = inspect_candidates(json.loads(data))
    public = encoded(result)
    if len(public) > MAX_JSON:
        raise EvidenceError("NATIVE_OUTPUT_LIMIT")
    sys.stdout.buffer.write(public)


def match_policy(rows, wheel_tags, policy):
    from packaging.tags import parse_tag
    from packaging.utils import parse_wheel_filename

    if type(policy.get("schema_version")) is not int or policy["schema_version"] != 1:
        raise EvidenceError("NATIVE_POLICY_SCHEMA_REFUSED")
    expected = {}
    for item in policy["distributions"]:
        name = normalize(item["name"])
        if name in expected:
            raise EvidenceError("NATIVE_POLICY_AMBIGUOUS")
        expected[name] = item
    if set(expected) != {row["name"] for row in rows} or set(wheel_tags) != set(expected):
        raise EvidenceError("NATIVE_POLICY_INVENTORY_MISMATCH")
    result = []
    for row in rows:
        entry = expected[row["name"]]
        if entry["version"] != row["version"]:
            raise EvidenceError("NATIVE_POLICY_VERSION_MISMATCH")
        installed_tags = set()
        for tag in wheel_tags[row["name"]]:
            installed_tags.update(parse_tag(checked(tag, r"[A-Za-z0-9_.-]{1,256}")))
        matches = []
        for variant in entry["variants"]:
            filename = checked(
                variant["wheel_filename"], r"[A-Za-z0-9_][A-Za-z0-9_.+-]{1,510}\.whl"
            )
            name, version, _, tags = parse_wheel_filename(filename)
            checked(variant["wheel_sha256"], r"[0-9a-f]{64}")
            if normalize(name) != row["name"] or str(version) != row["version"]:
                raise EvidenceError("NATIVE_PROOF_IDENTITY_MISMATCH")
            if installed_tags == tags and variant["files"] == row["files"]:
                matches.append(
                    {"wheel_filename": filename, "wheel_sha256": variant["wheel_sha256"]}
                )
        if not matches:
            raise EvidenceError("NATIVE_REVIEWED_SET_MISMATCH")
        result.append(
            {
                **row,
                "matched_variants": sorted(matches, key=lambda item: item["wheel_filename"]),
                "native_dependency_closure": "not-established",
            }
        )
    return result


def generate_report(python, receipt, policy_path, temporary):
    from build_evidence import read_regular
    from check_sbom import binding, load_json

    core = binding(receipt)
    probe_path = temporary / "probe.json"
    run_worker(python, "from check_native import probe; probe()", [], probe_path)
    probe_data = load_json(probe_path)
    if probe_data["inventory"] != core["inventory"] or probe_data["runtime"] != core["runtime"]:
        raise EvidenceError("NATIVE_TARGET_MISMATCH")
    result_path = temporary / "parsed.json"
    run_worker(
        Path(sys.executable),
        "from check_native import parse_worker; parse_worker(sys.argv[2])",
        [str(probe_path)],
        result_path,
    )
    rows = load_json(result_path)
    _, policy_hash, policy_bytes = read_regular(policy_path, MAX_JSON, collect=True)
    policy = json.loads(policy_bytes)
    _, _, lock_bytes = read_regular(ROOT / "uv.lock", MAX_JSON, collect=True)
    if policy["lock_sha256"] != hashlib.sha256(lock_bytes).hexdigest():
        raise EvidenceError("NATIVE_POLICY_LOCK_MISMATCH")
    result = {
        "schema_version": 1,
        "scope": "record-listed-elf-files",
        "binding_sha256": hashlib.sha256(encoded(core)).hexdigest(),
        "policy_sha256": policy_hash,
        "tool": {"name": "pyelftools", "version": importlib.metadata.version("pyelftools")},
        "distributions": match_policy(rows, probe_data["wheel_tags"], policy),
        "loader_resolution": "not-performed",
        "legal_approval": False,
        "native_dependency_closure": "not-established",
    }
    if len(encoded(result)) > MAX_JSON:
        raise EvidenceError("NATIVE_OUTPUT_LIMIT")
    return result


def main():
    from check_sbom import load_json

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("generate", "verify"))
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        receipt = load_json(args.manifest)
        source_identity(
            ROOT,
            {
                "OW_EVIDENCE_COMMIT": receipt["source"]["commit"],
                "OW_EVIDENCE_TREE": receipt["source"]["tree"],
            },
        )
        with tempfile.TemporaryDirectory(prefix="ow-native-") as temporary:
            report = generate_report(args.python.absolute(), receipt, args.policy, Path(temporary))
        if args.action == "generate":
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("xb") as stream:
                stream.write(encoded(report))
        elif encoded(load_json(args.output)) != encoded(report):
            raise EvidenceError("NATIVE_REPORT_MISMATCH")
    except (
        EvidenceError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        RecursionError,
        subprocess.SubprocessError,
    ) as error:
        category = str(error) if isinstance(error, EvidenceError) else "NATIVE_OPERATION_FAILED"
        print(json.dumps({"status": "failed", "category": category}))
        return 1
    print(
        json.dumps(
            {
                "status": "generated" if args.action == "generate" else "verified",
                "elf_files": sum(len(row["files"]) for row in report["distributions"]),
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
