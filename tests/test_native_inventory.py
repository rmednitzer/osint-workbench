import copy
import importlib.util
import json
import struct
from email.message import Message
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest


@pytest.fixture
def native(monkeypatch):
    scripts = Path(__file__).resolve().parents[1] / "scripts"
    monkeypatch.syspath_prepend(str(scripts))
    spec = importlib.util.spec_from_file_location("native_inventory", scripts / "check_native.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def elf_fixture(needed="libexample.so.1"):
    strings = b"\0" + needed.encode() + b"\0libfixture.so\0/private/operator-file\0"
    soname = 2 + len(needed)
    rpath = soname + len("libfixture.so") + 1
    dynamic_offset = 64 + 2 * 56
    string_offset = dynamic_offset + 6 * 16
    size = string_offset + len(strings)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header = ident + struct.pack("<HHIQQQIHHHHHH", 3, 62, 1, 0, 64, 0, 0, 64, 56, 2, 64, 0, 0)
    load = struct.pack("<IIQQQQQQ", 1, 4, 0, 4096, 4096, size, size, 4096)
    dynamic = struct.pack(
        "<IIQQQQQQ", 2, 4, dynamic_offset, 4096 + dynamic_offset, 4096 + dynamic_offset, 96, 96, 8
    )
    tags = [
        (5, 4096 + string_offset),
        (10, len(strings)),
        (1, 1),
        (14, soname),
        (15, rpath),
        (0, 0),
    ]
    return header + load + dynamic + b"".join(struct.pack("<QQ", *tag) for tag in tags) + strings


def test_real_elf_parser_projects_loader_names_without_rpath_or_execution(native, monkeypatch):
    monkeypatch.setattr(native.subprocess, "run", lambda *a, **kw: pytest.fail("no native tools"))
    result = native.extract_elf(elf_fixture())
    assert result == {
        "type": "ET_DYN",
        "machine": "EM_X86_64",
        "bits": 64,
        "needed": ["libexample.so.1"],
        "soname": "libfixture.so",
    }
    assert "private" not in str(result)


def test_truncated_and_unsafe_loader_names_fail_with_sanitized_categories(native):
    with pytest.raises(native.EvidenceError, match="ELF_INVALID"):
        native.extract_elf(elf_fixture()[:20])
    with pytest.raises(native.EvidenceError, match="METADATA_REFUSED"):
        native.extract_elf(elf_fixture("../private.so"))


def test_component_walk_refuses_directory_symlink_and_fifo(native, tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "file").write_bytes(elf_fixture())
    (root / "linked").symlink_to(outside, target_is_directory=True)
    with pytest.raises(OSError):
        native.open_record(root, "linked/file")
    native.os.mkfifo(root / "fifo")
    with pytest.raises(native.EvidenceError, match="NOT_REGULAR"):
        native.open_record(root, "fifo")


def test_fifo_replacement_before_open_cannot_block(native, monkeypatch, tmp_path):
    path = tmp_path / "file"
    path.write_bytes(b"original")
    original = native.os.open
    descriptors = []

    def replace(name, flags, **kwargs):
        if kwargs.get("dir_fd") is not None and not flags & native.os.O_DIRECTORY:
            assert flags & native.os.O_NONBLOCK
            path.unlink()
            native.os.mkfifo(path)
        descriptor = original(name, flags, **kwargs)
        descriptors.append(descriptor)
        return descriptor

    monkeypatch.setattr(native.os, "open", replace)
    with pytest.raises(native.EvidenceError, match="NOT_REGULAR"):
        native.open_record(tmp_path, "file")
    for descriptor in descriptors:
        with pytest.raises(OSError):
            native.os.fstat(descriptor)


def test_growing_file_read_is_cumulatively_bounded_and_closed(native, monkeypatch, tmp_path):
    path = tmp_path / "file"
    path.write_bytes(b"seed")
    original = native.os.read
    total = 0
    descriptors = []

    def grow(descriptor, count):
        nonlocal total
        with path.open("ab") as stream:
            stream.write(b"grow")
        block = original(descriptor, min(count, 3))
        total += len(block)
        descriptors.append(descriptor)
        return block

    monkeypatch.setattr(native.os, "read", grow)
    with pytest.raises(native.EvidenceError, match="INPUT_LIMIT"):
        native.read_record(tmp_path, "file", limit=8)
    assert total == 9
    with pytest.raises(OSError):
        native.os.fstat(descriptors[0])


def test_metadata_probe_does_not_import_target_modules_or_run_tools(
    native, monkeypatch, tmp_path, capsys
):
    package = tmp_path / "lib/site-packages"
    (package / "osint_workbench").mkdir(parents=True)
    module = package / "osint_workbench/native_fixture.py"
    module.write_text("raise AssertionError('must never be imported')\n")
    wheel = package / "osint_workbench-1.0.dist-info/WHEEL"
    wheel.parent.mkdir()
    wheel.write_text("Wheel-Version: 1.0\nTag: py3-none-any\n")
    metadata = Message()
    metadata["Name"] = "osint-workbench"
    dist = SimpleNamespace(
        metadata=metadata,
        version="1.0",
        files=[
            PurePosixPath("osint_workbench/native_fixture.py"),
            PurePosixPath("osint_workbench-1.0.dist-info/WHEEL"),
        ],
        locate_file=lambda item: package / item,
    )
    monkeypatch.setattr(native.sys, "prefix", str(tmp_path))
    monkeypatch.setattr(native.importlib.metadata, "distributions", lambda: [dist])
    monkeypatch.setattr(native.subprocess, "run", lambda *a, **kw: pytest.fail("no external tools"))
    native.probe()
    result = json.loads(capsys.readouterr().out)
    assert result["candidates"] == []
    assert result["wheel_tags"] == {"osint-workbench": ["py3-none-any"]}


def policy_inputs():
    first = {
        "path": "fixture/a.so",
        "bytes": 4,
        "sha256": "a" * 64,
        "elf": {
            "type": "ET_DYN",
            "machine": "EM_X86_64",
            "bits": 64,
            "needed": ["libc.so.6"],
            "soname": None,
        },
    }
    second = {**first, "path": "fixture/b.so", "sha256": "b" * 64}
    files = [first, second]
    native_variant = {
        "wheel_filename": "fixture-1.0-cp314-cp314-manylinux_2_28_x86_64.whl",
        "wheel_sha256": "c" * 64,
        "files": files,
    }
    other = {
        "wheel_filename": "fixture-1.0-cp312-cp312-manylinux_2_28_x86_64.whl",
        "wheel_sha256": "d" * 64,
        "files": [{**item, "sha256": "e" * 64} for item in files],
    }
    universal = {
        "wheel_filename": "fixture-1.0-py3-none-any.whl",
        "wheel_sha256": "f" * 64,
        "files": [],
    }
    policy = {
        "schema_version": 1,
        "distributions": [
            {"name": "fixture", "version": "1.0", "variants": [native_variant, other, universal]}
        ],
    }
    rows = [{"name": "fixture", "version": "1.0", "files": copy.deepcopy(files)}]
    tags = {"fixture": ["cp314-cp314-manylinux_2_28_x86_64"]}
    return rows, tags, policy


def test_review_matches_complete_native_set_and_genuine_universal_variant(native):
    rows, tags, policy = policy_inputs()
    result = native.match_policy(rows, tags, policy)
    assert result[0]["matched_variants"][0]["wheel_sha256"] == "c" * 64
    rows[0]["files"] = []
    tags["fixture"] = ["py3-none-any"]
    result = native.match_policy(rows, tags, policy)
    assert result[0]["matched_variants"][0]["wheel_sha256"] == "f" * 64


@pytest.mark.parametrize("change", ["omitted", "added", "hash", "mixed", "extra-tags"])
def test_native_set_or_tag_drift_fails_closed(native, change):
    rows, tags, policy = policy_inputs()
    if change == "omitted":
        rows[0]["files"] = []  # Native WHEEL tags must not match a universal empty proof.
    elif change == "added":
        rows[0]["files"].append({**rows[0]["files"][0], "path": "fixture/new.so"})
    elif change == "hash":
        rows[0]["files"][0]["sha256"] = "0" * 64
    elif change == "mixed":
        rows[0]["files"][1]["sha256"] = "e" * 64
    else:
        tags["fixture"].append("py3-none-any")
    with pytest.raises(native.EvidenceError, match="REVIEWED_SET_MISMATCH"):
        native.match_policy(rows, tags, policy)


def test_boolean_policy_version_is_not_an_integer_schema(native):
    rows, tags, policy = policy_inputs()
    policy["schema_version"] = True
    with pytest.raises(native.EvidenceError, match="POLICY_SCHEMA_REFUSED"):
        native.match_policy(rows, tags, policy)
