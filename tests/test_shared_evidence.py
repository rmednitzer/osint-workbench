"""Opt-in read sharing never converts private retained objects or directory custody."""

import os
import stat

import pytest

from osint_workbench.errors import WorkbenchError
from osint_workbench.evidence import EvidenceStore
from osint_workbench.text import digest


def provision(path):
    path.mkdir()
    path.chmod(0o2750)
    return path


def test_shared_creation_survives_private_umask_and_replay(tmp_path):
    root = provision(tmp_path / "shared")
    before = os.umask(0o077)
    try:
        store = EvidenceStore(root, shared_group=os.getegid())
        sha = store.put(b"synthetic shared evidence")
        assert store.put(b"synthetic shared evidence") == sha
    finally:
        os.umask(before)
    directory, target = root / sha[:2], root / sha[:2] / sha
    assert stat.S_IMODE(directory.stat().st_mode) == 0o750
    assert stat.S_IMODE(target.stat().st_mode) == 0o640
    assert directory.stat().st_gid == target.stat().st_gid == os.getegid()
    assert target.stat().st_nlink == 1
    assert EvidenceStore(root, read_only=True).get(sha) == b"synthetic shared evidence"
    with pytest.raises(WorkbenchError, match="READ_ONLY_STORE"):
        EvidenceStore(root, read_only=True).put(b"forbidden")


def test_default_stays_private(tmp_path):
    store = EvidenceStore(tmp_path / "private")
    sha = store.put(b"private remains private")
    assert stat.S_IMODE(store.root.stat().st_mode) == 0o700
    assert stat.S_IMODE((store.root / sha[:2]).stat().st_mode) == 0o700
    assert stat.S_IMODE((store.root / sha[:2] / sha).stat().st_mode) == 0o600


@pytest.mark.parametrize("mode", [0o700, 0o770, 0o2755, 0o2770, 0o4750])
def test_shared_root_refuses_unsafe_custody_without_chmod(tmp_path, mode):
    root = provision(tmp_path / "root")
    root.chmod(mode)
    with pytest.raises(WorkbenchError, match="EVIDENCE_SHARED_CUSTODY_UNSAFE"):
        EvidenceStore(root, shared_group=os.getegid())
    assert stat.S_IMODE(root.stat().st_mode) == mode


@pytest.mark.parametrize("group", [True, False, -1, 2**32 - 1, "0"])
def test_invalid_group_refused_before_creating_paths(tmp_path, group):
    root = tmp_path / "absent"
    with pytest.raises(WorkbenchError, match="EVIDENCE_SHARED_CUSTODY_UNSAFE"):
        EvidenceStore(root, shared_group=group)
    assert not root.exists()


def test_missing_root_and_read_only_group_profile_refused(tmp_path):
    with pytest.raises(WorkbenchError, match="EVIDENCE_SHARED_CUSTODY_UNSAFE"):
        EvidenceStore(tmp_path / "absent", shared_group=os.getegid())
    root = provision(tmp_path / "root")
    with pytest.raises(WorkbenchError, match="EVIDENCE_SHARED_CUSTODY_UNSAFE"):
        EvidenceStore(root, read_only=True, shared_group=os.getegid())


def test_existing_private_child_and_object_never_widen(tmp_path):
    root = provision(tmp_path / "shared")
    data = b"retained private bytes"
    sha = digest(data)
    child = root / sha[:2]
    child.mkdir(mode=0o700)
    child.chmod(0o700)
    store = EvidenceStore(root, shared_group=os.getegid())
    with pytest.raises(WorkbenchError, match="EVIDENCE_SHARED_CUSTODY_UNSAFE"):
        store.put(data)
    assert stat.S_IMODE(child.stat().st_mode) == 0o700
    child.chmod(0o2750)  # Explicit test operator provisioning, never helper conversion.
    target = child / sha
    target.write_bytes(data)
    target.chmod(0o600)
    with pytest.raises(WorkbenchError, match="EVIDENCE_SHARED_CUSTODY_UNSAFE"):
        store.put(data)
    assert target.read_bytes() == data and stat.S_IMODE(target.stat().st_mode) == 0o600
    assert list(child.iterdir()) == [target]


def test_replaced_root_and_symlink_ancestor_refused(tmp_path):
    root = provision(tmp_path / "shared")
    store = EvidenceStore(root, shared_group=os.getegid())
    root.rename(tmp_path / "original")
    provision(root)
    with pytest.raises(WorkbenchError, match="EVIDENCE_SHARED_CUSTODY_UNSAFE"):
        store.put(b"replacement tree")
    container = tmp_path / "container"
    container.mkdir()
    provision(container / "objects")
    (tmp_path / "alias").symlink_to(container, target_is_directory=True)
    with pytest.raises(WorkbenchError, match="EVIDENCE_SHARED_CUSTODY_UNSAFE"):
        EvidenceStore(tmp_path / "alias/objects", shared_group=os.getegid())


def test_changed_child_permissions_refused_on_next_operation(tmp_path):
    root = provision(tmp_path / "shared")
    store = EvidenceStore(root, shared_group=os.getegid())
    sha = store.put(b"immutable bytes")
    (root / sha[:2]).chmod(0o2770)
    with pytest.raises(WorkbenchError, match="EVIDENCE_SHARED_CUSTODY_UNSAFE"):
        store.get(sha)
    assert stat.S_IMODE((root / sha[:2]).stat().st_mode) == 0o2770


@pytest.mark.parametrize("attribute", ["system.posix_acl_access", "system.posix_acl_default"])
def test_shared_root_refuses_actual_named_linux_acl(tmp_path, attribute):
    import struct

    root = provision(tmp_path / "named-acl")
    # Linux POSIX ACL xattr version 2: an explicit named entry survives the
    # otherwise expected 2750 mode. Use a mapped UID even inside a user namespace;
    # all extended ACLs are refused, including redundant owner entries.
    entries = [
        (1, 7, 0xFFFFFFFF),
        (2, 4, os.geteuid()),
        (4, 5, 0xFFFFFFFF),
        (16, 5, 0xFFFFFFFF),
        (32, 0, 0xFFFFFFFF),
    ]
    value = struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *row) for row in entries)
    os.setxattr(root, attribute, value)
    root.chmod(0o2750)
    assert os.getxattr(root, attribute) == value
    with pytest.raises(WorkbenchError, match="EVIDENCE_SHARED_CUSTODY_UNSAFE"):
        EvidenceStore(root, shared_group=os.getegid())
    assert os.getxattr(root, attribute) == value  # No attempted ACL repair.


def test_write_failure_keeps_staging_private_and_never_publishes(tmp_path, monkeypatch):
    root = provision(tmp_path / "shared")
    store = EvidenceStore(root, shared_group=os.getegid())
    data = b"synthetic interrupted write"
    sha = digest(data)
    original = os.fdopen
    observations = []

    class RefuseWrite:
        def __init__(self, fd):
            self.fd = fd

        def __enter__(self):
            return self

        def __exit__(self, *args):
            os.close(self.fd)

        def write(self, value):
            observations.append(stat.S_IMODE(os.fstat(self.fd).st_mode))
            raise OSError("synthetic write refusal")

    def fdopen(fd, mode):
        return RefuseWrite(fd) if mode == "wb" else original(fd, mode)

    monkeypatch.setattr(os, "fdopen", fdopen)
    with pytest.raises(OSError, match="synthetic write refusal"):
        store.put(data)
    assert observations == [0o600]
    assert not (root / sha[:2] / sha).exists()
    assert list((root / sha[:2]).iterdir()) == []


def test_supplementary_group_cannot_select_shared_writer_identity(tmp_path, monkeypatch):
    root = provision(tmp_path / "shared")
    other = (os.getegid() + 1) % (2**32 - 1)
    monkeypatch.setattr(os, "getgroups", lambda: [other])
    with pytest.raises(WorkbenchError, match="EVIDENCE_SHARED_CUSTODY_UNSAFE"):
        EvidenceStore(root, shared_group=other)
    assert list(root.iterdir()) == []
