"""Cooperative host-local inference admission and bounded uncertain-work receipts.

The operator owns configuration and the OS account. Directory descriptors anchor
operations; identity checks detect accidental replacement, not a malicious peer
with the same UID or administrative authority. See docs/inference-marker-safety.md.
"""

import fcntl
import json
import os
import re
import stat
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .errors import WorkbenchError

MAX_RECEIPT_BYTES = 4096
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
_FILE_FLAGS = os.O_NOFOLLOW | os.O_NONBLOCK


def _unsafe():
    return WorkbenchError("INFERENCE_LOCK_UNSAFE")


def _directory(info):
    # Root-owned sticky ancestors (normally /tmp) protect entries owned by peers.
    sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid not in {0, os.getuid()}
        or (info.st_mode & 0o022 and not sticky_root)
    ):
        raise _unsafe()


def _parent(path):
    """Open every directory component without following symlinks."""
    if not path.is_absolute() or len(str(path)) > 4096 or ".." in path.parts:
        raise _unsafe()
    parts = path.parent.parts[1:]
    if len(parts) > 128 or not path.name or path.name in {".", ".."}:
        raise _unsafe()
    fd = os.open("/", _DIRECTORY_FLAGS)
    try:
        _directory(os.fstat(fd))
        for component in parts:
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
            _directory(os.fstat(fd))
        info = os.fstat(fd)
        # Reviewed compatibility exception: exact root-owned sticky /tmp only.
        default_parent = path.parent == Path("/tmp") and info.st_uid == 0  # noqa: S108
        if default_parent:
            if stat.S_IMODE(info.st_mode) != 0o1777:
                raise _unsafe()
        elif info.st_uid != os.getuid() or info.st_mode & 0o022 or info.st_mode & 0o700 != 0o700:
            raise _unsafe()
        return fd
    except BaseException:
        os.close(fd)
        raise


def _file(info):
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
    ):
        raise _unsafe()


def _identity(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _receipt(data):
    try:
        if not isinstance(data, bytes) or not 1 <= len(data) <= MAX_RECEIPT_BYTES:
            raise ValueError
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs)
        if not isinstance(value, dict) or set(value) != {
            "operation_id",
            "generator_id",
            "pid",
            "start",
        }:
            raise ValueError
        operation = value["operation_id"]
        if not isinstance(operation, str) or str(uuid.UUID(operation)) != operation:
            raise ValueError
        if not isinstance(value["generator_id"], str) or not re.fullmatch(
            "[0-9a-f]{64}", value["generator_id"]
        ):
            raise ValueError
        if type(value["pid"]) is not int or not 1 <= value["pid"] <= 2**31 - 1:
            raise ValueError
        if not isinstance(value["start"], str) or not re.fullmatch("[0-9]{1,32}", value["start"]):
            raise ValueError
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise _unsafe() from None


@dataclass(frozen=True)
class Receipt:
    identity: tuple
    data: bytes
    value: dict


class Admission:
    def __init__(self, path, directory, lock):
        self.path, self.directory, self.lock = path, directory, lock
        self.parent_identity = _identity(os.fstat(directory))[:2]
        self.lock_identity = _identity(os.fstat(lock))[:2]
        self.marker = path.name + ".unknown"

    def _current(self):
        # Reopening detects moved/replaced configured parents; operations still use
        # the original descriptor. This is not an atomic defence against same-UID peers.
        fresh = _parent(self.path)
        try:
            if _identity(os.fstat(fresh))[:2] != self.parent_identity:
                raise _unsafe()
        finally:
            os.close(fresh)
        held = os.fstat(self.lock)
        named = os.stat(self.path.name, dir_fd=self.directory, follow_symlinks=False)
        _file(held)
        _file(named)
        if _identity(held)[:2] != self.lock_identity or _identity(named) != _identity(held):
            raise _unsafe()

    def marker_exists(self):
        try:
            self._current()
            try:
                os.stat(self.marker, dir_fd=self.directory, follow_symlinks=False)
            except FileNotFoundError:
                return False
            return True
        except OSError:
            raise _unsafe() from None

    def read_marker(self):
        fd = None
        try:
            self._current()
            try:
                fd = os.open(self.marker, os.O_RDONLY | _FILE_FLAGS, dir_fd=self.directory)
            except FileNotFoundError:
                return None
            before = os.fstat(fd)
            _file(before)
            if not 1 <= before.st_size <= MAX_RECEIPT_BYTES:
                raise _unsafe()
            with os.fdopen(fd, "rb") as stream:
                fd = None
                data = stream.read(MAX_RECEIPT_BYTES + 1)
                after = os.fstat(stream.fileno())
            named = os.stat(self.marker, dir_fd=self.directory, follow_symlinks=False)
            if (
                len(data) != before.st_size
                or _identity(before) != _identity(after)
                or _identity(before) != _identity(named)
            ):
                raise _unsafe()
            return Receipt(_identity(before), data, _receipt(data))
        except OSError:
            raise _unsafe() from None
        finally:
            if fd is not None:
                os.close(fd)

    def create_marker(self, generator_id, peer):
        # No prompt, model path, socket path or credentials enter the receipt.
        value = {"operation_id": str(uuid.uuid4()), "generator_id": generator_id, **peer}
        data = json.dumps(value, separators=(",", ":")).encode()
        _receipt(data)
        try:
            self._current()
            fd = os.open(
                self.marker,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | _FILE_FLAGS,
                0o600,
                dir_fd=self.directory,
            )
            with os.fdopen(fd, "wb") as stream:
                _file(os.fstat(stream.fileno()))
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(self.directory)
            result = self.read_marker()
            if result is None or result.data != data:
                raise _unsafe()
            return result
        except OSError:
            # A partially written receipt remains a fail-closed reservation.
            raise _unsafe() from None

    def remove_marker(self, expected):
        try:
            current = self.read_marker()
            if (
                current is None
                or current.identity != expected.identity
                or current.data != expected.data
            ):
                raise _unsafe()
            os.unlink(self.marker, dir_fd=self.directory)
            os.fsync(self.directory)
        except OSError:
            raise _unsafe() from None


@contextmanager
def admission(*, allow_uncertain=False):
    # Explicit operator configuration; all cooperating profiles use the same path.
    path = Path(os.environ.get("OW_INFERENCE_LOCK", f"/tmp/ow-inference-{os.getuid()}.lock"))  # noqa: S108
    directory = lock = None
    try:
        directory = _parent(path)
        lock = os.open(path.name, os.O_CREAT | os.O_RDWR | _FILE_FLAGS, 0o600, dir_fd=directory)
        _file(os.fstat(lock))
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise WorkbenchError("INFERENCE_BUSY") from None
        held = Admission(path, directory, lock)
        if held.marker_exists() and not allow_uncertain:
            raise WorkbenchError("INFERENCE_OUTCOME_UNKNOWN")
    except OSError:
        if lock is not None:
            os.close(lock)
        if directory is not None:
            os.close(directory)
        raise _unsafe() from None
    except BaseException:
        if lock is not None:
            os.close(lock)
        if directory is not None:
            os.close(directory)
        raise
    try:
        yield held
    finally:
        os.close(lock)
        os.close(directory)
