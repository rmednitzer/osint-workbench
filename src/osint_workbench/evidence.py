import os
import re
import stat
import uuid
from contextlib import contextmanager
from pathlib import Path

from .errors import WorkbenchError
from .text import digest

MAX_OBJECT = 20 * 1024 * 1024


class EvidenceStore:
    """Immutable objects with dirfd-relative, no-follow reads and promotion."""

    def __init__(self, root: Path, *, read_only: bool = False):
        self.root = root
        self.read_only = read_only
        if not read_only:
            root.mkdir(parents=True, exist_ok=True, mode=0o700)

    @contextmanager
    def _directory(self, sha: str):
        if not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise WorkbenchError("INVALID_DIGEST")
        root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            if not self.read_only:
                try:
                    os.mkdir(sha[:2], mode=0o700, dir_fd=root_fd)
                    os.fsync(root_fd)
                except FileExistsError:
                    pass
            child_fd = os.open(
                sha[:2], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd
            )
            try:
                yield child_fd
            finally:
                os.close(child_fd)
        finally:
            os.close(root_fd)

    def put(self, data: bytes) -> str:
        if self.read_only:
            raise WorkbenchError("READ_ONLY_STORE")
        if len(data) > MAX_OBJECT:
            raise WorkbenchError("OBJECT_TOO_LARGE")
        sha = digest(data)
        temp = ".staging-" + uuid.uuid4().hex
        with self._directory(sha) as directory:
            fd = os.open(
                temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory
            )
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                try:
                    os.link(
                        temp, sha, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False
                    )
                except FileExistsError:
                    self.get(sha)
                os.fsync(directory)
            finally:
                os.unlink(temp, dir_fd=directory)
        return sha

    def get(self, sha: str) -> bytes:
        try:
            with self._directory(sha) as directory:
                fd = os.open(sha, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
                with os.fdopen(fd, "rb") as stream:
                    info = os.fstat(stream.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_OBJECT:
                        raise WorkbenchError("INVALID_EVIDENCE_OBJECT")
                    value = stream.read(MAX_OBJECT + 1)
        except OSError:
            raise WorkbenchError("EVIDENCE_UNAVAILABLE") from None
        if len(value) > MAX_OBJECT or digest(value) != sha:
            raise WorkbenchError("EVIDENCE_INTEGRITY_MISMATCH")
        return value
