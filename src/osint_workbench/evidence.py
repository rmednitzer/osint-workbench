import os
import re
import stat
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from threading import local

from .errors import WorkbenchError
from .text import digest

MAX_OBJECT = 20 * 1024 * 1024
ADMISSION_SECONDS = 5.0


class EvidenceStore:
    """Immutable objects with dirfd-relative, no-follow reads and promotion."""

    def __init__(self, root: Path, *, read_only: bool = False):
        self.root = root
        self.read_only = read_only
        self._local = local()
        if not read_only:
            root.mkdir(parents=True, exist_ok=True, mode=0o700)

    @contextmanager
    def admission(self, *, exclusive: bool = False):
        """Local Linux store-inode exclusion, independent of database liveness.

        Reentrancy is per instance/thread, never shared by concurrent threads.
        The root inode is anchored until the outermost admission exits. All
        cooperative processes must use this protocol and one DB/store pair.
        """
        import fcntl

        held = getattr(self._local, "held", None)
        if held is not None:
            fd, owner, mode = held
            if owner != os.getpid() or (exclusive and not mode):
                raise WorkbenchError("EVIDENCE_ADMISSION_UNSAFE")
            yield fd
            return
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            deadline = time.monotonic() + ADMISSION_SECONDS
            while True:
                try:
                    fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise WorkbenchError("EVIDENCE_STORE_BUSY") from None
                    time.sleep(min(0.01, remaining))
            self._local.held = (fd, os.getpid(), exclusive)
            try:
                yield fd
            finally:
                self._local.held = None
        finally:
            os.close(fd)

    def admitted_root(self):
        held = getattr(self._local, "held", None)
        if held is None or held[1] != os.getpid():
            raise WorkbenchError("EVIDENCE_ADMISSION_REQUIRED")
        return held[0]

    @contextmanager
    def acceptance(self, conn, *, exclusive=False):
        """Hold store admission until this already-admitted DB session exits.

        Acquire database admission BEFORE entering this context. The database
        context commits/rolls back and closes before filesystem exclusion ends.
        No reconnection or database-lock reacquisition is permitted inside it.
        """
        with self.admission(exclusive=exclusive):
            connections = getattr(self._local, "connections", ())
            self._local.connections = (*connections, conn)
            try:
                with conn:
                    yield conn
            finally:
                # psycopg's context exit may raise at COMMIT before its normal
                # close. Retire that session while filesystem exclusion is
                # still owned, including the acknowledgement-loss path.
                try:
                    conn.close()
                finally:
                    self._local.connections = connections

    @contextmanager
    def transaction(self, db, *, lifecycle_exclusive=False, exclusive=False):
        conn = db.connect(lifecycle_exclusive=lifecycle_exclusive)
        try:
            with self.acceptance(conn, exclusive=exclusive):
                yield conn
        finally:
            conn.close()

    def require_transaction(self, conn):
        self.admitted_root()
        if not any(c is conn for c in getattr(self._local, "connections", ())):
            raise WorkbenchError("EVIDENCE_ACCEPTANCE_REQUIRED")

    @contextmanager
    def _directory(self, sha: str):
        if not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise WorkbenchError("INVALID_DIGEST")
        with self.admission() as root_fd:
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
                fd = os.open(sha, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
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
