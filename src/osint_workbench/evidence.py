import errno
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

    def __init__(self, root: Path, *, read_only: bool = False, shared_group: int | None = None):
        self.root = root
        self.read_only = read_only
        self.shared_group = shared_group
        self._local = local()
        self._shared_identity = None
        if shared_group is not None:
            if (
                read_only
                or type(shared_group) is not int
                or not 0 <= shared_group < 2**32 - 1
                or shared_group != os.getegid()
            ):
                raise WorkbenchError("EVIDENCE_SHARED_CUSTODY_UNSAFE")
            fd = self._open_shared_root()
            try:
                info = os.fstat(fd)
                self._shared_identity = (info.st_dev, info.st_ino)
            finally:
                os.close(fd)
        elif not read_only:
            root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _shared_directory(self, info):
        mode = stat.S_IMODE(info.st_mode)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_gid != self.shared_group
            or mode not in {0o750, 0o2750}
        ):
            raise WorkbenchError("EVIDENCE_SHARED_CUSTODY_UNSAFE")

    def _open_shared_root(self):
        """Require an explicitly provisioned tree; never convert an existing private tree."""
        if self.shared_group != os.getegid() or ".." in self.root.parts:
            raise WorkbenchError("EVIDENCE_SHARED_CUSTODY_UNSAFE")
        fd = None
        try:
            fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK)
            for component in self.root.absolute().parts[1:]:
                child = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK,
                    dir_fd=fd,
                )
                os.close(fd)
                fd = child
            info = os.fstat(fd)
            self._shared_directory(info)
            self._shared_acl(fd)
            if self._shared_identity is not None and self._shared_identity != (
                info.st_dev,
                info.st_ino,
            ):
                raise WorkbenchError("EVIDENCE_SHARED_CUSTODY_UNSAFE")
            result, fd = fd, None
            return result
        except OSError:
            raise WorkbenchError("EVIDENCE_SHARED_CUSTODY_UNSAFE") from None
        finally:
            if fd is not None:
                os.close(fd)

    @staticmethod
    def _shared_acl(fd):
        for name in ("system.posix_acl_access", "system.posix_acl_default"):
            try:
                os.getxattr(fd, name)
            except OSError as error:
                if error.errno in (errno.ENODATA, errno.ENOTSUP):
                    continue
                raise WorkbenchError("EVIDENCE_SHARED_CUSTODY_UNSAFE") from None
            raise WorkbenchError("EVIDENCE_SHARED_CUSTODY_UNSAFE")

    def _shared_object(self, info, fd):
        self._shared_acl(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_gid != self.shared_group
            or stat.S_IMODE(info.st_mode) != 0o640
        ):
            raise WorkbenchError("EVIDENCE_SHARED_CUSTODY_UNSAFE")

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
        fd = (
            self._open_shared_root()
            if self.shared_group is not None
            else os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        )
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
            created = False
            if not self.read_only:
                try:
                    os.mkdir(sha[:2], mode=0o700, dir_fd=root_fd)
                    created = True
                except FileExistsError:
                    pass
            child_fd = os.open(
                sha[:2], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd
            )
            try:
                if self.shared_group is not None:
                    self._shared_acl(child_fd)
                    if created:
                        # Only this invocation's fresh directory is widened. Its
                        # gid must match the explicitly selected primary group.
                        info = os.fstat(child_fd)
                        if info.st_uid != os.geteuid() or info.st_gid != self.shared_group:
                            raise WorkbenchError("EVIDENCE_SHARED_CUSTODY_UNSAFE")
                        os.fchmod(child_fd, 0o750)
                        os.fsync(child_fd)
                    self._shared_directory(os.fstat(child_fd))
                if created:
                    os.fsync(root_fd)
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
                if self.shared_group is not None:
                    try:
                        info = os.fstat(fd)
                        if info.st_nlink != 1 or info.st_gid != self.shared_group:
                            raise WorkbenchError("EVIDENCE_SHARED_CUSTODY_UNSAFE")
                        self._shared_acl(fd)
                    except BaseException:
                        os.close(fd)
                        raise
                with os.fdopen(fd, "wb") as stream:
                    stream.write(data)
                    stream.flush()
                    if self.shared_group is not None:
                        # Staging remains private until the complete bytes have
                        # been flushed. Publish only after verified final custody.
                        self._shared_acl(stream.fileno())
                        os.fchmod(stream.fileno(), 0o640)
                        self._shared_object(os.fstat(stream.fileno()), stream.fileno())
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
                    if self.shared_group is not None:
                        self._shared_object(info, stream.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_OBJECT:
                        raise WorkbenchError("INVALID_EVIDENCE_OBJECT")
                    value = stream.read(MAX_OBJECT + 1)
        except OSError:
            raise WorkbenchError("EVIDENCE_UNAVAILABLE") from None
        if len(value) > MAX_OBJECT or digest(value) != sha:
            raise WorkbenchError("EVIDENCE_INTEGRITY_MISMATCH")
        return value
