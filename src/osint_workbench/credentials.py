"""Bounded, secret-free credential references for operator-provisioned tokens.

The service environment may select a systemd credential directory; it never
supplies credential values. These Linux file checks protect against other users,
not a compromised process with the same UID or a privileged host administrator.
"""

import os
import re
import stat
from pathlib import Path
from typing import Literal

from pydantic import ConfigDict, Field, SecretStr, model_validator

from .contracts import Identifier, StrictModel
from .errors import WorkbenchError

MAX_CREDENTIAL_BYTES = 4096
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
_TOKEN = re.compile(rb"[\x21-\x7e]{1,4096}")


class CredentialError(WorkbenchError):
    """Fixed diagnostics only; neither credential values nor paths are exposed."""

    def __init__(self, code: str = "CREDENTIAL_UNAVAILABLE"):
        if code not in {"CREDENTIAL_UNAVAILABLE", "CREDENTIAL_UNSAFE", "CREDENTIAL_INVALID"}:
            raise ValueError("INVALID_CREDENTIAL_ERROR_CODE")
        super().__init__(code)


class CredentialRef(StrictModel):
    """A private configuration reference, never a token or environment key."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, hide_input_in_errors=True)

    kind: Literal["systemd", "file"]
    name: Identifier | None = Field(default=None, repr=False)
    path: str | None = Field(default=None, min_length=1, max_length=4096, repr=False)

    @model_validator(mode="after")
    def valid_reference(self):
        if self.kind == "systemd":
            if self.name is None or self.path is not None:
                raise ValueError("INVALID_CREDENTIAL_REFERENCE")
        elif self.name is not None or self.path is None or not _valid_path(Path(self.path)):
            raise ValueError("INVALID_CREDENTIAL_REFERENCE")
        return self


def _valid_path(path: Path) -> bool:
    return (
        path.is_absolute()
        and 1 < len(path.parts) <= 130
        and ".." not in path.parts
        and len(str(path)) <= 4096
        and "\x00" not in str(path)
    )


def _check_directory(info: os.stat_result, *, sticky_temporary: bool = False) -> None:
    # Only the exact root-owned sticky /tmp exception permits a writable ancestor.
    sticky_root = sticky_temporary and info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid not in {0, os.geteuid()}
        or (info.st_mode & 0o022 and not sticky_root)
    ):
        raise CredentialError("CREDENTIAL_UNSAFE")


def _parent(path: Path) -> int:
    """Walk checked directory descriptors, refusing symlinks at every component."""
    descriptor = os.open("/", _DIRECTORY_FLAGS)
    try:
        _check_directory(os.fstat(descriptor))
        for index, component in enumerate(path.parent.parts[1:]):
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            _check_directory(
                os.fstat(descriptor), sticky_temporary=index == 0 and component == "tmp"
            )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read(path: Path) -> SecretStr:
    parent = _parent(path)
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid not in {0, os.geteuid()}
                or stat.S_IMODE(before.st_mode) not in {0o400, 0o600}
                or before.st_nlink != 1
            ):
                raise CredentialError("CREDENTIAL_UNSAFE")
            if not 1 <= before.st_size <= MAX_CREDENTIAL_BYTES:
                raise CredentialError("CREDENTIAL_INVALID")
            # Include an extra byte to catch growth or a misleading reported size.
            payload = b""
            while len(payload) <= MAX_CREDENTIAL_BYTES:
                chunk = os.read(descriptor, MAX_CREDENTIAL_BYTES + 1 - len(payload))
                if not chunk:
                    break
                payload += chunk
            after = os.fstat(descriptor)
            if _file_identity(before) != _file_identity(after):
                raise CredentialError("CREDENTIAL_UNSAFE")
            if not _TOKEN.fullmatch(payload):
                raise CredentialError("CREDENTIAL_INVALID")
            return SecretStr(payload.decode("ascii"))
        finally:
            os.close(descriptor)
    finally:
        os.close(parent)


def resolve_credential(
    reference: CredentialRef, *, credentials_directory: Path | None = None
) -> SecretStr:
    """Resolve one printable header token; no fallback to environment values.

    Directory selection is trusted service configuration. Explicit selection is
    useful for controlled embedding and fixtures; it grants no arbitrary-file
    access to MCP or source input. File and directory errors are sanitized.
    """
    try:
        if reference.kind == "systemd":
            configured = credentials_directory
            if configured is None:
                selected = os.environ.get("CREDENTIALS_DIRECTORY")
                if not selected:
                    raise CredentialError()
                configured = Path(selected)
            if not _valid_path(configured) or reference.name is None:
                raise CredentialError("CREDENTIAL_UNSAFE")
            path = configured / reference.name
        elif reference.path is not None:
            path = Path(reference.path)
        else:
            raise CredentialError("CREDENTIAL_INVALID")
        if not _valid_path(path):
            raise CredentialError("CREDENTIAL_UNSAFE")
        return _read(path)
    except (OSError, ValueError):
        raise CredentialError() from None
