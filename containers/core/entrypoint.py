"""Fixed-role credential adapter for the opt-in synthetic container profile."""

import os
import stat
import sys
from pathlib import Path

ROLES = {
    "writer": "OW_WRITER_DSN",
    "worker": "OW_WRITER_DSN",
    "reader": "OW_READER_DSN",
    "lifecycle": "OW_LIFECYCLE_DSN",
    "recovery": "OW_RECOVERY_DSN",
    "migration": "OW_MIGRATION_DSN",
}


def main():
    role = os.environ["PROFILE_ROLE"]
    key = ROLES[role]
    expected = {
        "writer": 10001,
        "worker": 10002,
        "reader": 10003,
        "lifecycle": 10004,
        "recovery": 10005,
        "migration": 10006,
    }
    if os.getuid() != expected[role] or os.getgid() != 10100:
        raise RuntimeError("PROFILE_PRINCIPAL_INVALID")
    path = Path("/run/credential")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
        raise RuntimeError("PROFILE_CREDENTIAL_INVALID")
    secret = path.read_text().strip()
    if not secret or any(
        c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in secret
    ):
        raise RuntimeError("PROFILE_CREDENTIAL_INVALID")
    # Compose file mounts do not implement secret uid/gid remapping. The private
    # host directory and service-only read-only mount are the custody boundary.
    os.environ[key] = (
        f"host=db dbname={os.environ.get('PROFILE_DATABASE', 'workbench')} "
        f"user=profile_{role} password={secret} connect_timeout=5"
    )
    os.execv(sys.executable, [sys.executable, "-I", "/opt/profile/acceptance.py", *sys.argv[1:]])


if __name__ == "__main__":
    main()
