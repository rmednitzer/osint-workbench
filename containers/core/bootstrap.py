"""Fixed paths only. Explicit initialization/copy of new synthetic stores."""

import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path


def directory(path, uid, gid=10100, mode=0o750):
    path.mkdir(mode=mode)
    os.chown(path, uid, gid)
    path.chmod(mode)


def regular(path, maximum):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
        raise RuntimeError("PROFILE_FILE_INVALID")
    return path.read_bytes()


def main():
    mode = sys.argv[1]
    root = Path("/state")
    if mode == "initialize":
        if list(root.iterdir()):
            raise RuntimeError("PROFILE_VOLUME_NOT_EMPTY")
        pg = Path("/pgdata")
        if list(pg.iterdir()):
            raise RuntimeError("PROFILE_DATABASE_VOLUME_NOT_EMPTY")
        os.chown(pg, 999, 999)
        pg.chmod(0o700)
        directory(root / "cas", 10001)
        directory(root / "policy", 10004, mode=0o700)
        directory(root / "backup", 10005, mode=0o700)
        directory(root / "restore", 10005, mode=0o700)
        directory(root / "shared", 10001)
        (root / "owner").write_text(os.environ["PROFILE_RUN_ID"])
        (root / "owner").chmod(0o600)
    elif mode == "policy-copy":
        if (root / "owner").read_text() != os.environ["PROFILE_RUN_ID"]:
            raise RuntimeError("PROFILE_VOLUME_OWNER_MISMATCH")
        for name in ("old.owpolicy", "current.owpolicy"):
            data = regular(root / "policy" / name, 8 * 1024 * 1024)
            target = root / "backup" / name
            with target.open("xb") as output:
                output.write(data)
            target.chmod(0o600)
            os.chown(target, 10005, 10100)
    elif mode == "restore-share":
        if (root / "owner").read_text() != os.environ["PROFILE_RUN_ID"]:
            raise RuntimeError("PROFILE_VOLUME_OWNER_MISMATCH")
        source = root / "restore" / "objects"
        target = root / "shared"
        if list(target.iterdir()):
            raise RuntimeError("PROFILE_SHARED_TARGET_NOT_EMPTY")
        if not stat.S_ISDIR(source.lstat().st_mode):
            raise RuntimeError("PROFILE_STORE_INVALID")
        total = 0
        for prefix in sorted(source.iterdir()):
            if prefix.name == ".allocation-lock" and regular(prefix, 0) == b"":
                continue
            if not re.fullmatch("[0-9a-f]{2}", prefix.name) or not stat.S_ISDIR(
                prefix.lstat().st_mode
            ):
                raise RuntimeError("PROFILE_STORE_INVALID")
            directory(target / prefix.name, 10001)
            for item in sorted(prefix.iterdir()):
                if not re.fullmatch("[0-9a-f]{64}", item.name) or not item.name.startswith(
                    prefix.name
                ):
                    raise RuntimeError("PROFILE_STORE_INVALID")
                data = regular(item, 20 * 1024 * 1024)
                total += len(data)
                if total > 64 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != item.name:
                    raise RuntimeError("PROFILE_STORE_INVALID")
                copied = target / prefix.name / item.name
                with copied.open("xb") as output:
                    output.write(data)
                copied.chmod(0o640)
                os.chown(copied, 10001, 10100)
    else:
        raise RuntimeError("PROFILE_ACTION_INVALID")
    print(json.dumps({"status": "complete", "action": mode}))


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from None
