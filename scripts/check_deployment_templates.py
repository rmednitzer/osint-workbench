"""Read-only comparison of selected installed templates with this checkout.

This is a source-checkout tool, not runtime or systemd health qualification.
"""

import argparse
import errno
import json
import os
import stat
from contextlib import ExitStack
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "config" / "systemd"
MAX_BYTES = 65536
PROFILES = {
    "collector": ("osint-workbench-collect.service", "osint-workbench-collect.timer"),
    "shared": (
        "osint-workbench-collect-shared.conf",
        "osint-workbench-work.service",
        "osint-workbench-work.timer",
        "osint-workbench-health.service",
        "osint-workbench-health.timer",
    ),
    "api": ("osint-workbench-collect-api.service", "osint-workbench-collect-api.timer"),
    "api-credential": ("osint-workbench-api-credential.conf",),
    "local-api": (
        "osint-workbench-enrich-local-api.service",
        "osint-workbench-enrich-local-api.timer",
    ),
}
DROP_INS = {
    "osint-workbench-collect-shared.conf": "osint-workbench-collect.service.d",
    "osint-workbench-api-credential.conf": "osint-workbench-collect-api.service.d",
}


def read_template(root, name, *, installed):
    """Bounded regular-file read, anchored at a non-symlink directory descriptor."""
    try:
        with ExitStack() as stack:
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            stack.callback(os.close, directory)
            if installed and name in DROP_INS:
                directory = os.open(
                    DROP_INS[name], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory
                )
                stack.callback(os.close, directory)
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
                    return "unsafe", None
                data = stream.read(MAX_BYTES + 1)
                if len(data) > MAX_BYTES:
                    return "unsafe", None
                return "read", data
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return "missing", None
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            return "unsafe", None
        return "unavailable", None


def check(profiles, installed_root, *, reference_root=ROOT):
    names = sorted({name for profile in profiles for name in PROFILES[profile]})
    results = []
    for name in names:
        reference_state, reference = read_template(reference_root, name, installed=False)
        if reference_state != "read":
            state = "reference_unavailable_or_unsafe"
        else:
            state, actual = read_template(installed_root, name, installed=True)
            if state == "read":
                state = "matches" if actual == reference else "changed"
        results.append({"template": name, "state": state})
    code = (
        2
        if any(item["state"] == "reference_unavailable_or_unsafe" for item in results)
        else int(any(item["state"] != "matches" for item in results))
    )
    return {"format": 1, "kind": "deployment_template_comparison", "templates": results}, code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=PROFILES, action="append", required=True)
    parser.add_argument("--installed-root", type=Path, default=Path("/etc/systemd/system"))
    args = parser.parse_args()
    result, code = check(args.profile, args.installed_root)
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
