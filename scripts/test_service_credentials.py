"""Real credential delivery on explicitly disposable GitHub-hosted systemd runners.

Never run this as ordinary pytest or on an operational host. It creates random
synthetic credentials, distinct transient DynamicUser services and owned /run
directories. The installed fixture venv is copied into its owned /run tree so
services retain private temporary storage and strict filesystem protection. No provider
requests, operational secrets or environment values are copied into services.
"""

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

COMMAND_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
VENV = Path("/tmp/ow-reference-core")

# The installed wheel supplies the resolver. No repository source path is added.
PROBE = r"""
import hashlib
import json
import os
import sys
import time
from pathlib import Path

stage = "IMPORT"
def safe_exception(kind, value, traceback):
    code = getattr(value, "code", None)
    if code not in {"CREDENTIAL_UNAVAILABLE", "CREDENTIAL_UNSAFE", "CREDENTIAL_INVALID"}:
        code = "ASSERTION" if kind is RuntimeError else "UNEXPECTED"
    print("CREDENTIAL_PROBE_FAILURE=" + stage + ":" + code, file=sys.stderr, flush=True)
sys.excepthook = safe_exception

from osint_workbench.credentials import CredentialError, CredentialRef, resolve_credential

def require(condition):
    if not condition:
        raise RuntimeError("CREDENTIAL_PROBE_FAILED")

case, expected = sys.argv[1:3]
stage = "CONTEXT"
require(os.geteuid() != 0)
require("site-packages" in __import__("osint_workbench").__file__)
require(not any(key.startswith("OW_") for key in os.environ))
if case == "positive":
    print("CREDENTIAL_PROBE_STARTED", flush=True)
    stage = "RESOLVE"
    secret = resolve_credential(CredentialRef(kind="systemd", name="source-token"))
    stage = "TOKEN"
    require(hashlib.sha256(secret.get_secret_value().encode()).hexdigest() == expected)
    stage = "READY"
    state = Path(sys.argv[3])
    (state / "ready").write_text(json.dumps({
        "uid": os.geteuid(), "pid": os.getpid(),
        "directory": os.environ["CREDENTIALS_DIRECTORY"]}))
    deadline = time.monotonic() + 30
    stage = "WAIT"
    while not (state / "release").exists():
        require(time.monotonic() < deadline)
        time.sleep(0.1)
elif case in {"no-delivery", "missing-name"}:
    stage = "DENIAL"
    try:
        resolve_credential(CredentialRef(kind="systemd", name="missing-token"))
    except CredentialError as error:
        require(error.code == "CREDENTIAL_UNAVAILABLE")
    else:
        require(False)
elif case == "cross-unit":
    stage = "ISOLATION"
    producer_uid, *paths = sys.argv[3:]
    require(os.geteuid() != int(producer_uid))
    for value in paths:
        try:
            with open(value, "rb") as stream:
                stream.read(1)
        except PermissionError:
            pass
        else:
            require(False)
        try:
            resolve_credential(CredentialRef(kind="file", path=value))
        except CredentialError as error:
            require(error.code in {"CREDENTIAL_UNAVAILABLE", "CREDENTIAL_UNSAFE"})
        else:
            require(False)
else:
    require(False)
print("CREDENTIAL_PROBE_OK", flush=True)
"""


class Rejected(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Rejected(code)


def preflight(venv):
    require(os.geteuid() == 0, "ROOT_REQUIRED")
    require(os.environ.get("GITHUB_ACTIONS") == "true", "GITHUB_ACTIONS_REQUIRED")
    require(os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted", "HOSTED_RUNNER_REQUIRED")
    require(Path("/proc/1/comm").read_text().strip() == "systemd", "SYSTEMD_PID1_REQUIRED")
    require(
        all(shutil.which(name) for name in ("systemd-run", "systemctl")), "SYSTEM_TOOLS_REQUIRED"
    )
    require(venv == VENV and not venv.is_symlink(), "FIXTURE_VENV_REFUSED")
    require((venv / "bin/python").is_file(), "CORE_VENV_REQUIRED")
    require((venv / "bin/python").resolve().is_relative_to("/usr"), "SYSTEM_PYTHON_REQUIRED")
    require(Path(sys.prefix).resolve() == venv, "INSTALLED_INTERPRETER_REQUIRED")


def run(argv, *, timeout=15, allowed=(0,)):
    result = subprocess.run(
        argv, env=COMMAND_ENV, capture_output=True, text=True, timeout=timeout, check=False
    )
    require(result.returncode in allowed, "FIXTURE_COMMAND_FAILED")
    return result.stdout


def producer_failure(process):
    """Classify only an authored fixed marker; captured output is never relayed."""
    _, error = process.communicate(timeout=5)
    pattern = re.compile(
        r"CREDENTIAL_PROBE_FAILURE=(IMPORT|CONTEXT|RESOLVE|TOKEN|READY|WAIT|DENIAL|ISOLATION):"
        r"(CREDENTIAL_UNAVAILABLE|CREDENTIAL_UNSAFE|CREDENTIAL_INVALID|ASSERTION|UNEXPECTED)"
    )
    for line in error.splitlines():
        match = pattern.fullmatch(line)
        if match is not None:
            return "DELIVERY_PROBE_" + match[1] + "_" + match[2]
    return {
        200: "DELIVERY_SYSTEMD_CHDIR_FAILED",
        203: "DELIVERY_SYSTEMD_EXEC_FAILED",
        216: "DELIVERY_SYSTEMD_GROUP_FAILED",
        217: "DELIVERY_SYSTEMD_USER_FAILED",
        218: "DELIVERY_SYSTEMD_CAPABILITIES_FAILED",
        226: "DELIVERY_SYSTEMD_NAMESPACE_FAILED",
    }.get(process.returncode, "DELIVERY_SERVICE_FAILED")


def acceptance(venv):
    root = Path(tempfile.mkdtemp(prefix="ow-credential-fixture-", dir="/run"))
    root.chmod(0o755)
    token = secrets.token_urlsafe(32)
    expected = hashlib.sha256(token.encode()).hexdigest()
    # Keep the longest DynamicUser name within portable 31-byte account limits.
    prefix = "owcred-" + secrets.token_hex(5)
    units = []
    process = None
    state = Path("/run") / (prefix + "-positive-state")
    failure = None
    try:
        # DynamicUser sandbox setup must not depend on the host /tmp view. Copy
        # only the explicitly installed fixture runtime into this owned /run tree,
        # as the reference-service harness does for its /opt installation. Preserve
        # the verified /usr interpreter symlink and make every copied inode
        # non-writable to group/other; services receive a read-only mount.
        runtime = root / "runtime"
        shutil.copytree(venv, runtime, symlinks=True)
        for directory, directories, files in os.walk(runtime):
            for name in [*directories, *files]:
                entry = Path(directory) / name
                if entry.is_symlink():
                    target = entry.resolve()
                    require(
                        target.is_relative_to("/usr") or target.is_relative_to(runtime),
                        "RUNTIME_SYMLINK_TARGET_REFUSED",
                    )
                else:
                    entry.chmod(entry.stat().st_mode & ~0o022)
        runtime.chmod(runtime.stat().st_mode & ~0o022)
        private = root / "private"
        private.mkdir(mode=0o700)
        source = private / "token"
        descriptor = os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(token)
        probe = root / "probe.py"
        probe.write_text(PROBE)
        probe.chmod(0o444)

        def launch(case, *, delivery=False, arguments=(), asynchronous=False):
            name = prefix + "-" + case
            unit = name + ".service"
            require(unit not in units, "DUPLICATE_OWNED_UNIT")
            # Random names are checked before cleanup ownership is recorded.
            load = run(["systemctl", "show", unit, "--property=LoadState", "--value"])
            require(load.strip() == "not-found", "UNIT_ALREADY_EXISTS")
            argv = [
                "systemd-run",
                "--quiet",
                "--wait",
                "--pipe",
                "--unit=" + unit,
                "--property=Type=exec",
                "--property=DynamicUser=yes",
                "--property=User=" + name,
                "--property=PrivateTmp=yes",
                "--property=PrivateNetwork=yes",
                "--property=PrivateDevices=yes",
                "--property=ProtectHome=yes",
                "--property=ProtectSystem=strict",
                "--property=NoNewPrivileges=yes",
                "--property=RestrictAddressFamilies=AF_UNIX",
                "--property=UMask=0077",
                "--property=RuntimeMaxSec=40s",
                "--property=TimeoutStopSec=5s",
                "--property=MemoryMax=192M",
                "--property=TasksMax=16",
                "--property=LimitCORE=0",
                "--property=WorkingDirectory=/",
                "--property=ReadOnlyPaths=" + str(runtime),
            ]
            if case == "positive":
                require(not os.path.lexists(state), "STATE_ALREADY_EXISTS")
                argv += [
                    "--property=RuntimeDirectory=" + state.name,
                    "--property=RuntimeDirectoryMode=0700",
                ]
            if delivery:
                argv += ["--property=LoadCredential=source-token:" + str(source)]
            argv += [str(runtime / "bin/python"), "-I", str(probe), case, expected, *arguments]
            units.append(unit)
            if asynchronous:
                return subprocess.Popen(
                    argv, env=COMMAND_ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                )
            try:
                output = run(argv)
            except Rejected:
                stage = {
                    "cross-unit": "CROSS_UNIT_ISOLATION_FAILED",
                    "no-delivery": "NO_DELIVERY_DENIAL_FAILED",
                    "missing-name": "MISSING_NAME_DENIAL_FAILED",
                }[case]
                raise Rejected(stage) from None
            require(output.strip() == "CREDENTIAL_PROBE_OK", "PROBE_OUTPUT_INVALID")
            return None

        process = launch("positive", delivery=True, arguments=(str(state),), asynchronous=True)
        deadline = time.monotonic() + 10
        while not (state / "ready").exists():
            if process.poll() is not None:
                raise Rejected(producer_failure(process))
            require(time.monotonic() < deadline, "DELIVERY_SERVICE_TIMEOUT")
            time.sleep(0.1)
        identity = json.loads((state / "ready").read_text())
        producer_uid = int(identity["uid"])
        # Credential mounts can be visible only in the producer's mount namespace.
        # Root verifies the live file there; a different UID must be unable to
        # traverse that namespace root, independently of host mount visibility.
        directory = Path(identity["directory"])
        require(directory.is_absolute(), "CREDENTIAL_DIRECTORY_INVALID")
        delivered = (
            Path("/proc")
            / str(int(identity["pid"]))
            / "root"
            / directory.relative_to("/")
            / "source-token"
        )
        require(source.is_file() and delivered.is_file(), "DELIVERED_FILE_MISSING")
        launch("cross-unit", arguments=(str(producer_uid), str(source), str(delivered)))
        launch("no-delivery")
        launch("missing-name", delivery=True)
        (state / "release").touch(mode=0o600)
        output, _ = process.communicate(timeout=10)
        require(process.returncode == 0, "DELIVERY_SERVICE_FAILED")
        require(
            output.strip() == "CREDENTIAL_PROBE_STARTED\nCREDENTIAL_PROBE_OK",
            "PROBE_OUTPUT_INVALID",
        )
    except BaseException as error:
        failure = error
    finally:
        for unit in reversed(units):
            try:
                run(["systemctl", "stop", unit], allowed=(0, 5))
                active = run(["systemctl", "is-active", unit], allowed=(0, 3, 4)).strip()
                require(active in {"inactive", "failed", "unknown"}, "OWNED_UNIT_STILL_ACTIVE")
                run(["systemctl", "reset-failed", unit], allowed=(0, 1, 5))
            except (Rejected, OSError, subprocess.SubprocessError):
                failure = Rejected("OWNED_UNIT_CLEANUP_FAILED")
        if process is not None and process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
        # Only this mkdtemp tree is removed; credential mounts/runtime directories
        # remain systemd-owned and their disappearance is checked, not forced.
        shutil.rmtree(root)
        require(not state.exists(), "OWNED_RUNTIME_DIRECTORY_REMAINS")
    if failure is not None:
        raise failure
    return {
        "credential_delivery": True,
        "missing_delivery_denied": True,
        "missing_name_denied": True,
        "source_file_isolation": True,
        "live_cross_unit_isolation": True,
        "owned_units_stopped": True,
        "installed_wheel": True,
        "external_requests": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-venv", type=Path, required=True)
    args = parser.parse_args()
    try:
        preflight(args.core_venv)
        report = acceptance(args.core_venv)
    except Rejected as error:
        print(json.dumps({"accepted": False, "error": str(error)}), file=sys.stderr)
        return 1
    except Exception:
        # Never dump captured child stdout/stderr, argv, paths or token bytes.
        print(
            json.dumps({"accepted": False, "error": "CREDENTIAL_SERVICE_FIXTURE_FAILED"}),
            file=sys.stderr,
        )
        return 1
    print("PUBLIC_CREDENTIAL_SERVICE_REPORT=" + json.dumps({"accepted": True, **report}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
