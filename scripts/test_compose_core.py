"""Explicit opt-in disposable Compose profile; never imported by ordinary tests.

Only generated nonce-scoped resources are created or removed. Docker authority
remains on the operator host, never inside an application container. Private work
files and diagnostic captures remain outside the repository and are not receipts.
"""

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

LABEL = "org.osint-workbench.synthetic-run"
BASE = (
    "python:3.12.14-slim-trixie@sha256:"
    "44ff437bba879d4941b710a369a8f19266aea34b29002807f0c487fabc9eec9b"
)
POSTGRES = (
    "pgvector/pgvector:pg18@sha256:2358fcba361ed2233a5ed81b5fe4ca779ccb304120ce531a3bf51c0ed7e2bc11"
)
WHEEL = "osint_workbench-0.1.0.dev1-py3-none-any.whl"
ROLES = ("writer", "worker", "reader", "lifecycle", "recovery", "migration")


class Rejected(Exception):
    pass


def require(value, code):
    if not value:
        raise Rejected(code)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def input_bytes(path, maximum):
    """Capture one bounded regular public input; never follow links or wait on a FIFO."""
    resolved = path.resolve()
    if not resolved.is_relative_to("/tmp") and not resolved.is_relative_to("/var/tmp"):
        raise Rejected("PROFILE_INPUT_STAGING_REQUIRED")
    require(resolved == path.absolute(), "PROFILE_INPUT_SYMLINK")
    descriptor = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        require(
            stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= maximum,
            "PROFILE_INPUT_INVALID",
        )
        data = source.read(maximum + 1)
        after = os.fstat(source.fileno())
        require(
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            and len(data) == before.st_size
            and len(data) <= maximum,
            "PROFILE_INPUT_CHANGED",
        )
    return data


def command_name(argv):
    """Only fixed command categories; never paths, identifiers or arguments."""
    if argv[:2] == ["docker", "compose"]:
        for verb in ("version", "run", "up", "create", "ps", "restart", "down"):
            if verb in argv[2:]:
                return "DOCKER_COMPOSE_" + verb.upper()
        return "DOCKER_COMPOSE"
    if (
        len(argv) >= 3
        and argv[0] == "docker"
        and argv[1] in {"context", "image", "volume", "container", "network"}
        and argv[2] in {"inspect", "ls", "create", "rm"}
    ):
        return "DOCKER_" + argv[1].upper() + "_" + argv[2].upper()
    if argv[:2] == ["docker", "build"]:
        return "DOCKER_BUILD"
    if argv and argv[0] == "git":
        return "GIT_PREFLIGHT"
    return "OTHER"


def safe_failure(exc):
    if isinstance(exc, Rejected):
        return str(exc)
    if isinstance(exc, subprocess.TimeoutExpired):
        return "PROFILE_COMMAND_TIMEOUT"
    return "PROFILE_UNEXPECTED_FAILURE"


@contextmanager
def cleanup_guard(cleanup):
    primary = None
    try:
        yield
    except BaseException as exc:
        primary = exc
        raise
    finally:
        try:
            cleanup()
        except Exception as exc:
            if primary is None:
                raise
            primary.add_note("PROFILE_CLEANUP_FAILED:" + safe_failure(exc))


def command(argv, *, env=None, timeout=180, failure=False, expected_error=None):
    # The caller selects arguments, never a command executable or a shell.
    if argv[0] == "docker":
        executable = "docker"
    elif argv[0] == "git":
        executable = "git"
    else:
        raise Rejected("PROFILE_EXECUTABLE_REFUSED")
    try:
        result = subprocess.run(
            [executable, *argv[1:]],
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise Rejected("PROFILE_COMMAND_TIMEOUT_" + command_name(argv)) from None
    if (result.returncode != 0) != failure:
        codes = [
            line
            for line in result.stderr.splitlines()
            if re.fullmatch("PROFILE_[A-Z_]{1,110}", line)
        ]
        raise Rejected(
            "PROFILE_COMMAND_FAILED_" + command_name(argv) + (":" + codes[-1] if codes else "")
        )
    if expected_error is not None:
        require(expected_error in result.stderr.splitlines(), "PROFILE_WRONG_REFUSAL")
    return result.stdout


def ownership(resource, expected):
    """Fail closed on missing or foreign labels, including an unexpected object."""
    labels = resource.get("Config", {}).get("Labels") or resource.get("Labels") or {}
    require(labels.get(LABEL) == expected, "PROFILE_RESOURCE_OWNERSHIP")


def effective_container(info):
    host = info["HostConfig"]
    require(host["ReadonlyRootfs"] and not host["Privileged"], "PROFILE_ROOTFS")
    require(not host.get("PortBindings") and host["NetworkMode"] != "host", "PROFILE_NETWORK")
    require("ALL" in host["CapDrop"], "PROFILE_CAPABILITIES")
    require("no-new-privileges:true" in host["SecurityOpt"], "PROFILE_PRIVILEGES")
    require(0 < host["Memory"] <= 512 * 1024 * 1024, "PROFILE_MEMORY")
    require(0 < host["NanoCpus"] <= 1_000_000_000, "PROFILE_CPU")
    require(0 < host["PidsLimit"] <= 128, "PROFILE_PIDS")
    service = info["Config"]["Labels"]["com.docker.compose.service"]
    users = {
        "db": "999:999",
        "writer": "10001:10100",
        "worker": "10002:10100",
        "reader": "10003:10100",
        "restored-reader": "10003:10100",
        "lifecycle": "10004:10100",
        "recovery": "10005:10100",
        "restore": "10005:10100",
        "migration": "10006:10100",
    }
    require(info["Config"]["User"] == users[service], "PROFILE_RUNTIME_PRINCIPAL")
    require(
        not host.get("CapAdd") and not host.get("Devices") and not host.get("DeviceRequests"),
        "PROFILE_ADDITIONAL_AUTHORITY",
    )
    require(
        host.get("PidMode") != "host"
        and host.get("IpcMode") != "host"
        and host.get("CgroupnsMode") == "private",
        "PROFILE_HOST_NAMESPACES",
    )
    for mount in info["Mounts"]:
        require("docker.sock" not in mount["Source"], "PROFILE_SOCKET_MOUNT")
        if mount["Destination"] == "/run/credential":
            require(not mount["RW"], "PROFILE_CREDENTIAL_WRITABLE")
    if info["Config"]["User"] in {"10002:10100", "10003:10100"}:
        require(
            any(m["Destination"] == "/evidence" and not m["RW"] for m in info["Mounts"]),
            "PROFILE_READER_STORE_WRITABLE",
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--acknowledge-disposable-containers", action="store_true", required=True)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--wheel-sha256", required=True)
    parser.add_argument("--core-lock", type=Path, required=True)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    args = parser.parse_args()
    require(
        not any(name.startswith(("DOCKER_", "COMPOSE_")) for name in os.environ),
        "PROFILE_AMBIENT_DOCKER_CONFIGURATION",
    )
    context_info = json.loads(command(["docker", "context", "inspect"]))
    require(
        len(context_info) == 1
        and context_info[0]["Endpoints"]["docker"]["Host"].startswith("unix://"),
        "PROFILE_LOCAL_DOCKER_REQUIRED",
    )
    require(re.fullmatch("[0-9a-f]{40}", args.source_revision), "PROFILE_REVISION_INVALID")
    require(re.fullmatch("[0-9a-f]{64}", args.wheel_sha256), "PROFILE_DIGEST_INVALID")
    wheel_data = input_bytes(args.wheel, 32 * 1024 * 1024)
    require(
        args.wheel.name == WHEEL and hashlib.sha256(wheel_data).hexdigest() == args.wheel_sha256,
        "PROFILE_WHEEL_INVALID",
    )
    lock_data = input_bytes(args.core_lock, 2 * 1024 * 1024)
    lock = lock_data.decode("utf-8")
    require("--hash=sha256:" in lock and "-e " not in lock, "PROFILE_HASH_LOCK_REQUIRED")
    root = Path(__file__).resolve().parents[1]
    observed_revision = command(["git", "-C", str(root), "rev-parse", "HEAD"]).strip()
    require(observed_revision == args.source_revision, "PROFILE_REVISION_MISMATCH")
    dirty = command(
        [
            "git",
            "-C",
            str(root),
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--",
            "containers/core",
            "scripts/test_compose_core.py",
            "tests/test_compose_profile.py",
        ]
    )
    require(not dirty.strip(), "PROFILE_DIRTY_IMPLEMENTATION")
    work = args.workdir.resolve()
    require(
        not work.exists() and not work.is_relative_to(root), "PROFILE_NEW_EXTERNAL_WORKDIR_REQUIRED"
    )
    # No pull is implicit: operator reviews and acquires these images beforehand.
    for image in (BASE, POSTGRES):
        command(["docker", "image", "inspect", image])
    command(["docker", "compose", "version"])
    nonce = secrets.token_hex(12)
    project = "ow-synthetic-" + nonce
    image = project + ":local"
    # Refuse collisions before any resource creation, including stopped objects.
    for kind in ("container", "network", "volume"):
        listed = command(
            [
                "docker",
                kind,
                "ls",
                "-aq" if kind == "container" else "-q",
                "--filter",
                "name=" + project,
            ]
        )
        require(not listed.strip(), "PROFILE_RESOURCE_COLLISION")
    work.mkdir(mode=0o700, parents=True)
    work.chmod(0o700)
    (work / "owner.json").write_text(json.dumps({"run_id": nonce, "project": project}))
    (work / "owner.json").chmod(0o600)
    stage = work / "stage"
    stage.mkdir(mode=0o700)
    credentials = stage / "credentials"
    credentials.mkdir(mode=0o700)
    for role in ROLES:
        path = credentials / role
        path.write_text(secrets.token_urlsafe(32))
        path.chmod(0o444)
    context = work / "build"
    context.mkdir(mode=0o700)
    for name in ("Dockerfile", "entrypoint.py", "bootstrap.py", "acceptance.py"):
        shutil.copyfile(root / "containers/core" / name, context / name)
    (context / WHEEL).write_bytes(wheel_data)
    (context / "requirements.txt").write_bytes(lock_data)
    wheels = context / "wheels"
    wheels.mkdir()
    total_wheels = 0
    for source in sorted(args.wheelhouse.iterdir()):
        total_wheels += source.lstat().st_size
        require(total_wheels <= 256 * 1024 * 1024, "PROFILE_WHEELHOUSE_TOO_LARGE")
        require(
            source.suffix == ".whl" and stat.S_ISREG(source.lstat().st_mode),
            "PROFILE_WHEELHOUSE_INVALID",
        )
        data = input_bytes(source, 32 * 1024 * 1024)
        require(
            "--hash=sha256:" + hashlib.sha256(data).hexdigest() in lock,
            "PROFILE_DEPENDENCY_NOT_LOCKED",
        )
        (wheels / source.name).write_bytes(data)
    require(any(wheels.iterdir()), "PROFILE_WHEELHOUSE_EMPTY")
    env = {
        **os.environ,
        "PROFILE_STAGE": str(stage),
        "PROFILE_PROJECT": project,
        "PROFILE_RUN_ID": nonce,
        "PROFILE_IMAGE": image,
    }
    compose = [
        "docker",
        "compose",
        "--profile",
        "acceptance",
        "--project-name",
        project,
        "--file",
        str(root / "containers/core/compose.json"),
    ]
    created = []
    receipt = {
        "source_revision": args.source_revision,
        "wheel_sha256": args.wheel_sha256,
        "core_lock_sha256": hashlib.sha256(lock_data).hexdigest(),
        "base_image": BASE,
        "postgres_image": POSTGRES,
        "profile": "synthetic-compose-core/1",
    }

    def cleanup():
        marker = json.loads((work / "owner.json").read_text())
        require(marker == {"run_id": nonce, "project": project}, "PROFILE_CLEANUP_MARKER")
        ids = command(
            [
                "docker",
                "container",
                "ls",
                "-aq",
                "--filter",
                "label=com.docker.compose.project=" + project,
            ]
        ).split()
        for identifier in ids:
            ownership(json.loads(command(["docker", "container", "inspect", identifier]))[0], nonce)
        networks = command(
            [
                "docker",
                "network",
                "ls",
                "-q",
                "--filter",
                "label=com.docker.compose.project=" + project,
            ]
        ).split()
        for identifier in networks:
            ownership(json.loads(command(["docker", "network", "inspect", identifier]))[0], nonce)
        for volume in created:
            ownership(json.loads(command(["docker", "volume", "inspect", volume]))[0], nonce)
        command(compose + ["down", "--remove-orphans", "--timeout", "15"], env=env)
        for volume in created:
            command(["docker", "volume", "rm", volume])
        image_info = command(["docker", "image", "ls", "-q", image]).strip()
        if image_info:
            ownership(json.loads(command(["docker", "image", "inspect", image]))[0], nonce)
            command(["docker", "image", "rm", image])

    with cleanup_guard(cleanup):
        command(
            [
                "docker",
                "build",
                "--network=none",
                "--pull=false",
                "--label",
                LABEL + "=" + nonce,
                "--build-arg",
                "WHEEL_SHA256=" + args.wheel_sha256,
                "--tag",
                image,
                str(context),
            ],
            timeout=600,
        )
        receipt["image_id"] = json.loads(command(["docker", "image", "inspect", image]))[0]["Id"]
        for name in ("state", "pgdata"):
            volume = project + "_" + name
            command(["docker", "volume", "create", "--label", LABEL + "=" + nonce, volume])
            created.append(volume)

        def run(service, phase, payload=None, failure=False, expected_error=None):
            argv = compose + ["run", "--rm", "--no-deps", "-T", service, phase]
            if payload is not None:
                argv.append(json.dumps(payload))
            try:
                output = command(argv, env=env, failure=failure, expected_error=expected_error)
            except Rejected as exc:
                raise Rejected(
                    "PROFILE_PHASE_FAILED_" + service + "_" + phase + ":" + str(exc)
                ) from None
            return json.loads(output) if not failure else None

        run("bootstrap", "initialize")
        # Reinitialization must refuse a populated volume; subsequent reads prove
        # that the refusal did not destroy its custody marker or directories.
        run("bootstrap", "initialize", failure=True, expected_error="PROFILE_VOLUME_NOT_EMPTY")
        command(compose + ["up", "--detach", "--wait", "--wait-timeout", "90", "db"], env=env)
        command(compose + ["create", "--no-build", *ROLES, "restore", "restored-reader"], env=env)
        runtime_ids = command(compose + ["ps", "--all", "--quiet"], env=env).split()
        for identifier in runtime_ids:
            info = json.loads(command(["docker", "container", "inspect", identifier]))[0]
            ownership(info, nonce)
            effective_container(info)
        private_network = json.loads(
            command(["docker", "network", "inspect", project + "_private"])
        )[0]
        ownership(private_network, nonce)
        require(private_network["Internal"], "PROFILE_NETWORK_NOT_INTERNAL")
        run("migration", "provision")
        imported = run("writer", "import")
        read_payload = {"briefing": imported["briefing"]}
        run("worker", "work")
        before = run("reader", "read", read_payload)
        run("reader", "negative")
        run("worker", "negative")
        command(compose + ["restart", "db"], env=env)
        command(compose + ["up", "--detach", "--wait", "--wait-timeout", "90", "db"], env=env)
        after = run("reader", "read", read_payload)
        require(before == after, "PROFILE_RESTART_CHANGED_STATE")
        checkpoint = run("recovery", "checkpoint")
        old = run("lifecycle", "policy-old")
        retired = before["documents"][1]["document_id"]
        current = run("lifecycle", "retire", {"retired": retired})
        run("bootstrap", "policy-copy")
        restored = run(
            "restore",
            "restore",
            {
                "checkpoint": checkpoint["sha256"],
                "policy": current["sha256"],
                "old_policy": old["sha256"],
                "revision": current["revision"],
            },
        )
        run("bootstrap", "restore-share")
        run("restored-reader", "read", {**read_payload, "retired": retired})
        run("restored-reader", "negative")
        receipt["quarantined_jobs"] = restored["quarantined_jobs"]
        receipt["checks"] = [
            "seven-stdio-reads",
            "role-and-filesystem-denials",
            "restart-durability",
            "checkpoint",
            "invalid-restore-refusal",
            "current-policy-restore",
        ]
        receipt["result"] = "passed"
    for kind in ("container", "network", "volume"):
        remaining = command(
            [
                "docker",
                kind,
                "ls",
                "-aq" if kind == "container" else "-q",
                "--filter",
                "label=" + LABEL + "=" + nonce,
            ]
        )
        require(not remaining.strip(), "PROFILE_CLEANUP_INCOMPLETE")
    receipt["cleanup_verified"] = True
    receipt["files"] = {
        name: sha(root / name)
        for name in (
            "containers/core/Dockerfile",
            "containers/core/compose.json",
            "containers/core/entrypoint.py",
            "containers/core/bootstrap.py",
            "containers/core/acceptance.py",
            "scripts/test_compose_core.py",
        )
    }
    (work / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Rejected as exc:
        for note in getattr(exc, "__notes__", ()):
            print(note, file=sys.stderr)
        raise SystemExit(str(exc)) from None
    except subprocess.TimeoutExpired as exc:
        for note in getattr(exc, "__notes__", ()):
            print(note, file=sys.stderr)
        raise SystemExit("SYNTHETIC_COMPOSE_ACCEPTANCE_TIMEOUT") from None
