"""Explicit acceptance on disposable GitHub-hosted Linux runners; never imported by tests.

Requires sudo while preserving only the two GitHub runner marker variables. No
external sources or inference requests are supplied. An explicit database fixture
uses only a fixed synthetic loopback PostgreSQL endpoint. Guard rejection occurs
before mutation. Ephemeral runner disposal removes application state/user;
finally stops our units and removes only unit files created by this invocation.
"""

import argparse
import grp
import json
import os
import pwd
import shutil
import subprocess
import sys
import time
from pathlib import Path

APP = Path("/opt/osint-workbench")
CONFIG = Path("/etc/osint-workbench")
STATE = Path("/var/lib/osint-workbench")
UNIT_ROOT = Path("/etc/systemd/system")
SERVICE = "osint-workbench-collect.service"
TIMER = "osint-workbench-collect.timer"
ACCOUNT = "osint-workbench"
COMMAND_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


class Rejected(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Rejected(code)


def command(argv, *, allowed=(0,), timeout=30):
    result = subprocess.run(
        argv, env=COMMAND_ENV, capture_output=True, text=True, timeout=timeout, check=False
    )
    require(result.returncode in allowed, "NATIVE_COMMAND_FAILED")
    return result.stdout


def write_private(path, content, *, mode=0o600):
    with path.open("x", encoding="utf-8") as stream:
        stream.write(content)
    path.chmod(mode)


def preflight(venv, units):
    require(os.geteuid() == 0, "ROOT_REQUIRED")
    require(os.environ.get("GITHUB_ACTIONS") == "true", "GITHUB_ACTIONS_REQUIRED")
    require(os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted", "HOSTED_RUNNER_REQUIRED")
    require(Path("/proc/1/comm").read_text().strip() == "systemd", "SYSTEMD_PID1_REQUIRED")
    require(
        all(shutil.which(item) for item in ("systemctl", "journalctl", "useradd")),
        "SYSTEM_TOOLS_REQUIRED",
    )
    for path in (APP, CONFIG, STATE, UNIT_ROOT / SERVICE, UNIT_ROOT / TIMER):
        require(not os.path.lexists(path), "TARGET_ALREADY_EXISTS")
    for name in (SERVICE, TIMER):
        require(not os.path.lexists(UNIT_ROOT / f"{name}.d"), "DROPIN_TARGET_ALREADY_EXISTS")
    for lookup in (pwd.getpwnam, grp.getgrnam):
        try:
            lookup(ACCOUNT)
        except KeyError:
            continue
        raise Rejected("ACCOUNT_ALREADY_EXISTS")
    require((venv / "bin/python").is_file(), "CORE_VENV_REQUIRED")
    require((venv / "bin/osint-workbench").is_file(), "INSTALLED_ENTRYPOINT_REQUIRED")
    settings = {}
    for line in (venv / "pyvenv.cfg").read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            settings[key.strip()] = value.strip()
    base = Path(settings.get("home", "/nonexistent")).resolve()
    require(
        base.is_relative_to("/usr") or base.is_relative_to("/opt"),
        "SYSTEM_PYTHON_BASE_REQUIRED",
    )
    for name in (SERVICE, TIMER):
        require((units / name).is_file(), "REFERENCE_UNITS_REQUIRED")
    require(
        command(
            ["systemctl", "show", SERVICE, "--property=LoadState", "--value"], allowed=(0, 1, 4)
        ).strip()
        == "not-found",
        "SERVICE_ALREADY_KNOWN",
    )
    require(
        command(
            ["systemctl", "show", TIMER, "--property=LoadState", "--value"], allowed=(0, 1, 4)
        ).strip()
        == "not-found",
        "TIMER_ALREADY_KNOWN",
    )


# Public disposable-runner credentials only. No DSN or network endpoint is accepted
# from a command-line argument or environment variable for this optional fixture.
FIXTURE_PASSWORD = "ci-fixture-only"
FIXTURE_ADMIN_DSN = (
    "host=127.0.0.1 port=5432 dbname=ow_test user=postgres "
    "password=ci-fixture-only connect_timeout=5 sslmode=disable"
)
FIXTURE_COLLECTOR_DSN = (
    "host=127.0.0.1 port=5432 dbname=ow_test user=ow_reference_collector "
    "password=ci-fixture-only connect_timeout=5 sslmode=disable"
)
FIXTURE_WRITER_DSN = (
    "host=127.0.0.1 port=5432 dbname=ow_test user=ow_reference_writer "
    "password=ci-fixture-only connect_timeout=5 sslmode=disable"
)


def prepare_database_fixture(venv):
    # Called only after every root/hosted-runner/PID1/owned-target preflight guard.
    require(venv == Path("/tmp/ow-reference-core"), "FIXTURE_VENV_REFUSED")
    require(
        Path(sys.executable).resolve() == (venv / "bin/python").resolve()
        and Path(sys.prefix).resolve() == venv,
        "FIXTURE_PYTHON_REFUSED",
    )
    for name in tuple(os.environ):
        if name.startswith("PG"):
            del os.environ[name]
    import psycopg

    from osint_workbench.database import Database, migrate
    from osint_workbench.errors import WorkbenchError

    with psycopg.connect(FIXTURE_ADMIN_DSN, autocommit=True) as conn:
        identity = conn.execute(
            "SELECT current_database(),current_user,current_setting('server_version_num')::int"
        ).fetchone()
        require(
            identity[0] == "ow_test" and identity[1] == "postgres" and identity[2] // 10000 == 18,
            "FIXTURE_DATABASE_IDENTITY_REFUSED",
        )
        require(
            conn.execute("SELECT to_regnamespace('ow')").fetchone()[0] is None,
            "FIXTURE_SCHEMA_ALREADY_EXISTS",
        )
        require(
            not conn.execute(
                "SELECT 1 FROM pg_roles WHERE rolname IN "
                "('ow_reference_collector','ow_reference_writer')"
            ).fetchone(),
            "FIXTURE_LOGIN_ALREADY_EXISTS",
        )
    migrate(FIXTURE_ADMIN_DSN)
    with psycopg.connect(FIXTURE_ADMIN_DSN) as conn:
        from psycopg import sql

        for name, group in (
            ("ow_reference_collector", "ow_collector"),
            ("ow_reference_writer", "ow_writer"),
        ):
            conn.execute(
                sql.SQL(
                    "CREATE ROLE {} LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "NOREPLICATION NOBYPASSRLS PASSWORD {}"
                ).format(sql.Identifier(name), sql.Literal(FIXTURE_PASSWORD))
            )
            conn.execute(
                sql.SQL("GRANT {} TO {}").format(sql.Identifier(group), sql.Identifier(name))
            )
        require(
            conn.execute("SELECT max(version) FROM ow.migrations").fetchone()[0] == 6,
            "FIXTURE_SCHEMA_VERSION_MISMATCH",
        )
    Database(FIXTURE_COLLECTOR_DSN).validate_collector()
    for dsn in (FIXTURE_WRITER_DSN, FIXTURE_ADMIN_DSN):
        try:
            Database(dsn).validate_collector()
        except WorkbenchError as exc:
            require(exc.code == "UNSAFE_COLLECTOR_IDENTITY", "FIXTURE_UNSAFE_CODE_MISMATCH")
        else:
            raise Rejected("FIXTURE_BROAD_IDENTITY_ACCEPTED")


def journal_observed(since, account, expected):
    command(["journalctl", "--sync"])
    logs = command(
        ["journalctl", "--unit", SERVICE, f"--since=@{since}", "--output=json", "--no-pager"]
    )
    for line in logs.splitlines():
        row = json.loads(line)
        try:
            value = json.loads(row.get("MESSAGE", ""))
        except (ValueError, TypeError):
            continue
        if value == expected:
            require(row.get("_UID") == str(account.pw_uid), "JOURNAL_UID_MISMATCH")
            return True
    return False


def database_service_acceptance(account):
    import psycopg

    def configure(identifier, dsn):
        (CONFIG / "collector.env").write_text("OW_COLLECTOR_DSN=" + dsn + "\n")
        (CONFIG / "sources.json").write_text(
            json.dumps(
                {
                    "sources": [
                        {
                            "source_id": identifier,
                            "url": "https://fixture.invalid/disabled",
                            "enabled": False,
                        }
                    ]
                }
            )
        )

    identifier = "reference-disabled"
    configure(identifier, FIXTURE_COLLECTOR_DSN)
    started = str(time.time())
    command(["systemctl", "start", SERVICE], timeout=30)
    require(
        command(["systemctl", "show", SERVICE, "--property=ExecMainStatus", "--value"]).strip()
        == "0",
        "DATABASE_TICK_FAILED",
    )
    require(
        journal_observed(
            started,
            account,
            {
                "status": "complete",
                "results": [{"source_id": identifier, "status": "disabled", "documents": 0}],
                "deferred_sources": 0,
            },
        ),
        "DATABASE_DISABLED_RESULT_NOT_OBSERVED",
    )
    evidence = STATE / "evidence"
    before = sorted(str(path.relative_to(evidence)) for path in evidence.rglob("*"))
    with psycopg.connect(FIXTURE_ADMIN_DSN) as conn:
        require(
            conn.execute("SELECT source_id,enabled FROM ow.sources").fetchall()
            == [(identifier, False)],
            "DATABASE_DISABLED_SOURCE_MISMATCH",
        )
        for table in ("collection_runs", "jobs", "documents", "snapshots"):
            from psycopg import sql

            require(
                conn.execute(
                    sql.SQL("SELECT count(*) FROM ow.{}").format(sql.Identifier(table))
                ).fetchone()[0]
                == 0,
                "DATABASE_UNEXPECTED_WORK",
            )
    for label, dsn in (("writer", FIXTURE_WRITER_DSN), ("admin", FIXTURE_ADMIN_DSN)):
        rejected_identifier = "reference-rejected-" + label
        configure(rejected_identifier, dsn)
        started = str(time.time())
        command(["systemctl", "start", SERVICE], allowed=(1,), timeout=30)
        require(
            command(["systemctl", "show", SERVICE, "--property=ExecMainStatus", "--value"]).strip()
            == "1",
            "BROAD_IDENTITY_EXIT_MISMATCH",
        )
        require(
            journal_observed(started, account, {"error": "UNSAFE_COLLECTOR_IDENTITY"}),
            "BROAD_IDENTITY_REJECTION_NOT_OBSERVED",
        )
        with psycopg.connect(FIXTURE_ADMIN_DSN) as conn:
            require(
                not conn.execute(
                    "SELECT 1 FROM ow.sources WHERE source_id=%s", (rejected_identifier,)
                ).fetchone(),
                "BROAD_IDENTITY_MUTATED_SOURCE",
            )
        require(
            before == sorted(str(path.relative_to(evidence)) for path in evidence.rglob("*")),
            "BROAD_IDENTITY_MUTATED_EVIDENCE",
        )
        command(["systemctl", "reset-failed", SERVICE])
    configure(identifier, FIXTURE_COLLECTOR_DSN)
    return {
        "synthetic_database_tick": True,
        "collector_scope_validated": True,
        "disabled_source_persisted": True,
        "disabled_source_no_work": True,
        "database_journal_service_uid": True,
        "writer_identity_refused": True,
        "admin_identity_refused": True,
        "unsafe_identity_no_source_or_evidence_writes": True,
    }


PROBE = r"""
import errno
import json
import mmap
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

state = Path('/var/lib/osint-workbench/evidence')
if sys.argv[1] == 'sandbox':
    result = {'uid': os.getuid()}
    status = Path('/proc/self/status').read_text().splitlines()
    result['capabilities_zero'] = any(
        line.startswith('CapEff:') and int(line.split()[1], 16) == 0 for line in status
    )
    try:
        Path('/opt/osint-workbench/writable-probe/forbidden').write_text('probe')
        result['code_mount_read_only'] = False
    except OSError as exc:
        result['code_mount_read_only'] = exc.errno == errno.EROFS
    try:
        region = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        region.close()
        result['writable_executable_denied'] = False
    except OSError as exc:
        result['writable_executable_denied'] = exc.errno in (errno.EPERM, errno.EACCES)
    output = state / 'sandbox-result.json'
    with output.open('x') as stream:
        json.dump(result, stream)
        stream.flush()
        os.fsync(stream.fileno())
else:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    child = subprocess.Popen([
        sys.executable, '-c',
        'import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(60)'
    ])
    # Wait until the child has installed its handler, then record its immutable
    # proc start-time identity; no PID is printed by the public runner script.
    time.sleep(0.2)
    stat = Path(f'/proc/{child.pid}/stat').read_text().rsplit(')', 1)[1].split()
    with (state / 'timeout-result.json').open('x') as stream:
        json.dump({'pid': child.pid, 'start': stat[19]}, stream)
        stream.flush()
        os.fsync(stream.fileno())
    time.sleep(60)
"""


def acceptance(venv, units, installed_units, dropins, *, database_fixture=False):
    command(
        [
            "useradd",
            "--system",
            "--user-group",
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
            ACCOUNT,
        ]
    )
    account = pwd.getpwnam(ACCOUNT)
    APP.mkdir(mode=0o755)
    shutil.copytree(venv, APP / "venv", symlinks=False)
    for directory, dirs, files in os.walk(APP):
        for name in [*dirs, *files]:
            path = Path(directory) / name
            path.chmod(path.stat().st_mode & ~0o022)
    entrypoint = APP / "venv/bin/osint-workbench"
    script = entrypoint.read_text()
    first, separator, rest = script.partition("\n")
    require(first.startswith("#!") and separator, "ENTRYPOINT_FORMAT_UNSUPPORTED")
    entrypoint.write_text(f"#!{APP}/venv/bin/python\n{rest}")
    CONFIG.mkdir(mode=0o750)
    os.chown(CONFIG, 0, account.pw_gid)
    write_private(CONFIG / "collector.env", "# No credentials in synthetic acceptance.\n")
    write_private(CONFIG / "sources.json", '{"sources": []}\n', mode=0o640)
    os.chown(CONFIG / "sources.json", 0, account.pw_gid)
    for name in (SERVICE, TIMER):
        target = UNIT_ROOT / name
        write_private(target, (units / name).read_text(), mode=0o644)
        installed_units.append(target)
    command(["systemctl", "daemon-reload"])
    started = str(time.time())
    command(["systemctl", "start", SERVICE], timeout=30)
    require(
        command(["systemctl", "show", SERVICE, "--property=ExecMainStatus", "--value"]).strip()
        == "0",
        "EMPTY_CONFIG_TICK_FAILED",
    )
    command(["journalctl", "--sync"])
    logs = command(
        ["journalctl", "--unit", SERVICE, f"--since=@{started}", "--output=json", "--no-pager"]
    )
    observed = False
    for line in logs.splitlines():
        row = json.loads(line)
        try:
            value = json.loads(row.get("MESSAGE", ""))
        except (ValueError, TypeError):
            continue
        if value == {"status": "unconfigured", "sources": 0}:
            require(row.get("_UID") == str(account.pw_uid), "JOURNAL_UID_MISMATCH")
            observed = True
    require(observed, "UNCONFIGURED_RESULT_NOT_OBSERVED")
    database_result = database_service_acceptance(account) if database_fixture else {}
    probe_dir = APP / "writable-probe"
    probe_dir.mkdir(mode=0o700)
    os.chown(probe_dir, account.pw_uid, account.pw_gid)
    write_private(APP / "probe.py", PROBE, mode=0o644)
    dropin_dir = UNIT_ROOT / f"{SERVICE}.d"
    dropin_dir.mkdir(mode=0o755)
    dropins.append(dropin_dir)
    override = dropin_dir / "acceptance.conf"
    write_private(
        override,
        f"[Service]\nExecStart=\nExecStart={APP}/venv/bin/python {APP}/probe.py sandbox\n",
        mode=0o644,
    )
    dropins.append(override)
    command(["systemctl", "daemon-reload"])
    command(["systemctl", "start", SERVICE], timeout=30)
    result_file = STATE / "evidence/sandbox-result.json"
    result = json.loads(result_file.read_text())
    require(result_file.stat().st_uid == account.pw_uid, "STATE_WRITE_UID_MISMATCH")
    require(result.pop("uid") == account.pw_uid, "PROBE_UID_MISMATCH")
    require(
        all(value is True for value in result.values()) and len(result) == 3,
        "SANDBOX_POSTCONDITION_FAILED",
    )
    override.write_text(
        f"[Service]\nExecStart=\nExecStart={APP}/venv/bin/python {APP}/probe.py timeout\n"
        "TimeoutStartSec=2s\nTimeoutStopSec=2s\n"
    )
    command(["systemctl", "daemon-reload"])
    command(["systemctl", "start", SERVICE], allowed=(1,), timeout=15)
    require(
        command(["systemctl", "show", SERVICE, "--property=Result", "--value"]).strip()
        == "timeout",
        "TIMEOUT_NOT_OBSERVED",
    )
    child = json.loads((STATE / "evidence/timeout-result.json").read_text())
    try:
        stat = Path(f"/proc/{int(child['pid'])}/stat").read_text().rsplit(")", 1)[1].split()
        require(stat[19] != child["start"] or stat[0] == "Z", "CHILD_SURVIVED_TIMEOUT")
    except FileNotFoundError:
        pass
    return {
        "empty_config_tick": True,
        "journal_service_uid": True,
        "state_write": True,
        **result,
        "supervisor_timeout": True,
        "timeout_child_stopped": True,
        **database_result,
        "external_sources_tested": False,
        "synthetic_database_tested": database_fixture,
        "timer_activation_tested": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-venv", type=Path, required=True)
    parser.add_argument("--units", type=Path, required=True)
    parser.add_argument("--database-fixture", action="store_true")
    args = parser.parse_args()
    installed_units, dropins = [], []
    outcome = None
    failure = None
    try:
        preflight(args.core_venv.resolve(), args.units.resolve())
        if args.database_fixture:
            prepare_database_fixture(args.core_venv.resolve())
        outcome = acceptance(
            args.core_venv.resolve(),
            args.units.resolve(),
            installed_units,
            dropins,
            database_fixture=args.database_fixture,
        )
    except Rejected as exc:
        failure = str(exc)
    except (OSError, ValueError, KeyError, TypeError, IndexError, subprocess.SubprocessError):
        failure = "ACCEPTANCE_OPERATION_FAILED"
    except Exception:
        # Driver failures must not print connection strings or raw backend messages.
        failure = "ACCEPTANCE_OPERATION_FAILED"
    finally:
        if installed_units:
            try:
                command(["systemctl", "stop", TIMER, SERVICE], allowed=(0, 5), timeout=30)
                for name in (SERVICE, TIMER):
                    active = command(["systemctl", "is-active", name], allowed=(0, 3, 4)).strip()
                    require(active in ("inactive", "failed", "unknown"), "UNIT_STILL_ACTIVE")
            except (Rejected, OSError, subprocess.SubprocessError):
                failure = "OWNED_UNIT_STOP_FAILED"
            for path in [*reversed(dropins), *installed_units]:
                try:
                    path.rmdir() if path.is_dir() else path.unlink()
                except OSError:
                    failure = "OWNED_UNIT_CLEANUP_FAILED"
            try:
                command(["systemctl", "daemon-reload"])
                command(["systemctl", "reset-failed", SERVICE], allowed=(0, 1, 5))
                require(
                    all(not os.path.lexists(path) for path in installed_units + dropins),
                    "OWNED_UNITS_REMAIN",
                )
            except (Rejected, OSError, subprocess.SubprocessError):
                failure = "OWNED_UNIT_CLEANUP_FAILED"
    if failure:
        print(json.dumps({"accepted": False, "error": failure}), file=sys.stderr)
        return 1
    print(
        "PUBLIC_DEPLOYMENT_REPORT="
        + json.dumps({"accepted": True, **outcome, "owned_units_removed": True})
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
