"""Explicit disposable GitHub-hosted acceptance; import never starts deployment.

Requires sudo while preserving the two GitHub runner marker variables. No
external sources or inference requests are supplied. The optional database uses
a fixed synthetic endpoint; its optional HTTP peer occupies a disconnected
namespace. Preflight guards precede deployment mutation. Finally stops and
removes owned units/drop-ins; the network context cleans up its owned peer and
namespace. Runner disposal removes the remaining synthetic state/account/database.
This script is separate from ordinary installed-wheel pytest execution.
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
WORK_ACCOUNT = "osint-workbench-worker"
HEALTH_ACCOUNT = "osint-workbench-health"
EVIDENCE_GROUP = "osint-workbench-evidence"
WORK_CONFIG = Path("/etc/osint-workbench-worker")
HEALTH_CONFIG = Path("/etc/osint-workbench-health")
WORK_SERVICE = "osint-workbench-work.service"
WORK_TIMER = "osint-workbench-work.timer"
HEALTH_SERVICE = "osint-workbench-health.service"
HEALTH_TIMER = "osint-workbench-health.timer"
API_SERVICE = "osint-workbench-collect-api.service"
API_TIMER = "osint-workbench-collect-api.timer"
ENRICH_ACCOUNT = "osint-workbench-enrich"
ENRICH_CONFIG = Path("/etc/osint-workbench-enrich")
ENRICH_STATE = Path("/var/lib/osint-workbench-enrich")
ENRICH_SERVICE = "osint-workbench-enrich-local-api.service"
ENRICH_TIMER = "osint-workbench-enrich-local-api.timer"
OPERATIONAL_UNITS = (
    WORK_SERVICE,
    WORK_TIMER,
    HEALTH_SERVICE,
    HEALTH_TIMER,
    API_SERVICE,
    API_TIMER,
    ENRICH_SERVICE,
    ENRICH_TIMER,
)
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
    if result.returncode not in allowed:
        executable = Path(argv[0]).name
        if executable not in {"systemctl", "journalctl", "useradd", "busctl"}:
            executable = "other"
        action = argv[1] if len(argv) > 1 else "none"
        if action not in {
            "start",
            "stop",
            "show",
            "daemon-reload",
            "is-active",
            "reset-failed",
            "get-property",
            "--sync",
            "--unit",
            "--system",
        }:
            action = "other"
        print(
            "PUBLIC_DEPLOYMENT_DIAGNOSTIC="
            + json.dumps(
                {
                    "kind": "native_command_failed",
                    "executable": executable,
                    "action": action,
                    "returncode": result.returncode,
                },
                sort_keys=True,
            ),
            flush=True,
        )
        raise Rejected("NATIVE_COMMAND_FAILED")
    return result.stdout


def parse_bus_uint64(value):
    """Parse busctl's raw typed uint64 without accepting display durations."""
    require(isinstance(value, str) and len(value) <= 64, "TIMER_DBUS_VALUE_INVALID")
    fields = value.split()
    require(len(fields) == 2 and fields[0] == "t", "TIMER_DBUS_VALUE_INVALID")
    number = fields[1]
    require(
        number.isascii() and number.isdecimal() and len(number) <= 20, "TIMER_DBUS_VALUE_INVALID"
    )
    result = int(number)
    require(result <= 2**64 - 1, "TIMER_DBUS_VALUE_INVALID")
    return result


def timer_last_trigger(timer=TIMER):
    require(timer in (TIMER, WORK_TIMER, HEALTH_TIMER, API_TIMER), "UNKNOWN_FIXTURE_TIMER")
    encoded = timer.replace("-", "_2d").replace(".", "_2e")
    # Fixed unit object only. Call while the timer is active so GC cannot replace
    # its runtime object; systemctl show formats nonzero durations for humans.
    return parse_bus_uint64(
        command(
            [
                "busctl",
                "get-property",
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1/unit/" + encoded,
                "org.freedesktop.systemd1.Timer",
                "LastTriggerUSecMonotonic",
            ]
        )
    )


def exception_diagnostic(error):
    """Expose bounded exception location only, never exception values or paths."""
    accepted_types = {
        "OSError",
        "PermissionError",
        "FileNotFoundError",
        "FileExistsError",
        "ValueError",
        "KeyError",
        "TypeError",
        "IndexError",
        "TimeoutExpired",
        "CalledProcessError",
        "OperationalError",
        "InterfaceError",
        "ProgrammingError",
        "RuntimeError",
        "WorkbenchError",
        "AssertionError",
        "JSONDecodeError",
    }
    name = type(error).__name__
    diagnostic = {
        "kind": "unexpected_exception",
        "exception_type": name if name in accepted_types else "other",
    }
    script = Path(__file__).resolve()
    known = {
        script: "test_reference_deployment.py",
        script.with_name("reference_network.py"): "reference_network.py",
    }
    frame = error.__traceback__
    for _ in range(32):
        if frame is None:
            break
        path = Path(frame.tb_frame.f_code.co_filename).resolve()
        if path in known:
            diagnostic["frame_file"] = known[path]
            diagnostic["frame_line"] = max(1, min(frame.tb_lineno, 20000))
        frame = frame.tb_next
    print("PUBLIC_DEPLOYMENT_DIAGNOSTIC=" + json.dumps(diagnostic, sort_keys=True), flush=True)


def write_private(path, content, *, mode=0o600):
    with path.open("x", encoding="utf-8") as stream:
        stream.write(content)
    path.chmod(mode)


def preflight(venv, units, *, operational_fixture=False):
    require(os.geteuid() == 0, "ROOT_REQUIRED")
    require(os.environ.get("GITHUB_ACTIONS") == "true", "GITHUB_ACTIONS_REQUIRED")
    require(os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted", "HOSTED_RUNNER_REQUIRED")
    require(Path("/proc/1/comm").read_text().strip() == "systemd", "SYSTEMD_PID1_REQUIRED")
    require(
        all(shutil.which(item) for item in ("systemctl", "journalctl", "useradd", "busctl")),
        "SYSTEM_TOOLS_REQUIRED",
    )
    names = (SERVICE, TIMER, *OPERATIONAL_UNITS) if operational_fixture else (SERVICE, TIMER)
    targets = (APP, CONFIG, STATE, *(UNIT_ROOT / name for name in names))
    if operational_fixture:
        targets = (*targets, WORK_CONFIG, HEALTH_CONFIG, ENRICH_CONFIG, ENRICH_STATE)
    for path in targets:
        require(not os.path.lexists(path), "TARGET_ALREADY_EXISTS")
    for name in names:
        require(not os.path.lexists(UNIT_ROOT / f"{name}.d"), "DROPIN_TARGET_ALREADY_EXISTS")
    accounts = (
        (ACCOUNT, WORK_ACCOUNT, HEALTH_ACCOUNT, ENRICH_ACCOUNT)
        if operational_fixture
        else (ACCOUNT,)
    )
    for lookup in (pwd.getpwnam, grp.getgrnam):
        for account in accounts:
            try:
                lookup(account)
            except KeyError:
                continue
            raise Rejected("ACCOUNT_ALREADY_EXISTS")
    if operational_fixture:
        try:
            grp.getgrnam(EVIDENCE_GROUP)
        except KeyError:
            pass
        else:
            raise Rejected("EVIDENCE_GROUP_ALREADY_EXISTS")
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
    for name in names:
        require((units / name).is_file(), "REFERENCE_UNITS_REQUIRED")
    if operational_fixture:
        for name in OPERATIONAL_UNITS:
            require(
                command(
                    ["systemctl", "show", name, "--property=LoadState", "--value"],
                    allowed=(0, 1, 4),
                ).strip()
                == "not-found",
                "OPERATIONAL_UNIT_ALREADY_KNOWN",
            )
    if operational_fixture:
        require(
            (units / "osint-workbench-collect-shared.conf").is_file(), "SHARING_DROPIN_REQUIRED"
        )
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


def collector_environment(dsn, shared_gid=None):
    result = "OW_COLLECTOR_DSN=" + dsn + "\n"
    if shared_gid is not None:
        require(type(shared_gid) is int and shared_gid >= 0, "INVALID_SHARED_GROUP")
        result += f"OW_EVIDENCE_READ_GID={shared_gid}\n"
    return result


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

FIXTURE_UNIX_ADMIN_DSN = (
    "host=/run/ow-reference-postgres port=5432 dbname=ow_test user=postgres "
    "password=ci-fixture-only connect_timeout=5 sslmode=disable"
)
FIXTURE_UNIX_DSN = (
    "host=/run/ow-reference-postgres port=5432 dbname=ow_test user=ow_reference_collector "
    "password=ci-fixture-only connect_timeout=5 sslmode=disable"
)


def prepare_database_fixture(venv, *, enabled_http_fixture=False, operational_fixture=False):
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

    from osint_workbench.database import SCHEMA_VERSION, Database, migrate
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
                "('ow_reference_collector','ow_reference_writer','ow_reference_reader')"
            ).fetchone(),
            "FIXTURE_LOGIN_ALREADY_EXISTS",
        )
    migrate(FIXTURE_ADMIN_DSN)
    with psycopg.connect(FIXTURE_ADMIN_DSN) as conn:
        from psycopg import sql

        for name, group in (
            ("ow_reference_collector", "ow_collector"),
            ("ow_reference_writer", "ow_writer"),
            *(
                ([("ow_reference_reader", "ow_reader"), ("ow_reference_enricher", "ow_writer")])
                if operational_fixture
                else []
            ),
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
            conn.execute("SELECT max(version) FROM ow.migrations").fetchone()[0] == SCHEMA_VERSION,
            "FIXTURE_SCHEMA_VERSION_MISMATCH",
        )
    if enabled_http_fixture:
        with psycopg.connect(FIXTURE_UNIX_ADMIN_DSN) as conn:
            require(
                conn.execute("SELECT current_database(),current_user").fetchone()
                == ("ow_test", "postgres"),
                "FIXTURE_UNIX_IDENTITY_REFUSED",
            )
        try:
            psycopg.connect(
                FIXTURE_UNIX_ADMIN_DSN, password="wrong-public-fixture-password"
            ).close()
        except psycopg.OperationalError as exc:
            require(
                "password authentication failed" in str(exc).lower(),
                "FIXTURE_UNIX_AUTH_FAILURE_MISMATCH",
            )
        else:
            raise Rejected("FIXTURE_UNIX_AUTH_NOT_ENFORCED")
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


def database_service_acceptance(account, *, shared_gid=None):
    import psycopg

    def configure(identifier, dsn):
        (CONFIG / "collector.env").write_text(collector_environment(dsn, shared_gid))
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


def enabled_http_service_acceptance(account, *, shared_gid=None, operational_accounts=None):
    import psycopg
    from psycopg.rows import dict_row
    from reference_network import FEED_V1, FEED_V2, ReferenceNetwork

    from osint_workbench.evidence import EvidenceStore

    source_id = "reference-enabled"
    service_dir = UNIT_ROOT / f"{SERVICE}.d"
    timer_dir = UNIT_ROOT / f"{TIMER}.d"
    owned = []

    def connect():
        return psycopg.connect(FIXTURE_ADMIN_DSN, row_factory=dict_row)

    def force_due():
        with connect() as conn:
            conn.execute(
                "UPDATE ow.collection_state SET next_attempt=clock_timestamp()-interval '1 second' "
                "WHERE source_id=%s",
                (source_id,),
            )

    def observed(since, status, documents=None):
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
            if not isinstance(value, dict) or value.get("status") != status:
                continue
            items = value.get("results")
            if not isinstance(items, list):
                continue
            if documents is None:
                matched = items == []
            else:
                matched = len(items) == 1 and items[0].get("source_id") == source_id
                matched = matched and (documents < 0 or items[0].get("documents") == documents)
            if matched:
                require(row.get("_UID") == str(account.pw_uid), "HTTP_JOURNAL_UID_MISMATCH")
                return value
        raise Rejected("HTTP_JOURNAL_RESULT_NOT_OBSERVED")

    def state():
        with connect() as conn:
            policy = conn.execute(
                "SELECT *,next_attempt>clock_timestamp() AS future, "
                "next_attempt-clock_timestamp() AS wait "
                "FROM ow.collection_state WHERE source_id=%s",
                (source_id,),
            ).fetchone()
            runs = conn.execute(
                "SELECT * FROM ow.collection_runs WHERE source_id=%s ORDER BY started_at,run_id",
                (source_id,),
            ).fetchall()
            docs = conn.execute(
                "SELECT * FROM ow.documents WHERE source_id=%s ORDER BY document_id", (source_id,)
            ).fetchall()
            heads = conn.execute(
                "SELECT d.document_id,d.title,d.body FROM ow.document_heads h JOIN ow.documents d "
                "USING(document_id) WHERE h.source_id=%s ORDER BY d.title",
                (source_id,),
            ).fetchall()
            jobs = conn.execute("SELECT kind,status,payload,dedup_key FROM ow.jobs").fetchall()
            snapshots = conn.execute(
                "SELECT * FROM ow.snapshots WHERE source_id=%s", (source_id,)
            ).fetchall()
            source = conn.execute(
                "SELECT enabled,last_error,last_success FROM ow.sources WHERE source_id=%s",
                (source_id,),
            ).fetchone()
        return policy, runs, docs, heads, jobs, snapshots, source

    def validate_evidence(current, expected_raws, expected_documents):
        policy, runs, docs, heads, jobs, snapshots, source = current
        require(
            len(docs) == expected_documents and len(jobs) == expected_documents,
            "HTTP_DOCUMENT_JOB_COUNT_MISMATCH",
        )
        require(len(heads) == 2 and source["enabled"], "HTTP_HEAD_OR_SOURCE_MISMATCH")
        doc_ids = {row["document_id"] for row in docs}
        doc_by_id = {row["document_id"]: row for row in docs}
        require(
            {row["payload"]["document_id"] for row in jobs} == doc_ids, "HTTP_JOB_DOCUMENT_MISMATCH"
        )
        require(
            all(
                row["kind"] == "document.accepted"
                and row["status"] == "ready"
                and row["dedup_key"] == row["payload"]["document_id"]
                and row["payload"]["snapshot_id"]
                == doc_by_id[row["payload"]["document_id"]]["snapshot_id"]
                for row in jobs
            ),
            "HTTP_JOB_CONTRACT_MISMATCH",
        )
        store = EvidenceStore(STATE / "evidence", read_only=True)
        snapshot_by_id = {row["snapshot_id"]: row for row in snapshots}
        raw_values = set()
        for row in docs:
            snapshot = snapshot_by_id[row["snapshot_id"]]
            raw_values.add(store.get(snapshot["raw_sha256"]))
            require(
                store.get(snapshot["text_sha256"]) == row["body"].encode(),
                "HTTP_TEXT_EVIDENCE_MISMATCH",
            )
        require(raw_values == expected_raws, "HTTP_RAW_EVIDENCE_MISMATCH")
        require(
            all(
                path.stat().st_uid == account.pw_uid
                for path in (STATE / "evidence").rglob("*")
                if path.is_file()
            ),
            "HTTP_EVIDENCE_UID_MISMATCH",
        )

    def entries():
        return sorted(
            str(path.relative_to(STATE / "evidence")) for path in (STATE / "evidence").rglob("*")
        )

    def timer_diagnostic(reason, network, before_trigger):
        # Report only bounded states/counts; never print raw journals or properties.
        diagnostic = {"reason": reason}
        try:
            states = {"active", "inactive", "failed", "activating", "deactivating", "unknown"}
            substates = {
                "waiting",
                "elapsed",
                "dead",
                "running",
                "start",
                "start-pre",
                "start-post",
                "stop",
                "stop-sigterm",
                "stop-sigkill",
                "failed",
            }
            results = {
                "success",
                "exit-code",
                "signal",
                "timeout",
                "start-limit-hit",
                "resources",
                "oom-kill",
                "protocol",
                "condition",
            }
            timer_active = False
            for label, name in (("timer", TIMER), ("service", SERVICE)):
                values = command(
                    [
                        "systemctl",
                        "show",
                        name,
                        "--property=ActiveState",
                        "--property=SubState",
                        "--property=Result",
                    ]
                ).splitlines()
                observed_values = dict(line.split("=", 1) for line in values if "=" in line)
                if label == "timer":
                    timer_active = observed_values.get("ActiveState") == "active"
                for field, accepted in (
                    ("ActiveState", states),
                    ("SubState", substates),
                    ("Result", results),
                ):
                    value = observed_values.get(field)
                    diagnostic[label + "_" + field] = value if value in accepted else "other"
            diagnostic["raw_trigger_available"] = timer_active
            diagnostic["timer_trigger_advanced"] = (
                timer_last_trigger() > before_trigger if timer_active else False
            )
            timers = command(["systemctl", "show", TIMER, "--property=TimersMonotonic", "--value"])
            diagnostic["initial_active_arm_present"] = "OnActiveUSec" in timers
            diagnostic["recurring_inactive_arm_present"] = "OnUnitInactiveUSec" in timers
            current = state()
            diagnostic["collection_run_count"] = min(len(current[1]), 100)
            diagnostic["http_request_count"] = min(len(network.observations()), 100)
            diagnostic["sql_due"] = current[0] is not None and not current[0]["future"]
        except Exception:
            diagnostic["diagnostic_incomplete"] = True
        print("PUBLIC_DEPLOYMENT_DIAGNOSTIC=" + json.dumps(diagnostic, sort_keys=True), flush=True)

    def stop_owned_units():
        command(["systemctl", "stop", TIMER, SERVICE], allowed=(0, 5), timeout=30)
        for name in (SERVICE, TIMER):
            require(
                command(["systemctl", "is-active", name], allowed=(0, 3, 4)).strip()
                in ("inactive", "failed", "unknown"),
                "HTTP_UNIT_STILL_ACTIVE",
            )

    with ReferenceNetwork(before_close=stop_owned_units) as network:
        try:
            for directory in (service_dir, timer_dir):
                if not directory.exists():
                    directory.mkdir(mode=0o755)
                    owned.append(directory)
            override = service_dir / "enabled-http.conf"
            owned.append(override)
            write_private(
                override,
                "[Service]\nNetworkNamespacePath="
                + str(network.namespace_path)
                + "\nBindReadOnlyPaths="
                + str(network.hosts_file)
                + ":/etc/hosts\n",
                mode=0o644,
            )
            timer_override = timer_dir / "accelerated-fixture.conf"
            owned.append(timer_override)
            write_private(
                timer_override,
                "[Timer]\nOnBootSec=\nOnUnitInactiveSec=\n"
                "OnActiveSec=1s\nOnUnitInactiveSec=1s\n"
                "RandomizedDelaySec=0\nAccuracySec=100ms\n",
                mode=0o644,
            )
            (CONFIG / "collector.env").write_text(
                collector_environment(FIXTURE_UNIX_DSN, shared_gid)
            )
            (CONFIG / "sources.json").write_text(
                json.dumps(
                    {
                        "sources": [
                            {
                                "source_id": source_id,
                                "url": network.url,
                                "enabled": True,
                                "poll_seconds": 60,
                            }
                        ]
                    }
                )
            )
            command(["systemctl", "daemon-reload"])
            network.set_phase("v1")
            started = str(time.time())
            command(["systemctl", "start", SERVICE], timeout=30)
            first_result = observed(started, "complete", 2)
            require(first_result["results"][0]["status"] == "success", "HTTP_FIRST_RESULT_FAILED")
            first = state()
            validate_evidence(first, {FEED_V1}, 2)
            require(
                len(first[1]) == 1
                and first[1][0]["http_status"] == 200
                and first[1][0]["status"] == "succeeded",
                "HTTP_FIRST_RUN_MISMATCH",
            )
            require(
                [(r["title"], r["body"]) for r in first[3]]
                == [("One", "First evidence"), ("Two", "Second evidence")],
                "HTTP_FIRST_CONTENT_MISMATCH",
            )
            require(
                network.observations()
                == [
                    {"phase": "v1", "status": 200, "if_none_match": None, "if_modified_since": None}
                ],
                "HTTP_FIRST_REQUEST_MISMATCH",
            )
            original_entries = entries()
            # Preflight refuses known units and this fresh fixture has never
            # activated its timer. There is no historical trigger to preserve;
            # querying an inactive, unloaded D-Bus object would be unreliable.
            before_trigger = 0
            force_due()
            # The fixture's initial arm is relative to timer activation. An
            # OnUnitInactiveSec-only timer may have no retained service timestamp
            # after an inactive oneshot was unloaded. Reset probe history without
            # changing any production rate limit or timer configuration.
            # An inactive timer may not be loaded yet; resetting that unit would
            # fail before its first arm. Only clear previous service probe state.
            command(["systemctl", "reset-failed", SERVICE], allowed=(0, 1))
            started = str(time.time())
            command(["systemctl", "start", TIMER])
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                current = state()
                if len(current[1]) == 2 and current[1][-1]["status"] == "succeeded":
                    break
                time.sleep(0.2)
            else:
                timer_diagnostic("HTTP_TIMER_TICK_NOT_OBSERVED", network, before_trigger)
                raise Rejected("HTTP_TIMER_TICK_NOT_OBSERVED")
            # Wait for the admitted oneshot to emit its result before stopping scheduling.
            while time.monotonic() < deadline:
                if (
                    command(["systemctl", "is-active", SERVICE], allowed=(0, 3)).strip()
                    == "inactive"
                ):
                    break
                time.sleep(0.1)
            else:
                timer_diagnostic("HTTP_TIMER_SERVICE_DID_NOT_SETTLE", network, before_trigger)
                raise Rejected("HTTP_TIMER_SERVICE_DID_NOT_SETTLE")
            # Capture runtime trigger evidence while the timer is still active.
            # Stopping an inactive unit permits GC/unload; a later show may load
            # a fresh object with no retained in-memory last-trigger timestamp.
            triggered = timer_last_trigger()
            if triggered <= before_trigger:
                timer_diagnostic("HTTP_TIMER_LAST_TRIGGER_UNCHANGED", network, before_trigger)
                raise Rejected("HTTP_TIMER_LAST_TRIGGER_UNCHANGED")
            command(["systemctl", "stop", TIMER, SERVICE])
            timer_result = observed(started, "complete", 0)
            require(
                timer_result["results"][0]["status"] == "not_modified",
                "HTTP_TIMER_304_RESULT_MISMATCH",
            )
            second = state()
            validate_evidence(second, {FEED_V1}, 2)
            require(
                len(second[1]) == 2
                and second[1][-1]["http_status"] == 304
                and entries() == original_entries,
                "HTTP_304_DUPLICATED_ARTIFACTS",
            )
            requests = network.observations()
            require(
                len(requests) == 2
                and requests[-1]["status"] == 304
                and requests[-1]["if_none_match"] == '"v1"',
                "HTTP_CONDITIONAL_REQUEST_MISMATCH",
            )
            network.set_phase("fail")
            force_due()
            started = str(time.time())
            command(["systemctl", "start", SERVICE], allowed=(1,), timeout=30)
            failure_result = observed(started, "failed", -1)
            require(
                failure_result["results"][0]["error"] == "SOURCE_HTTP_ERROR",
                "HTTP_FAILURE_CODE_MISMATCH",
            )
            failed = state()
            validate_evidence(failed, {FEED_V1}, 2)
            require(
                len(failed[1]) == 3
                and failed[1][-1]["status"] == "failed"
                and failed[1][-1]["error_code"] == "SOURCE_HTTP_ERROR"
                and failed[0]["failures"] == 1
                and failed[0]["future"]
                and 90 < failed[0]["wait"].total_seconds() <= 120
                and failed[6]["last_error"] == "SOURCE_HTTP_ERROR",
                "HTTP_FAILURE_BACKOFF_MISMATCH",
            )
            require(
                all(
                    failed[0][key] == second[0][key]
                    for key in ("etag", "last_modified", "raw_sha256")
                )
                and entries() == original_entries,
                "HTTP_FAILURE_ADVANCED_ARTIFACTS",
            )
            require(
                len(network.observations()) == 3 and network.observations()[-1]["status"] == 503,
                "HTTP_503_NOT_OBSERVED",
            )
            command(["systemctl", "reset-failed", SERVICE])
            started = str(time.time())
            command(["systemctl", "start", SERVICE], timeout=30)
            observed(started, "complete")
            require(
                len(network.observations()) == 3 and len(state()[1]) == 3, "HTTP_NOT_DUE_DISPATCHED"
            )
            network.set_phase("v2")
            force_due()
            started = str(time.time())
            command(["systemctl", "start", SERVICE], timeout=30)
            # "documents" counts processed items, including the reused head.
            # FEED_V2 changes only item Two: one new version/job, three retained.
            changed_result = observed(started, "complete", 2)
            require(
                changed_result["results"][0]["status"] == "success", "HTTP_CHANGED_RESULT_FAILED"
            )
            changed = state()
            validate_evidence(changed, {FEED_V1, FEED_V2}, 3)
            require(
                changed[3][0]["document_id"] == first[3][0]["document_id"]
                and changed[3][1]["document_id"] != first[3][1]["document_id"],
                "HTTP_CHANGED_ITEM_REUSE_MISMATCH",
            )
            require(
                len(changed[1]) == 4
                and changed[1][-1]["http_status"] == 200
                and changed[0]["failures"] == 0
                and changed[6]["last_error"] is None,
                "HTTP_CHANGED_RUN_MISMATCH",
            )
            require(
                [(r["title"], r["body"]) for r in changed[3]]
                == [("One", "First evidence"), ("Two", "Changed evidence")],
                "HTTP_CHANGED_HEAD_CONTENT_MISMATCH",
            )
            requests = network.observations()
            require(
                len(requests) == 4
                and requests[-1]["phase"] == "v2"
                and requests[-1]["status"] == 200
                and requests[-1]["if_none_match"] is None
                and requests[-1]["if_modified_since"] is None,
                "HTTP_FAILURE_REPLAY_NOT_UNCONDITIONAL",
            )
            operational_result = (
                operational_service_acceptance(*operational_accounts)
                if operational_accounts is not None
                else {}
            )
            html_result = html_service_acceptance(
                account, network, operational_accounts=operational_accounts
            )
            return {
                **operational_result,
                **html_result,
                "enabled_http_tick": True,
                "conditional_304_no_duplicates": True,
                "http_failure_backoff": True,
                "retry_after_seconds_persisted": True,
                "not_due_no_http": True,
                "changed_feed_immutable_versions": True,
                "job_and_cas_evidence_verified": True,
                "accelerated_timer_triggered": True,
                "enabled_http_journal_service_uid": True,
                "disconnected_namespace_fixture": True,
                "unix_socket_scram_verified": True,
            }
        finally:
            stop_owned_units()
            for path in reversed(owned):
                path.rmdir() if path.is_dir() else path.unlink(missing_ok=True)
            command(["systemctl", "daemon-reload"])
            command(["systemctl", "reset-failed", SERVICE], allowed=(0, 1, 5))
            (CONFIG / "collector.env").write_text(
                collector_environment(FIXTURE_COLLECTOR_DSN, shared_gid)
            )
            (CONFIG / "sources.json").write_text(
                json.dumps(
                    {
                        "sources": [
                            {
                                "source_id": "reference-disabled",
                                "url": "https://fixture.invalid/disabled",
                                "enabled": False,
                            }
                        ]
                    }
                )
            )


def html_service_acceptance(account, network, *, operational_accounts=None):
    """Installed collector/worker/reader HTML checks inside the already owned fixture."""
    import psycopg
    from psycopg.rows import dict_row
    from reference_network import HTML_PAGES, HTML_SAME, HTML_V1, HTML_V2

    from osint_workbench.errors import WorkbenchError
    from osint_workbench.evidence import EvidenceStore
    from osint_workbench.text import digest

    source_id = "reference-html"
    text_one = "Static HTML evidence\nFirst HTML text."
    text_two = "Static HTML evidence\nChanged HTML text."
    store = EvidenceStore(STATE / "evidence", read_only=True)
    (CONFIG / "sources.json").write_text(
        json.dumps(
            {
                "sources": [
                    {
                        "source_id": source_id,
                        "url": network.url,
                        "enabled": True,
                        "poll_seconds": 60,
                        "adapter": "static-html/1",
                        "rights": "all-existing-uses-permitted",
                        "request_billing": "unmetered",
                    }
                ]
            }
        )
    )

    def state():
        with psycopg.connect(FIXTURE_ADMIN_DSN, row_factory=dict_row) as conn:
            policy = conn.execute(
                "SELECT * FROM ow.collection_state WHERE source_id=%s", (source_id,)
            ).fetchone()
            runs = conn.execute(
                "SELECT * FROM ow.collection_runs WHERE source_id=%s ORDER BY started_at,run_id",
                (source_id,),
            ).fetchall()
            docs = conn.execute(
                "SELECT * FROM ow.documents WHERE source_id=%s ORDER BY document_id", (source_id,)
            ).fetchall()
            snapshots = conn.execute(
                "SELECT * FROM ow.snapshots WHERE source_id=%s ORDER BY snapshot_id", (source_id,)
            ).fetchall()
            heads = conn.execute(
                "SELECT document_id FROM ow.document_heads WHERE source_id=%s", (source_id,)
            ).fetchall()
            source = conn.execute(
                "SELECT last_error,last_success FROM ow.sources WHERE source_id=%s", (source_id,)
            ).fetchone()
            jobs = conn.execute(
                "SELECT kind,status,payload FROM ow.jobs WHERE kind='document.accepted' "
                "AND payload->>'document_id'=ANY(%s::text[]) ORDER BY job_id",
                ([d["document_id"] for d in docs],),
            ).fetchall()
        return policy, runs, docs, snapshots, heads, source, jobs

    def journal(unit, since, principal, predicate):
        command(["journalctl", "--sync"])
        raw = command(
            ["journalctl", "--unit", unit, f"--since=@{since}", "--output=json", "--no-pager"]
        )
        for line in raw.splitlines():
            row = json.loads(line)
            try:
                value = json.loads(row.get("MESSAGE", ""))
            except (ValueError, TypeError):
                continue
            if isinstance(value, dict) and predicate(value):
                require(row.get("_UID") == str(principal.pw_uid), "HTML_SERVICE_UID_MISMATCH")
                return value
        raise Rejected("HTML_SERVICE_RESULT_NOT_OBSERVED")

    def tick(phase, expected, *, documents=None, failed=False, force=True):
        network.set_phase(phase)
        if force:
            with psycopg.connect(FIXTURE_ADMIN_DSN) as conn:
                conn.execute(
                    "UPDATE ow.collection_state SET next_attempt=clock_timestamp()-interval '1 s' "
                    "WHERE source_id=%s",
                    (source_id,),
                )
        command(["systemctl", "reset-failed", SERVICE], allowed=(0, 1, 5))
        started = str(time.time())
        command(["systemctl", "start", SERVICE], allowed=(1,) if failed else (0,), timeout=30)
        result = journal(
            SERVICE,
            started,
            account,
            lambda value: (
                value.get("status") == ("failed" if failed else "complete")
                and isinstance(value.get("results"), list)
                and len(value["results"]) == 1
                and value["results"][0].get("source_id") == source_id
            ),
        )["results"][0]
        require(result.get("error" if failed else "status") == expected, "HTML_RESULT_MISMATCH")
        if documents is not None:
            require(result.get("documents") == documents, "HTML_ACCEPTED_COUNT_MISMATCH")
        return state()

    def evidence(current, bodies, raws):
        _, _, docs, snapshots, heads, _, jobs = current
        require(len(docs) == len(jobs) == len(bodies) and len(heads) == 1, "HTML_IDENTITY_COUNT")
        require({d["body"] for d in docs} == set(bodies), "HTML_NORMALIZED_TEXT_MISMATCH")
        by_id = {r["snapshot_id"]: r for r in snapshots}
        require(len(by_id) == len(docs), "HTML_SNAPSHOT_COUNT")
        for doc in docs:
            snapshot = by_id[doc["snapshot_id"]]
            expected_raw = HTML_V1 if doc["body"] == text_one else HTML_V2
            expected_text = digest(doc["body"].encode())
            expected_snapshot = digest(
                json.dumps(
                    [source_id, digest(expected_raw), expected_text, "static-html/1"]
                ).encode()
            )
            expected_document = digest(
                json.dumps(
                    [
                        source_id,
                        digest(network.url.encode()),
                        expected_snapshot,
                        "Synthetic HTML",
                        None,
                    ]
                ).encode()
            )
            require(
                doc["external_key"] == digest(network.url.encode())
                and doc["title"] == "Synthetic HTML"
                and doc["published_at"] is None
                and snapshot["extractor"] == "static-html/1"
                and snapshot["snapshot_id"] == expected_snapshot
                and doc["document_id"] == expected_document
                and snapshot["text_sha256"] == expected_text
                and snapshot["raw_sha256"] == digest(expected_raw)
                and store.get(snapshot["text_sha256"]) == doc["body"].encode()
                and store.get(snapshot["raw_sha256"]) == expected_raw,
                "HTML_PROVENANCE_MISMATCH",
            )
        for raw in raws:
            require(store.get(digest(raw)) == raw, "HTML_RAW_EVIDENCE_MISMATCH")

    first = tick("html-v1", "success", documents=1)
    evidence(first, {text_one}, {HTML_V1})
    first_id = first[2][0]["document_id"]
    second = tick("html-v1", "not_modified", documents=0)
    require(second[2:5] == first[2:5] and second[6] == first[6], "HTML_304_DUPLICATED_WORK")
    require(second[1][-1]["http_status"] == 304, "HTML_304_RUN_MISMATCH")
    same = tick("html-same", "success", documents=1)
    evidence(same, {text_one}, {HTML_V1, HTML_SAME})
    require(same[4] == [{"document_id": first_id}], "HTML_RAW_ONLY_CHANGE_REPLACED_HEAD")
    require(same[1][-1]["raw_sha256"] == digest(HTML_SAME), "HTML_RAW_ONLY_RUN_MISMATCH")
    changed = tick("html-v2", "success", documents=1)
    evidence(changed, {text_one, text_two}, {HTML_V1, HTML_SAME, HTML_V2})
    require(changed[4] != first[4], "HTML_CHANGED_TEXT_REUSED_HEAD")
    failed = tick("html-invalid", "HTML_ENCODING_UNSUPPORTED", failed=True)
    require(failed[2:5] == changed[2:5] and failed[6] == changed[6], "HTML_FAILURE_MUTATED_WORK")
    require(
        all(failed[0][k] == changed[0][k] for k in ("etag", "last_modified", "raw_sha256"))
        and failed[5]["last_success"] == changed[5]["last_success"]
        and failed[5]["last_error"] == "HTML_ENCODING_UNSUPPORTED"
        and failed[1][-1]["status"] == "failed",
        "HTML_FAILURE_ADVANCED_ACCEPTANCE",
    )
    try:
        store.get(digest(HTML_PAGES["html-invalid"]))
    except WorkbenchError as exc:
        require(exc.code == "EVIDENCE_UNAVAILABLE", "HTML_INVALID_RAW_CHECK_FAILED")
    else:
        raise Rejected("HTML_INVALID_RAW_ADMITTED")
    recovered = tick("html-v2", "success", documents=1)
    evidence(recovered, {text_one, text_two}, {HTML_V1, HTML_SAME, HTML_V2})
    require(
        recovered[2:5] == changed[2:5] and recovered[6] == changed[6],
        "HTML_RECOVERY_DUPLICATED_WORK",
    )
    requests = network.observations()[-6:]
    require(
        [r["status"] for r in requests] == [200, 304, 200, 200, 200, 200]
        and requests[1]["if_none_match"] == '"html-v1"'
        and requests[-1]["if_none_match"] is None
        and requests[-1]["if_modified_since"] is None,
        "HTML_CONDITIONAL_RECOVERY_MISMATCH",
    )
    if operational_accounts is not None:
        worker, observer, _ = operational_accounts
        started = str(time.time())
        command(["systemctl", "reset-failed", WORK_SERVICE], allowed=(0, 1, 5))
        command(["systemctl", "start", WORK_SERVICE], timeout=30)
        journal(
            WORK_SERVICE,
            started,
            worker,
            lambda value: (
                value.get("kind") == "chunk_worker_tick"
                and value.get("attempted") == value.get("succeeded") == 2
                and value.get("failed") == value.get("superseded") == 0
            ),
        )
        with psycopg.connect(FIXTURE_ADMIN_DSN, row_factory=dict_row) as conn:
            chunks = conn.execute(
                "SELECT c.*,d.body AS document_body FROM ow.chunks c JOIN ow.documents d "
                "USING(document_id) WHERE d.source_id=%s",
                (source_id,),
            ).fetchall()
        require(
            len(chunks) == 2
            and all(
                c["body"] == c["document_body"][c["start_offset"] : c["end_offset"]]
                and digest(c["body"].encode()) == c["text_sha256"]
                for c in chunks
            )
            and all(j["status"] == "succeeded" for j in state()[6]),
            "HTML_CHUNK_PROVENANCE_MISMATCH",
        )
        probe = APP / "html-read.py"
        write_private(probe, HTML_READ_PROBE, mode=0o644)
        directory = UNIT_ROOT / f"{HEALTH_SERVICE}.d"
        require(directory.is_dir(), "HTML_READER_OVERRIDE_DIRECTORY_MISSING")
        override = directory / "html-read.conf"
        require(not override.exists(), "HTML_READER_OVERRIDE_EXISTS")
        try:
            write_private(
                override,
                f"[Service]\nExecStart=\nExecStart={APP}/venv/bin/python {probe}\n",
                mode=0o644,
            )
            command(["systemctl", "daemon-reload"])
            started = str(time.time())
            command(["systemctl", "start", HEALTH_SERVICE], timeout=30)
            journal(
                HEALTH_SERVICE,
                started,
                observer,
                lambda value: value == {"kind": "html_reader_probe", "verified": True},
            )
        finally:
            command(["systemctl", "stop", HEALTH_SERVICE], allowed=(0, 5), timeout=20)
            override.unlink(missing_ok=True)
            command(["systemctl", "daemon-reload"])
    return {
        "html_service_collector_uid_tested": True,
        "html_conditional_reuse_versions_tested": True,
        "html_parser_failure_recovery_tested": True,
        "html_raw_text_extractor_identity_tested": True,
        "html_worker_reader_tested": operational_accounts is not None,
    }


HTML_READ_PROBE = r"""
import json,os
from pathlib import Path
from osint_workbench.database import Database
from osint_workbench.evidence import EvidenceStore
from osint_workbench.service import ReadService
service = ReadService(Database(os.environ['OW_READER_DSN']),
                      EvidenceStore(Path(os.environ['OW_EVIDENCE_ROOT']), read_only=True))
rows = [r for r in service.search('HTML')['results'] if r['source_id'] == 'reference-html']
assert len(rows) == 1 and rows[0]['title'] == 'Synthetic HTML'
document = service.document(rows[0]['document_id'])
assert document['text'] == 'Static HTML evidence\nChanged HTML text.'
assert document['integrity'] == 'verified'
proof = service.evidence(document['snapshot_id'])
assert proof['extractor'] == 'static-html/1' and proof['integrity'] == 'verified'
print(json.dumps({'kind': 'html_reader_probe', 'verified': True}))
"""


def api_service_acceptance(account, units, shared_gid, owned):
    """Real API unit, TLS and credential delivery in the disconnected namespace."""
    import secrets

    import psycopg
    from psycopg.rows import dict_row
    from reference_network import API_CERT, API_PAGES, OAUTH_ACCESS_TOKEN, ReferenceNetwork

    from osint_workbench.errors import WorkbenchError
    from osint_workbench.evidence import EvidenceStore
    from osint_workbench.text import digest

    source_id = "reference-api"
    token = secrets.token_urlsafe(32)
    credential = CONFIG / "api-token"
    write_private(credential, token, mode=0o400)
    configuration = CONFIG / "api-source.json"
    write_private(
        configuration,
        json.dumps(
            {
                "source_id": source_id,
                "endpoint": "https://feed.fixture.invalid/records",
                "enabled": True,
                "rights": "all-existing-uses-permitted",
                "request_billing": "unmetered",
                "poll_seconds": 60,
                "auth": {
                    "kind": "bearer",
                    "context": "synthetic-account-v1",
                    "credential": {"kind": "systemd", "name": "provider-token"},
                },
            }
        ),
        mode=0o640,
    )
    os.chown(configuration, 0, account.pw_gid)
    write_private(CONFIG / "api.env", collector_environment(FIXTURE_UNIX_DSN, shared_gid))
    service_dir = UNIT_ROOT / f"{API_SERVICE}.d"
    timer_dir = UNIT_ROOT / f"{API_TIMER}.d"
    for directory in (service_dir, timer_dir):
        directory.mkdir(mode=0o755)
        owned.append(directory)
    shared = service_dir / "shared-evidence.conf"
    write_private(shared, (units / "osint-workbench-collect-shared.conf").read_text(), mode=0o644)
    owned.append(shared)
    override = service_dir / "api-fixture.conf"
    timer_override = timer_dir / "accelerated-fixture.conf"
    write_private(
        timer_override,
        "[Timer]\nOnBootSec=\nOnUnitInactiveSec=\nOnActiveSec=1s\n"
        "OnUnitInactiveSec=1s\nRandomizedDelaySec=0\nAccuracySec=100ms\n",
        mode=0o644,
    )
    owned.append(timer_override)

    def state():
        with psycopg.connect(FIXTURE_ADMIN_DSN, row_factory=dict_row) as conn:
            schedule = conn.execute(
                "SELECT s.last_success,s.last_error,c.api_cursor,c.api_page,c.failures,"
                "c.next_attempt>clock_timestamp() AS future,"
                "extract(epoch FROM c.next_attempt-clock_timestamp()) AS wait "
                "FROM ow.sources s JOIN ow.collection_state c USING(source_id) WHERE source_id=%s",
                (source_id,),
            ).fetchone()
            runs = conn.execute(
                "SELECT status,error_code,raw_sha256 FROM ow.collection_runs WHERE source_id=%s "
                "ORDER BY started_at,run_id",
                (source_id,),
            ).fetchall()
            docs = conn.execute(
                "SELECT document_id,title,body FROM ow.documents WHERE source_id=%s ORDER BY title",
                (source_id,),
            ).fetchall()
            jobs = conn.execute(
                "SELECT j.status FROM ow.jobs j JOIN ow.documents d "
                "ON j.payload->>'document_id'=d.document_id WHERE d.source_id=%s "
                "AND j.kind='document.accepted'",
                (source_id,),
            ).fetchall()
            chunks = conn.execute(
                "SELECT c.body FROM ow.chunks c JOIN ow.documents d USING(document_id) "
                "WHERE d.source_id=%s ORDER BY d.title",
                (source_id,),
            ).fetchall()
        return schedule, runs, docs, jobs, chunks

    def force_due():
        with psycopg.connect(FIXTURE_ADMIN_DSN) as conn:
            conn.execute(
                "UPDATE ow.collection_state SET next_attempt=clock_timestamp()-interval '1 second' "
                "WHERE source_id=%s",
                (source_id,),
            )

    def tick(expected, *, failed=False):
        command(["systemctl", "reset-failed", API_SERVICE], allowed=(0, 1, 5))
        since = str(time.time())
        command(["systemctl", "start", API_SERVICE], allowed=(1,) if failed else (0,), timeout=30)
        command(["journalctl", "--sync"])
        raw = command(
            [
                "journalctl",
                "--unit",
                API_SERVICE,
                f"--since=@{since}",
                "--output=json",
                "--no-pager",
            ]
        )
        observed = False
        for line in raw.splitlines():
            row = json.loads(line)
            message = row.get("MESSAGE", "")
            require(
                token not in message and OAUTH_ACCESS_TOKEN not in message,
                "API_JOURNAL_TOKEN_DISCLOSURE",
            )
            try:
                value = json.loads(message)
            except (ValueError, TypeError):
                continue
            if isinstance(value, dict) and (value.get("error") or value.get("status")) == expected:
                require(row.get("_UID") == str(account.pw_uid), "API_JOURNAL_UID_MISMATCH")
                observed = True
        require(observed, "API_JOURNAL_RESULT_NOT_OBSERVED")
        return state()

    def stop():
        command(["systemctl", "stop", API_TIMER, API_SERVICE], allowed=(0, 5), timeout=20)
        for unit in (API_TIMER, API_SERVICE):
            require(
                command(["systemctl", "is-active", unit], allowed=(0, 3, 4)).strip()
                in {"inactive", "failed", "unknown"},
                "API_UNIT_STILL_ACTIVE",
            )

    with ReferenceNetwork(api_token=token, before_close=stop) as network:
        write_private(
            override,
            "[Service]\nNetworkNamespacePath="
            + str(network.namespace_path)
            + "\nBindReadOnlyPaths="
            + str(network.hosts_file)
            + ":/etc/hosts\n"
            + "LoadCredential=provider-token:"
            + str(credential)
            + "\n"
            + "Environment=SSL_CERT_FILE="
            + str(APP / "api-trust.pem")
            + "\n",
            mode=0o644,
        )
        owned.append(override)
        # Only this disposable service trusts the generated peer; production TLS
        # verification remains enabled. The root-only peer key is never copied.
        trust = APP / "api-trust.pem"
        write_private(trust, API_CERT.read_text(), mode=0o644)
        command(["systemctl", "daemon-reload"])
        first = tick("partial")
        require(
            first[0]["last_success"] is None
            and first[0]["last_error"] == "API_PARTIAL"
            and first[0]["api_cursor"] == "page-2"
            and first[0]["api_page"] == 1
            and first[1]
            == [
                {
                    "status": "failed",
                    "error_code": "API_PARTIAL",
                    "raw_sha256": digest(API_PAGES["v1"]),
                }
            ]
            and len(first[2]) == len(first[3]) == 1,
            "API_PARTIAL_STATE_MISMATCH",
        )
        count = len(network.observations())
        tick("not_due")
        require(
            len(network.observations()) == count and state()[1:] == first[1:],
            "API_NOT_DUE_DISPATCH",
        )
        network.set_phase("v2")
        force_due()
        command(["systemctl", "start", API_TIMER])
        deadline = time.monotonic() + 15
        while len(network.observations()) == count:
            require(time.monotonic() < deadline, "API_TIMER_NO_REQUEST")
            time.sleep(0.1)
        while command(["systemctl", "is-active", API_SERVICE], allowed=(0, 3, 4)).strip() in {
            "active",
            "activating",
            "deactivating",
        }:
            require(time.monotonic() < deadline, "API_TIMER_DID_NOT_SETTLE")
            time.sleep(0.1)
        require(timer_last_trigger(API_TIMER) > 0, "API_TIMER_NOT_TRIGGERED")
        stop()
        terminal = state()
        require(
            terminal[0]["last_success"] is not None
            and terminal[0]["last_error"] is None
            and terminal[0]["api_cursor"] is None
            and terminal[0]["api_page"] == 0
            and terminal[1][-1]
            == {"status": "succeeded", "error_code": None, "raw_sha256": digest(API_PAGES["v2"])}
            and [(d["title"], d["body"]) for d in terminal[2]]
            == [("API One", "First API evidence"), ("API Two", "Second API evidence")]
            and len(terminal[3]) == 2,
            "API_TERMINAL_STATE_MISMATCH",
        )
        store = EvidenceStore(STATE / "evidence", read_only=True)
        require(
            all(store.get(digest(API_PAGES[p])) == API_PAGES[p] for p in ("v1", "v2")),
            "API_RAW_MISMATCH",
        )
        require(
            all(o["authorized"] and o["path_ok"] for o in network.observations()),
            "API_REQUEST_CONTRACT_MISMATCH",
        )
        # An incorrect loaded token is refused at the actual peer, then replacing
        # the source file takes effect on the next service activation only.
        network.set_phase("v1")
        credential.write_text("synthetic-invalid-token")
        force_due()
        denied = tick("API_AUTHENTICATION_FAILED", failed=True)
        require(
            denied[2:] == terminal[2:] and network.observations()[-1]["status"] == 401,
            "API_AUTH_FAILURE_MUTATED_EVIDENCE",
        )
        credential.write_text(token)
        network.set_phase("fail")
        force_due()
        failure = tick("SOURCE_HTTP_ERROR", failed=True)
        require(
            failure[0]["wait"] > 110
            and failure[2:] == terminal[2:]
            and failure[0]["last_success"] == terminal[0]["last_success"],
            "API_BACKOFF_OR_FRESHNESS_MISMATCH",
        )
        count = len(network.observations())
        tick("not_due")
        require(len(network.observations()) == count, "API_BACKOFF_DISPATCH")
        network.set_phase("v1")
        force_due()
        recovered = tick("partial")
        require(recovered[2:] == terminal[2:], "API_RECOVERY_DUPLICATED_DOCUMENTS")
        # Drop the selected credential name, retaining delivery of a different
        # name. Application refusal must precede any provider HTTP request.
        config = json.loads(configuration.read_text())
        config["auth"]["credential"]["name"] = "missing-token"
        configuration.write_text(json.dumps(config))
        force_due()
        count = len(network.observations())
        tick("CREDENTIAL_UNAVAILABLE", failed=True)
        require(len(network.observations()) == count, "API_MISSING_SECRET_DISPATCH")
        config["auth"]["credential"]["name"] = "provider-token"
        configuration.write_text(json.dumps(config))
        force_due()
        tick("partial")
        network.set_phase("v2")
        force_due()
        tick("success")
        command(["systemctl", "reset-failed", WORK_SERVICE], allowed=(0, 1, 5))
        command(["systemctl", "start", WORK_SERVICE], timeout=30)
        processed = state()
        require(
            len(processed[3]) == 2
            and all(j["status"] == "succeeded" for j in processed[3])
            and processed[4] == [{"body": "First API evidence"}, {"body": "Second API evidence"}],
            "API_DOWNSTREAM_CHUNKS_MISMATCH",
        )
        probe = APP / "api-read.py"
        write_private(probe, API_READ_PROBE, mode=0o644)
        reader_override = UNIT_ROOT / f"{HEALTH_SERVICE}.d" / "api-read.conf"
        reader_override.parent.mkdir(mode=0o755, exist_ok=True)
        if reader_override.parent not in owned:
            owned.append(reader_override.parent)
        write_private(
            reader_override,
            "[Service]\nExecStart=\nExecStart="
            + str(APP / "venv/bin/python")
            + " "
            + str(probe)
            + "\n",
            mode=0o644,
        )
        owned.append(reader_override)
        command(["systemctl", "daemon-reload"])
        command(["systemctl", "start", HEALTH_SERVICE], timeout=30)
        # The actual isolated reader probe exits nonzero unless search and exact
        # text evidence agree; no provider or writer credentials enter its unit.
        config["adapter"] = "cisa-kev/1"
        configuration.write_text(json.dumps(config))
        network.set_phase("kev")
        tick("success")
        kev = state()
        record = json.loads(API_PAGES["kev"])["vulnerabilities"][0]
        require(
            len(kev[2]) == 3
            and len(kev[3]) == 3
            and any(
                json.loads(d["body"]) == record for d in kev[2] if d["title"].startswith("CVE-")
            )
            and store.get(digest(API_PAGES["kev"])) == API_PAGES["kev"],
            "KEV_SERVICE_EVIDENCE_MISMATCH",
        )
        force_due()
        tick("success")
        require(state()[2:] == kev[2:], "KEV_REPLAY_DUPLICATED_DOCUMENTS")
        network.set_phase("kev-invalid")
        force_due()
        tick("API_PARSE_FAILED", failed=True)
        require(state()[2:] == kev[2:], "KEV_SCHEMA_FAILURE_MUTATED_DOCUMENTS")
        try:
            store.get(digest(API_PAGES["kev-invalid"]))
        except WorkbenchError as exc:
            require(exc.code == "EVIDENCE_UNAVAILABLE", "KEV_EVIDENCE_CHECK_FAILED")
        else:
            raise Rejected("KEV_INVALID_RAW_ADMITTED")
        command(["systemctl", "start", WORK_SERVICE], timeout=30)
        require(all(j["status"] == "succeeded" for j in state()[3]), "KEV_WORKER_FAILURE")
        # The fixture already owns this root-written probe and the preceding
        # synchronous oneshot reader has exited. Preserve its existing mode.
        probe.write_text(API_READ_PROBE + KEV_READ_PROBE)
        command(["systemctl", "start", HEALTH_SERVICE], timeout=30)
        before_oauth = state()[2:]
        config["auth"].update(
            kind="oauth-client-credentials",
            context="synthetic-oauth-v1",
            oauth={
                "token_endpoint": "https://feed.fixture.invalid/token",
                "client_id": "reference-client",
                "scopes": ["catalog:read"],
            },
        )
        configuration.write_text(json.dumps(config))
        network.set_phase("oauth")
        count = len(network.observations())
        tick("success")
        observed = network.observations()[count:]
        require(
            len(observed) == 2
            and [r.get("stage") for r in observed] == ["token", "resource"]
            and all(r["authorized"] and r["path_ok"] and r["status"] == 200 for r in observed),
            "OAUTH_SERVICE_EXCHANGE_MISMATCH",
        )
        require(state()[2:] == before_oauth, "OAUTH_REPLAY_DUPLICATED_DOCUMENTS")
        config["auth"]["credential"]["name"] = "missing-token"
        configuration.write_text(json.dumps(config))
        count = len(network.observations())
        tick("CREDENTIAL_UNAVAILABLE", failed=True)
        require(len(network.observations()) == count, "OAUTH_MISSING_CREDENTIAL_DISPATCH")
        config["auth"]["credential"]["name"] = "provider-token"
        configuration.write_text(json.dumps(config))
        network.set_phase("oauth-denied")
        count = len(network.observations())
        tick("OAUTH_TOKEN_REJECTED", failed=True)
        require(
            len(network.observations()) == count + 1
            and network.observations()[-1]["stage"] == "token",
            "OAUTH_DENIAL_DISPATCHED_RESOURCE",
        )
        count = len(network.observations())
        tick("not_due")
        require(len(network.observations()) == count, "OAUTH_BACKOFF_DISPATCH")
        network.set_phase("oauth")
        force_due()
        tick("success")
        require(state()[2:] == before_oauth, "OAUTH_RECOVERY_MUTATED_DOCUMENTS")
        require(OAUTH_ACCESS_TOKEN not in repr(state()), "OAUTH_SQL_TOKEN_DISCLOSURE")
        require(
            all(
                OAUTH_ACCESS_TOKEN.encode() not in p.read_bytes()
                and token.encode() not in p.read_bytes()
                for p in store.root.rglob("*")
                if p.is_file()
            ),
            "OAUTH_CAS_TOKEN_DISCLOSURE",
        )
        command(["systemctl", "start", HEALTH_SERVICE], timeout=30)
    return {
        "api_https_service_tested": True,
        "api_loaded_credential_tested": True,
        "api_partial_terminal_evidence_tested": True,
        "api_timer_activation_tested": True,
        "api_auth_failure_rotation_tested": True,
        "api_missing_credential_no_dispatch": True,
        "api_backoff_recovery_no_duplicates": True,
        "api_worker_reader_tested": True,
        "api_external_provider_tested": False,
        "kev_format_service_worker_reader_tested": True,
        "kev_replay_schema_refusal_tested": True,
        "oauth_loaded_secret_token_resource_tested": True,
        "oauth_denial_backoff_recovery_tested": True,
        "oauth_token_nonretention_tested": True,
    }


API_READ_PROBE = r"""
import os
from pathlib import Path
from osint_workbench.database import Database
from osint_workbench.evidence import EvidenceStore
from osint_workbench.service import ReadService
service = ReadService(Database(os.environ['OW_READER_DSN']),
                      EvidenceStore(Path(os.environ['OW_EVIDENCE_ROOT']), read_only=True))
result = service.search('API')
expected = {'API One': 'First API evidence', 'API Two': 'Second API evidence'}
rows = [row for row in result['results'] if row['source_id'] == 'reference-api']
assert len(rows) == 2 and {row['title'] for row in rows} == set(expected)
for row in rows:
    assert row['excerpt'] == expected[row['title']]
print('API_READER_PROBE_OK')
"""

KEV_READ_PROBE = r"""
rows = [row for row in service.search('KEV')['results'] if row['source_id'] == 'reference-api']
assert len(rows) == 1 and rows[0]['title'] == 'CVE-2099-10001: KEV Fixture'
print('KEV_READER_PROBE_OK')
"""


def local_api_service_acceptance(owned):
    """Actual non-root service and loaded token against a synthetic local peer."""
    import contextlib
    import socket
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    import psycopg

    from osint_workbench import intelligence
    from osint_workbench.database import Database
    from osint_workbench.local_api import LocalApiGenerator, LocalApiManifest

    command(
        [
            "useradd",
            "--system",
            "--user-group",
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
            "--groups",
            EVIDENCE_GROUP,
            ENRICH_ACCOUNT,
        ]
    )
    account = pwd.getpwnam(ENRICH_ACCOUNT)
    ENRICH_CONFIG.mkdir(mode=0o750)
    os.chown(ENRICH_CONFIG, 0, account.pw_gid)
    writer = Database(FIXTURE_WRITER_DSN)
    with psycopg.connect(FIXTURE_ADMIN_DSN) as conn:
        document = conn.execute("SELECT document_id FROM ow.active_documents LIMIT 1").fetchone()[0]
    calls = []
    mode = {"ambiguous": False}
    token = "synthetic-local-api-credential"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def reply(self, value):
            body = json.dumps(value).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                self.wfile.write(body)

        def authorized(self):
            valid = self.headers.get("Authorization") == "Bearer " + token
            calls.append((self.command, valid))
            return valid

        def do_GET(self):
            if not self.authorized() or self.path != "/v1/models":
                self.send_error(403)
                return
            self.reply({"data": [{"id": "synthetic"}]})

        def do_POST(self):
            if not self.authorized() or self.path != "/v1/chat/completions":
                self.send_error(403)
                return
            length = int(self.headers.get("Content-Length", "0"))
            if not 1 <= length <= 131072:
                self.send_error(413)
                return
            self.rfile.read(length)
            if mode["ambiguous"]:
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
                return
            self.reply(
                {
                    "model": "synthetic",
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {"role": "assistant", "content": '{"claims":[]}'},
                        }
                    ],
                }
            )

    peer = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=peer.serve_forever, daemon=True)
    thread.start()
    try:
        manifest = LocalApiManifest.model_validate(
            {
                "endpoint": f"http://127.0.0.1:{peer.server_port}/v1/chat/completions",
                "model": "synthetic",
                "operator_controlled": True,
                "remote_forwarding": False,
                "metered": False,
                "qualification_sha256": "a" * 64,
                "model_revision_sha256": "b" * 64,
                "data_classes": ["public"],
                "timeout_seconds": 2,
                "credential": {"kind": "systemd", "name": "local-api-token"},
            }
        )
        generator = LocalApiGenerator(manifest)
        config = ENRICH_CONFIG / "local-api.json"
        write_private(config, manifest.model_dump_json(), mode=0o640)
        os.chown(config, 0, account.pw_gid)
        environment = ENRICH_CONFIG / "runtime.env"
        write_private(
            environment,
            "OW_WRITER_DSN="
            + FIXTURE_WRITER_DSN.replace("ow_reference_writer", "ow_reference_enricher")
            + "\n",
            mode=0o640,
        )
        os.chown(environment, 0, account.pw_gid)
        credential = ENRICH_CONFIG / "local-api-token"
        write_private(credential, token)
        directory = UNIT_ROOT / f"{ENRICH_SERVICE}.d"
        directory.mkdir(mode=0o755)
        owned.append(directory)
        override = directory / "bounded-probe.conf"
        write_private(
            override,
            "[Service]\nExecStart=\n"
            "ExecStart=/opt/osint-workbench/venv/bin/osint-workbench enrich work "
            "--local-api-manifest /etc/osint-workbench-enrich/local-api.json --max-jobs 2\n",
            mode=0o644,
        )
        owned.append(override)
        command(["systemctl", "daemon-reload"])

        def enqueue(operation, selected=generator):
            return intelligence.enqueue(writer, selected, document, operation, "public")

        def tick(*, failed=False):
            since = str(time.time())
            command(["systemctl", "reset-failed", ENRICH_SERVICE])
            command(
                ["systemctl", "start", ENRICH_SERVICE], allowed=(1,) if failed else (0,), timeout=30
            )
            command(["journalctl", "--sync"])
            raw = command(
                [
                    "journalctl",
                    "--unit",
                    ENRICH_SERVICE,
                    f"--since=@{since}",
                    "--output=json",
                    "--no-pager",
                ]
            )
            require(token not in raw, "ENRICH_CREDENTIAL_RETAINED")
            for line in raw.splitlines():
                row = json.loads(line)
                try:
                    result = json.loads(row.get("MESSAGE", ""))
                except (ValueError, TypeError):
                    continue
                if isinstance(result, dict) and result.get("kind") == "local_api_enrichment_tick":
                    require(row.get("_UID") == str(account.pw_uid), "ENRICH_SERVICE_UID_MISMATCH")
                    return result
            raise Rejected("ENRICH_TICK_NOT_OBSERVED")

        for operation in ("service-one", "service-two", "service-three"):
            enqueue(operation)
        other = LocalApiGenerator(manifest.model_copy(update={"qualification_sha256": "c" * 64}))
        enqueue("other-generator", other)
        first = tick()
        require(
            first["attempted"] == 2 and first["abstained"] == 2 and first["limit_reached"],
            "ENRICH_CAP_NOT_OBSERVED",
        )
        second = tick()
        require(
            second["attempted"] == 1 and second["abstained"] == 1 and second["idle_observed"],
            "ENRICH_IDLE_NOT_OBSERVED",
        )
        before = len(calls)
        enqueue("credential-recovery")
        credential.unlink()
        command(["systemctl", "start", ENRICH_SERVICE], allowed=(1,), timeout=30)
        require(len(calls) == before, "ENRICH_MISSING_CREDENTIAL_DISPATCHED")
        write_private(credential, token)
        require(tick()["abstained"] == 1, "ENRICH_CREDENTIAL_RECOVERY_FAILED")
        mode["ambiguous"] = True
        enqueue("uncertain-one")
        enqueue("uncertain-two")
        failed = tick(failed=True)
        require(
            failed["attempted"] == 1 and failed["stopped_on_failure"],
            "ENRICH_DID_NOT_STOP_ON_FAILURE",
        )
        before = len(calls)
        restarted = tick(failed=True)
        require(
            restarted["attempted"] == 1 and restarted["failed"] == 1 and len(calls) == before,
            "ENRICH_RESTART_REDISPATCHED_UNCERTAINTY",
        )
        require(
            ENRICH_STATE.stat().st_uid == account.pw_uid
            and ENRICH_STATE.stat().st_mode & 0o777 == 0o700,
            "ENRICH_STATE_NOT_PRIVATE",
        )
        require(all(valid for _, valid in calls), "ENRICH_UNAUTHENTICATED_REQUEST")
        return {
            "local_api_service_uid_and_credential": True,
            "local_api_batch_cap_and_identity": True,
            "local_api_credential_refusal_and_recovery": True,
            "local_api_uncertainty_survives_service_restart": True,
            "local_api_model_quality_tested": False,
        }
    finally:
        peer.shutdown()
        peer.server_close()
        thread.join(timeout=5)


def operational_service_acceptance(worker, observer, owned):
    """Exercise separate non-root units only inside the guarded synthetic fixture."""
    import psycopg
    from psycopg.rows import dict_row

    def state():
        with psycopg.connect(FIXTURE_ADMIN_DSN, row_factory=dict_row) as conn:
            jobs = conn.execute(
                "SELECT kind,status,count(*) AS n FROM ow.jobs GROUP BY kind,status"
            ).fetchall()
            chunks = conn.execute(
                "SELECT c.body,c.start_offset,c.end_offset,c.text_sha256,d.body AS document_body "
                "FROM ow.chunks c JOIN ow.documents d USING(document_id)"
            ).fetchall()
            sha = conn.execute(
                "SELECT s.text_sha256 FROM ow.document_heads h JOIN ow.documents d "
                "USING(document_id) JOIN ow.snapshots s USING(snapshot_id) "
                "WHERE d.title='One'"
            ).fetchone()["text_sha256"]
        return {(r["kind"], r["status"]): r["n"] for r in jobs}, chunks, sha

    def result(unit, since, account, predicate):
        command(["journalctl", "--sync"])
        raw = command(
            ["journalctl", "--unit", unit, f"--since=@{since}", "--output=json", "--no-pager"]
        )
        for line in raw.splitlines():
            row = json.loads(line)
            try:
                value = json.loads(row.get("MESSAGE", ""))
            except (ValueError, TypeError):
                continue
            if predicate(value):
                require(row.get("_UID") == str(account.pw_uid), "OPERATIONAL_UID_MISMATCH")
                return value
        raise Rejected("OPERATIONAL_RESULT_NOT_OBSERVED")

    def override(unit, content):
        directory = UNIT_ROOT / f"{unit}.d"
        if not directory.exists():
            directory.mkdir(mode=0o755)
            owned.append(directory)
        path = directory / "operational-probe.conf"
        require(not path.exists(), "OPERATIONAL_OVERRIDE_EXISTS")
        write_private(path, content, mode=0o644)
        owned.append(path)
        command(["systemctl", "daemon-reload"])
        return path

    def restore(path):
        path.unlink()
        owned.remove(path)
        command(["systemctl", "daemon-reload"])

    def health_environment(pending):
        return (
            "OW_READER_DSN=" + reader_dsn + "\n"
            "OW_HEALTH_MAX_SOURCE_AGE_SECONDS=3600\n"
            f"OW_HEALTH_MAX_PENDING_JOBS={pending}\nOW_HEALTH_MAX_FAILED_JOBS=0\n"
        )

    writer_dsn = FIXTURE_WRITER_DSN
    reader_dsn = (
        "host=127.0.0.1 port=5432 dbname=ow_test user=ow_reference_reader "
        "password=ci-fixture-only connect_timeout=5 sslmode=disable"
    )
    write_private(WORK_CONFIG / "runtime.env", "OW_WRITER_DSN=" + writer_dsn + "\n")
    write_private(HEALTH_CONFIG / "runtime.env", health_environment(8))
    before, chunks, sha = state()
    require(
        before == {("document.accepted", "ready"): 3} and not chunks,
        "OPERATIONAL_INITIAL_QUEUE_MISMATCH",
    )
    # Actual authentication failure must not claim or discard durable work.
    (WORK_CONFIG / "runtime.env").write_text(
        "OW_WRITER_DSN="
        + writer_dsn.replace("password=ci-fixture-only", "password=wrong-fixture")
        + "\n"
    )
    command(["systemctl", "start", WORK_SERVICE], allowed=(1,), timeout=20)
    require(state()[:2] == (before, []), "WORKER_AUTH_FAILURE_MUTATED_WORK")
    (WORK_CONFIG / "runtime.env").write_text("OW_WRITER_DSN=" + writer_dsn + "\n")
    command(["systemctl", "reset-failed", WORK_SERVICE])
    started = str(time.time())
    command(["systemctl", "start", WORK_SERVICE], timeout=30)
    result(
        WORK_SERVICE,
        started,
        worker,
        lambda v: (
            isinstance(v, dict)
            and v.get("kind") == "chunk_worker_tick"
            and v.get("attempted") == 3
            and v.get("succeeded") == 3
            and v.get("failed") == 0
        ),
    )
    jobs, chunks, _ = state()
    require(
        jobs == {("document.accepted", "succeeded"): 3, ("document.chunked", "ready"): 3}
        and len(chunks) == 3,
        "WORKER_DURABLE_RESULT_MISMATCH",
    )
    from osint_workbench.text import digest

    require(
        all(
            c["body"] == c["document_body"][c["start_offset"] : c["end_offset"]]
            and digest(c["body"].encode()) == c["text_sha256"]
            for c in chunks
        ),
        "WORKER_CHUNK_PROVENANCE_MISMATCH",
    )
    started = str(time.time())
    command(["systemctl", "start", WORK_SERVICE], timeout=30)
    result(
        WORK_SERVICE,
        started,
        worker,
        lambda v: (
            isinstance(v, dict)
            and v.get("kind") == "chunk_worker_tick"
            and v.get("attempted") == 0
            and v.get("idle_observed") is True
        ),
    )
    require(state()[0] == jobs and len(state()[1]) == 3, "WORKER_RESTART_DUPLICATED_WORK")
    # Prove access with the same unit hardening and real service accounts.
    probe = APP / "operational-probe.py"
    write_private(probe, OPERATIONAL_PROBE, mode=0o644)
    for unit, account, other_config in (
        (WORK_SERVICE, worker, HEALTH_CONFIG),
        (HEALTH_SERVICE, observer, WORK_CONFIG),
    ):
        target = APP / f"owned-probe-{account.pw_name}"
        write_private(target, "synthetic writable-owner probe\n")
        os.chown(target, account.pw_uid, account.pw_gid)
        path = override(
            unit,
            "[Service]\nExecStart=\n"
            f"ExecStart={APP}/venv/bin/python {probe} {sha} {target} {other_config}\n",
        )
        started = str(time.time())
        command(["systemctl", "start", unit], timeout=20)
        result(
            unit,
            started,
            account,
            lambda v: (
                isinstance(v, dict)
                and v.get("kind") == "custody_probe"
                and all(
                    v.get(k) is True
                    for k in (
                        "cas_read",
                        "cas_write_denied",
                        "code_read_only",
                        "other_config_denied",
                        "capabilities_zero",
                    )
                )
            ),
        )
        restore(path)
    # A real CLI lexical read is run as the reader account under its service sandbox.
    path = override(
        HEALTH_SERVICE,
        f"[Service]\nExecStart=\nExecStart={APP}/venv/bin/osint-workbench search Changed\n",
    )
    started = str(time.time())
    command(["systemctl", "start", HEALTH_SERVICE], timeout=20)
    result(
        HEALTH_SERVICE,
        started,
        observer,
        lambda v: (
            isinstance(v, dict)
            and v.get("strategy") == "lexical"
            and isinstance(v.get("results"), list)
            and len(v["results"]) == 1
            and v["results"][0].get("title") == "Two"
        ),
    )
    restore(path)
    # Unsupported downstream jobs stay queued and must affect health thresholds.
    (HEALTH_CONFIG / "runtime.env").write_text(health_environment(0))
    started = str(time.time())
    command(["systemctl", "start", HEALTH_SERVICE], allowed=(1,), timeout=20)
    result(
        HEALTH_SERVICE,
        started,
        observer,
        lambda v: (
            isinstance(v, dict)
            and v.get("kind") == "aggregate_health"
            and v.get("ready") is False
            and v.get("reasons") == ["HEALTH_PENDING_JOBS_EXCEEDED"]
        ),
    )
    (HEALTH_CONFIG / "runtime.env").write_text(health_environment(8))
    command(["systemctl", "reset-failed", HEALTH_SERVICE])
    started = str(time.time())
    command(["systemctl", "start", HEALTH_SERVICE], timeout=20)
    result(
        HEALTH_SERVICE,
        started,
        observer,
        lambda v: (
            isinstance(v, dict)
            and v.get("kind") == "aggregate_health"
            and v.get("ready") is True
            and not v.get("reasons")
        ),
    )

    def accelerated_tick(timer, service, account, predicate):
        path = override(
            timer,
            "[Timer]\nOnBootSec=\nOnUnitInactiveSec=\nOnActiveSec=2s\n"
            "OnUnitInactiveSec=30s\nRandomizedDelaySec=0\nAccuracySec=100ms\n",
        )
        try:
            command(["systemctl", "reset-failed", service], allowed=(0, 1, 5))
            started = str(time.time())
            command(["systemctl", "start", timer])
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                try:
                    result(service, started, account, predicate)
                    break
                except Rejected as error:
                    if str(error) != "OPERATIONAL_RESULT_NOT_OBSERVED":
                        raise
                    time.sleep(0.2)
            else:
                raise Rejected("OPERATIONAL_TIMER_TICK_NOT_OBSERVED")
            while time.monotonic() < deadline:
                if (
                    command(["systemctl", "is-active", service], allowed=(0, 3)).strip()
                    == "inactive"
                ):
                    break
                time.sleep(0.1)
            else:
                raise Rejected("OPERATIONAL_TIMER_SERVICE_DID_NOT_SETTLE")
            require(
                command(
                    ["systemctl", "show", service, "--property=ExecMainStatus", "--value"]
                ).strip()
                == "0",
                "OPERATIONAL_TIMER_SERVICE_FAILED",
            )
            require(timer_last_trigger(timer) > 0, "OPERATIONAL_TIMER_TRIGGER_NOT_OBSERVED")
        finally:
            command(["systemctl", "stop", timer, service], allowed=(0, 5), timeout=20)
            for name in (timer, service):
                require(
                    command(["systemctl", "is-active", name], allowed=(0, 3, 4)).strip()
                    in ("inactive", "failed", "unknown"),
                    "OPERATIONAL_TIMER_STILL_ACTIVE",
                )
            restore(path)

    accelerated_tick(
        WORK_TIMER,
        WORK_SERVICE,
        worker,
        lambda v: (
            isinstance(v, dict)
            and v.get("kind") == "chunk_worker_tick"
            and v.get("attempted") == 0
            and v.get("idle_observed") is True
        ),
    )
    accelerated_tick(
        HEALTH_TIMER,
        HEALTH_SERVICE,
        observer,
        lambda v: (
            isinstance(v, dict) and v.get("kind") == "aggregate_health" and v.get("ready") is True
        ),
    )
    return {
        "operational_fixture_tested": True,
        "worker_auth_failure_no_claim": True,
        "worker_jobs_and_chunks_verified": True,
        "worker_restart_no_duplicates": True,
        "separate_account_cas_read_only": True,
        "other_role_config_denied": True,
        "reader_lexical_service_read": True,
        "health_threshold_failure_recovery": True,
        "worker_timer_activation_tested": True,
        "health_timer_activation_tested": True,
    }


OPERATIONAL_PROBE = r"""
import errno,json,os,sys
from pathlib import Path
from osint_workbench.evidence import EvidenceStore
store = EvidenceStore(Path('/var/lib/osint-workbench/evidence'), read_only=True)
sha = sys.argv[1]
value = {'kind': 'custody_probe', 'cas_read': store.get(sha) == b'First evidence'}
value['capabilities_zero'] = any(line.startswith('CapEff:') and int(line.split()[1],16) == 0
    for line in Path('/proc/self/status').read_text().splitlines())
target = store.root / sha[:2] / sha
try:
    fd = os.open(target, os.O_WRONLY | os.O_NOFOLLOW)
    os.close(fd)
    value['cas_write_denied'] = False
except OSError as exc:
    value['cas_write_denied'] = exc.errno in (errno.EACCES, errno.EPERM, errno.EROFS)
try:
    fd = os.open(sys.argv[2], os.O_WRONLY | os.O_NOFOLLOW)
    os.close(fd)
    value['code_read_only'] = False
except OSError as exc:
    value['code_read_only'] = exc.errno == errno.EROFS
value['other_config_denied'] = True
for target in [Path('/etc/osint-workbench/sources.json'), Path(sys.argv[3]) / 'runtime.env']:
    try:
        target.read_bytes()
        value['other_config_denied'] = False
    except OSError as exc:
        value['other_config_denied'] &= exc.errno in (errno.EACCES, errno.EPERM, errno.ENOENT)
print(json.dumps(value))
"""


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


def acceptance(
    venv,
    units,
    installed_units,
    dropins,
    *,
    database_fixture=False,
    enabled_http_fixture=False,
    operational_fixture=False,
):
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
    operational_accounts = None
    shared_gid = None
    if operational_fixture:
        command(["groupadd", "--system", EVIDENCE_GROUP])
        shared_gid = grp.getgrnam(EVIDENCE_GROUP).gr_gid
        accounts = []
        for username, config in ((WORK_ACCOUNT, WORK_CONFIG), (HEALTH_ACCOUNT, HEALTH_CONFIG)):
            command(
                [
                    "useradd",
                    "--system",
                    "--user-group",
                    "--no-create-home",
                    "--shell",
                    "/usr/sbin/nologin",
                    "--groups",
                    EVIDENCE_GROUP,
                    username,
                ]
            )
            role_account = pwd.getpwnam(username)
            accounts.append(role_account)
            config.mkdir(mode=0o750)
            os.chown(config, 0, role_account.pw_gid)
        STATE.mkdir(mode=0o755)
        evidence = STATE / "evidence"
        evidence.mkdir(mode=0o700)
        os.chown(evidence, account.pw_uid, shared_gid)
        evidence.chmod(0o2750)
        shared_directory = UNIT_ROOT / f"{SERVICE}.d"
        shared_directory.mkdir(mode=0o755)
        dropins.append(shared_directory)
        shared = shared_directory / "shared-evidence.conf"
        write_private(
            shared, (units / "osint-workbench-collect-shared.conf").read_text(), mode=0o644
        )
        dropins.append(shared)
        operational_accounts = (*accounts, dropins)
    names = (SERVICE, TIMER, *OPERATIONAL_UNITS) if operational_fixture else (SERVICE, TIMER)
    for name in names:
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
    database_result = (
        database_service_acceptance(account, shared_gid=shared_gid) if database_fixture else {}
    )
    http_result = (
        enabled_http_service_acceptance(
            account, shared_gid=shared_gid, operational_accounts=operational_accounts
        )
        if enabled_http_fixture
        else {}
    )
    api_result = (
        api_service_acceptance(account, units, shared_gid, dropins) if operational_fixture else {}
    )
    local_api_result = local_api_service_acceptance(dropins) if operational_fixture else {}
    probe_dir = APP / "writable-probe"
    probe_dir.mkdir(mode=0o700)
    os.chown(probe_dir, account.pw_uid, account.pw_gid)
    write_private(APP / "probe.py", PROBE, mode=0o644)
    dropin_dir = UNIT_ROOT / f"{SERVICE}.d"
    if not dropin_dir.exists():
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
        **http_result,
        **api_result,
        **local_api_result,
        "external_sources_tested": False,
        "synthetic_database_tested": database_fixture,
        "timer_activation_tested": enabled_http_fixture,
        "production_timer_durations_tested": False,
        "https_tls_tested": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-venv", type=Path, required=True)
    parser.add_argument("--units", type=Path, required=True)
    parser.add_argument("--database-fixture", action="store_true")
    parser.add_argument("--enabled-http-fixture", action="store_true")
    parser.add_argument("--operational-fixture", action="store_true")
    args = parser.parse_args()
    installed_units, dropins = [], []
    outcome = None
    failure = None
    try:
        preflight(
            args.core_venv.resolve(),
            args.units.resolve(),
            operational_fixture=args.operational_fixture,
        )
        require(
            not args.operational_fixture or (args.database_fixture and args.enabled_http_fixture),
            "OPERATIONAL_FIXTURE_REQUIRES_HTTP_AND_DATABASE",
        )
        require(
            not args.enabled_http_fixture or args.database_fixture,
            "HTTP_FIXTURE_REQUIRES_DATABASE_FIXTURE",
        )
        if args.database_fixture:
            prepare_database_fixture(
                args.core_venv.resolve(),
                enabled_http_fixture=args.enabled_http_fixture,
                operational_fixture=args.operational_fixture,
            )
        outcome = acceptance(
            args.core_venv.resolve(),
            args.units.resolve(),
            installed_units,
            dropins,
            database_fixture=args.database_fixture,
            enabled_http_fixture=args.enabled_http_fixture,
            operational_fixture=args.operational_fixture,
        )
    except Rejected as exc:
        failure = str(exc)
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        IndexError,
        subprocess.SubprocessError,
    ) as exc:
        exception_diagnostic(exc)
        failure = "ACCEPTANCE_OPERATION_FAILED"
    except Exception as exc:
        # Driver failures must not print connection strings or raw backend messages.
        exception_diagnostic(exc)
        failure = "ACCEPTANCE_OPERATION_FAILED"
    finally:
        if installed_units:
            try:
                owned_names = [path.name for path in installed_units]
                command(["systemctl", "stop", *owned_names], allowed=(0, 5), timeout=30)
                for name in owned_names:
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
