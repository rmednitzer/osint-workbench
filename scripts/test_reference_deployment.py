"""Explicit acceptance on disposable GitHub-hosted Linux runners; never imported by tests.

Requires sudo while preserving only the two GitHub runner marker variables. No
external sources or inference requests are supplied. An explicit database fixture
uses only a fixed synthetic PostgreSQL endpoint; the optional HTTP fixture is
disconnected from external networks. Guard rejection occurs
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
    if result.returncode not in allowed:
        executable = Path(argv[0]).name
        if executable not in {"systemctl", "journalctl", "useradd"}:
            executable = "other"
        action = argv[1] if len(argv) > 1 else "none"
        if action not in {
            "start",
            "stop",
            "show",
            "daemon-reload",
            "is-active",
            "reset-failed",
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

FIXTURE_UNIX_ADMIN_DSN = (
    "host=/run/ow-reference-postgres port=5432 dbname=ow_test user=postgres "
    "password=ci-fixture-only connect_timeout=5 sslmode=disable"
)
FIXTURE_UNIX_DSN = (
    "host=/run/ow-reference-postgres port=5432 dbname=ow_test user=ow_reference_collector "
    "password=ci-fixture-only connect_timeout=5 sslmode=disable"
)


def prepare_database_fixture(venv, *, enabled_http_fixture=False):
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


def enabled_http_service_acceptance(account):
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
                "SELECT *,next_attempt>clock_timestamp() AS future "
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
                for field, accepted in (
                    ("ActiveState", states),
                    ("SubState", substates),
                    ("Result", results),
                ):
                    value = observed_values.get(field)
                    diagnostic[label + "_" + field] = value if value in accepted else "other"
            trigger = command(
                ["systemctl", "show", TIMER, "--property=LastTriggerUSecMonotonic", "--value"]
            ).strip()
            diagnostic["timer_trigger_advanced"] = (
                trigger.isdecimal() and int(trigger) > before_trigger
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
            (CONFIG / "collector.env").write_text("OW_COLLECTOR_DSN=" + FIXTURE_UNIX_DSN + "\n")
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
            before_trigger = int(
                command(
                    ["systemctl", "show", TIMER, "--property=LastTriggerUSecMonotonic", "--value"]
                ).strip()
            )
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
            triggered = int(
                command(
                    ["systemctl", "show", TIMER, "--property=LastTriggerUSecMonotonic", "--value"]
                ).strip()
            )
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
            changed_result = observed(started, "complete", 2)
            require(
                changed_result["results"][0]["status"] == "success", "HTTP_CHANGED_RESULT_FAILED"
            )
            changed = state()
            validate_evidence(changed, {FEED_V1, FEED_V2}, 4)
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
            return {
                "enabled_http_tick": True,
                "conditional_304_no_duplicates": True,
                "http_failure_backoff": True,
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
                "OW_COLLECTOR_DSN=" + FIXTURE_COLLECTOR_DSN + "\n"
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
    venv, units, installed_units, dropins, *, database_fixture=False, enabled_http_fixture=False
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
    http_result = enabled_http_service_acceptance(account) if enabled_http_fixture else {}
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
        **http_result,
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
    args = parser.parse_args()
    installed_units, dropins = [], []
    outcome = None
    failure = None
    try:
        preflight(args.core_venv.resolve(), args.units.resolve())
        require(
            not args.enabled_http_fixture or args.database_fixture,
            "HTTP_FIXTURE_REQUIRES_DATABASE_FIXTURE",
        )
        if args.database_fixture:
            prepare_database_fixture(
                args.core_venv.resolve(), enabled_http_fixture=args.enabled_http_fixture
            )
        outcome = acceptance(
            args.core_venv.resolve(),
            args.units.resolve(),
            installed_units,
            dropins,
            database_fixture=args.database_fixture,
            enabled_http_fixture=args.enabled_http_fixture,
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
