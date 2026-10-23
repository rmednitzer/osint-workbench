import json
import os
import subprocess
import sys
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from osint_workbench import diagnostics
from osint_workbench.database import SCHEMA_VERSION


def test_offline_cli_never_opens_configured_application_files(tmp_path):
    # A FIFO would hang an accidental manifest read; an invalid DSN would fail a probe.
    fifo = tmp_path / "private-canary"
    os.mkfifo(fifo)
    env = {k: v for k, v in os.environ.items() if not k.startswith("OW_")}
    env.update({key: str(fifo) for key in diagnostics._CONFIGURATION})
    result = subprocess.run(
        [sys.executable, "-m", "osint_workbench.cli", "diagnose"],
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0 and result.stderr == ""
    value = json.loads(result.stdout)
    assert value["reader"]["state"] == "not_checked"
    assert all(value["configuration_present"].values())
    assert "private-canary" not in result.stdout and str(tmp_path) not in result.stdout


@pytest.mark.parametrize(
    "version,state",
    [(SCHEMA_VERSION, "compatible"), (0, "schema_mismatch"), (True, "invalid_status")],
)
def test_reader_authority_precedes_fixed_schema_projection(monkeypatch, version, state):
    calls = []
    monkeypatch.setenv("OW_READER_DSN", "private-canary")

    def validate(*, connection):
        assert connection is conn
        calls.append("authority")

    def execute(query):
        assert calls == ["authority"]
        calls.append("schema")
        return SimpleNamespace(fetchone=lambda: {"version": version, "private": "canary"})

    conn = SimpleNamespace(execute=execute)
    connections = []

    def connect():
        connections.append(conn)
        assert len(connections) == 1
        return nullcontext(conn)

    monkeypatch.setattr(
        diagnostics,
        "Database",
        lambda _: SimpleNamespace(validate_reader=validate, connect=connect),
    )
    result = diagnostics.diagnose(check_reader=True)
    assert result["reader"]["state"] == state and calls == ["authority", "schema"]
    assert connections == [conn]
    assert "canary" not in json.dumps(result)


def test_denied_authority_stops_before_schema_and_sanitizes_exception(monkeypatch):
    monkeypatch.setenv("OW_READER_DSN", "private-canary")

    calls = []

    def denied(*, connection):
        calls.append("authority")
        raise RuntimeError("private-canary")

    monkeypatch.setattr(
        diagnostics,
        "Database",
        lambda _: SimpleNamespace(validate_reader=denied, connect=lambda: nullcontext(object())),
    )
    result = diagnostics.diagnose(check_reader=True)
    assert result["reader"]["state"] == "unavailable_or_unsafe"
    assert result["reader"]["observed_schema_version"] is None
    assert "canary" not in json.dumps(result)
    assert calls == ["authority"]


def test_explicit_reader_check_fails_when_unconfigured(monkeypatch, capsys):
    from osint_workbench.cli import main

    monkeypatch.delenv("OW_READER_DSN", raising=False)
    monkeypatch.setattr(sys, "argv", ["osint-workbench", "diagnose", "--check-reader"])
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 1
    assert json.loads(capsys.readouterr().out)["reader"]["state"] == "not_configured"


def test_unknown_os_metadata_is_not_echoed_or_qualified(monkeypatch):
    monkeypatch.setattr(
        diagnostics.platform,
        "freedesktop_os_release",
        lambda: {"ID": "ubuntu", "VERSION_ID": "private-canary"},
    )
    value = diagnostics.diagnose()
    assert not value["runtime"]["matches_required_profile"]
    assert "canary" not in json.dumps(value)


@pytest.mark.integration
def test_native_reader_and_writer_authority(databases, monkeypatch):
    _, _, roles = databases
    monkeypatch.setenv("OW_READER_DSN", roles["reader"])
    assert diagnostics.diagnose(check_reader=True)["reader"]["state"] == "compatible"
    monkeypatch.setenv("OW_READER_DSN", roles["writer"])
    assert diagnostics.diagnose(check_reader=True)["reader"]["state"] == "unavailable_or_unsafe"


@pytest.mark.parametrize(
    "ubuntu,minor,machine,implementation,matches",
    [
        ("24.04", 12, "x86_64", "CPython", True),
        ("26.04", 14, "x86_64", "CPython", True),
        ("24.04", 12, "aarch64", "CPython", False),
        ("26.04", 14, "aarch64", "CPython", False),
        ("24.04", 13, "x86_64", "CPython", False),
        ("24.04", 12, "x86_64", "PyPy", False),
        ("24.04", 12, "private-canary", "CPython", False),
    ],
)
def test_required_profile_matches_only_supported_native_triples(
    monkeypatch, ubuntu, minor, machine, implementation, matches
):
    monkeypatch.setattr(
        diagnostics.platform,
        "freedesktop_os_release",
        lambda: {"ID": "ubuntu", "VERSION_ID": ubuntu},
    )
    monkeypatch.setattr(diagnostics.platform, "machine", lambda: machine)
    monkeypatch.setattr(diagnostics.platform, "python_implementation", lambda: implementation)
    monkeypatch.setattr(diagnostics.sys, "version_info", (3, minor, 0))
    monkeypatch.setattr(diagnostics.sysconfig, "get_config_var", lambda _: None)
    value = diagnostics.diagnose()
    assert value["runtime"]["matches_required_profile"] is matches
    assert "private-canary" not in json.dumps(value)


def test_free_threaded_build_does_not_match_required_profile(monkeypatch):
    monkeypatch.setattr(
        diagnostics.platform,
        "freedesktop_os_release",
        lambda: {"ID": "ubuntu", "VERSION_ID": "26.04"},
    )
    monkeypatch.setattr(diagnostics.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(diagnostics.platform, "python_implementation", lambda: "CPython")
    monkeypatch.setattr(diagnostics.sys, "version_info", (3, 14, 0))
    monkeypatch.setattr(diagnostics.sysconfig, "get_config_var", lambda _: 1)
    runtime = diagnostics.diagnose()["runtime"]
    assert not runtime["standard_gil_build"] and not runtime["matches_required_profile"]


@pytest.mark.parametrize(
    "error",
    [OSError("private-canary"), UnicodeDecodeError("utf-8", b"\xff", 0, 1, "private-canary")],
)
def test_unreadable_os_metadata_remains_diagnosable(monkeypatch, error):
    def fail():
        raise error

    monkeypatch.setattr(diagnostics.platform, "freedesktop_os_release", fail)
    value = diagnostics.diagnose()
    assert value["runtime"]["ubuntu_profile"] == "other_or_unknown"
    assert not value["runtime"]["matches_required_profile"]
    assert "canary" not in json.dumps(value)


@pytest.mark.integration
def test_reader_validation_reuses_caller_owned_native_connection(databases, monkeypatch):
    _, reader, _ = databases
    with reader.connect() as connection:

        def refuse_new_connection():
            raise AssertionError("a second backend must not be contacted")

        monkeypatch.setattr(reader, "connect", refuse_new_connection)
        reader.validate_reader(connection=connection)
        assert (
            connection.execute("SELECT version FROM ow.schema_status").fetchone()["version"]
            == SCHEMA_VERSION
        )
        assert not connection.closed
