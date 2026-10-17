"""Actual libpq startup deadlines against a disposable silent protocol peer."""

import json
import socket
import subprocess
import sys
import threading
from contextlib import contextmanager

import pytest
from psycopg.conninfo import make_conninfo


@contextmanager
def silent_postgresql_peer():
    stopping = threading.Event()
    startup_received = threading.Event()
    errors = []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(0.2)

        def serve():
            try:
                while not stopping.is_set():
                    try:
                        connection, _ = listener.accept()
                    except TimeoutError:
                        continue
                    with connection:
                        connection.settimeout(1)
                        if connection.recv(1):
                            startup_received.set()
                        # Accept the startup request but provide no PostgreSQL
                        # authentication response. Nothing is logged or echoed.
                        stopping.wait(12)
                    break
            except OSError as error:
                errors.append(type(error).__name__)

        thread = threading.Thread(target=serve, name="synthetic-postgresql-startup-peer")
        thread.start()
        try:
            yield listener.getsockname()[1], startup_received
        finally:
            stopping.set()
            thread.join(timeout=2)
            assert not thread.is_alive(), "synthetic startup peer failed to stop"
            assert not errors, "synthetic startup peer failed"


CHILD = """
import json, sys, time
import psycopg
from osint_workbench.database import Database, migrate
packet = json.load(sys.stdin)
started = time.monotonic()
try:
    if packet['operation'] == 'connect':
        with Database(packet['dsn']).connect():
            pass
    else:
        migrate(packet['dsn'])
except psycopg.OperationalError as error:
    print(json.dumps({
        'error_class': type(error).__name__,
        'elapsed_seconds': time.monotonic() - started,
        'credential_exposed': packet['credential'] in str(error),
    }))
else:
    raise SystemExit('silent peer unexpectedly completed startup')
"""


@pytest.mark.parametrize("operation", ["connect", "migrate"])
def test_actual_postgresql_startup_has_five_second_bound(operation):
    credential = "synthetic-startup-credential"
    with silent_postgresql_peer() as (port, startup_received):
        dsn = make_conninfo(
            hostaddr="127.0.0.1",
            port=port,
            dbname="ow_test",
            user="synthetic_startup_probe",
            password=credential,
            sslmode="disable",
            gssencmode="disable",
            # The explicit application deadline must override a longer DSN
            # setting; connection refusal would not establish this behaviour.
            connect_timeout=60,
        )
        result = subprocess.run(
            [sys.executable, "-I", "-c", CHILD],
            input=json.dumps({"operation": operation, "dsn": dsn, "credential": credential}),
            text=True,
            capture_output=True,
            timeout=12,
            check=False,
        )
        assert startup_received.is_set(), "actual startup bytes were not observed"
        assert result.returncode == 0, "bounded startup subprocess failed"
        observation = json.loads(result.stdout)
        assert observation["error_class"] in {"ConnectionTimeout", "OperationalError"}
        assert 4 <= observation["elapsed_seconds"] <= 8
        assert not observation["credential_exposed"]
        assert credential not in result.stdout and credential not in result.stderr
