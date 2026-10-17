import hashlib
import os
import secrets
from importlib.resources import files

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import make_conninfo

from osint_workbench.database import Database, migrate


def pytest_addoption(parser):
    parser.addoption("--require-integration", action="store_true", default=False)


def pytest_configure(config):
    if config.getoption("--require-integration") and not os.environ.get("OW_TEST_ADMIN_DSN"):
        raise pytest.UsageError("OW_TEST_ADMIN_DSN is required; missing integration is not a pass")


@pytest.fixture(scope="session")
def roles():
    dsn = os.environ.get("OW_TEST_ADMIN_DSN")
    if not dsn:
        pytest.skip("isolated PostgreSQL unavailable; integration NOT VERIFIED locally")
    with psycopg.connect(dsn, autocommit=True) as conn:
        if conn.info.dbname != "ow_test":
            raise RuntimeError("tests refuse any database not named ow_test")
        if conn.execute("SELECT to_regclass('ow.migrations')").fetchone()[0] is None:
            script = files("osint_workbench").joinpath("schema.sql").read_text()
            conn.execute(script)
            conn.execute(
                "INSERT INTO ow.migrations(version,sha256) VALUES (1,%s)",
                (hashlib.sha256(script.encode()).hexdigest(),),
            )
    migrate(dsn)
    writer_password, reader_password = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    with psycopg.connect(dsn, autocommit=True) as conn:
        for role, group, password in [
            ("ow_test_writer", "ow_writer", writer_password),
            ("ow_test_reader", "ow_reader", reader_password),
        ]:
            exists = conn.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (role,)).fetchone()
            if not exists:
                conn.execute(sql.SQL("CREATE ROLE {} LOGIN").format(sql.Identifier(role)))
            conn.execute(
                sql.SQL("ALTER ROLE {} PASSWORD {}").format(
                    sql.Identifier(role), sql.Literal(password)
                )
            )
            conn.execute(
                sql.SQL("GRANT {} TO {}").format(sql.Identifier(group), sql.Identifier(role))
            )
    return {
        "admin": dsn,
        "writer": make_conninfo(dsn, user="ow_test_writer", password=writer_password),
        "reader": make_conninfo(dsn, user="ow_test_reader", password=reader_password),
    }


@pytest.fixture
def databases(roles):
    with psycopg.connect(roles["admin"]) as conn:
        conn.execute(
            "TRUNCATE ow.collection_runs,ow.job_events,ow.chunks,ow.jobs,ow.document_heads,"
            "ow.documents,ow.snapshots,ow.sources"
        )
    return Database(roles["writer"]), Database(roles["reader"]), roles
