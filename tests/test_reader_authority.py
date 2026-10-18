"""Effective reader ACL boundaries against the disposable PostgreSQL fixture."""

import psycopg
import pytest
from psycopg import sql

from osint_workbench.errors import WorkbenchError


@pytest.mark.parametrize(
    "relation,column", [("sources", "last_error"), ("collection_runs", "raw_sha256")]
)
@pytest.mark.parametrize("column_only", [False, True])
@pytest.mark.parametrize("grantee", ["ow_test_reader", "ow_reader", "PUBLIC"])
def test_reader_rejects_backing_data_grants(databases, relation, column, column_only, grantee):
    _, reader, roles = databases
    reader.validate_reader()
    privilege = (
        sql.SQL("SELECT ({})").format(sql.Identifier(column)) if column_only else sql.SQL("SELECT")
    )
    recipient = sql.SQL("PUBLIC") if grantee == "PUBLIC" else sql.Identifier(grantee)
    with psycopg.connect(roles["admin"], autocommit=True) as admin:
        admin.execute(
            sql.SQL("GRANT {} ON ow.{} TO {}").format(
                privilege, sql.Identifier(relation), recipient
            )
        )
        try:
            with pytest.raises(WorkbenchError, match="UNSAFE_READER_IDENTITY"):
                reader.validate_reader()
        finally:
            admin.execute(
                sql.SQL("REVOKE {} ON ow.{} FROM {}").format(
                    privilege, sql.Identifier(relation), recipient
                )
            )
    reader.validate_reader()


@pytest.mark.parametrize("kind", ["TABLE", "VIEW"])
@pytest.mark.parametrize("column_only", [False, True])
@pytest.mark.parametrize("grantee", ["ow_test_reader", "ow_reader", "PUBLIC"])
def test_reader_rejects_unforeseen_readable_relations(databases, kind, column_only, grantee):
    _, reader, roles = databases
    privilege = sql.SQL("SELECT (secret)") if column_only else sql.SQL("SELECT")
    recipient = sql.SQL("PUBLIC") if grantee == "PUBLIC" else sql.Identifier(grantee)
    with psycopg.connect(roles["admin"], autocommit=True) as admin:
        # Empty new tables still count as unauthorized authority. Views can
        # expose backing data without granting its underlying table directly.
        definition = (
            "(secret text)" if kind == "TABLE" else "AS SELECT last_error AS secret FROM ow.sources"
        )
        admin.execute(
            sql.SQL("CREATE {} ow.reader_probe {}").format(sql.SQL(kind), sql.SQL(definition))
        )
        try:
            admin.execute(sql.SQL("GRANT {} ON ow.reader_probe TO {}").format(privilege, recipient))
            with pytest.raises(WorkbenchError, match="UNSAFE_READER_IDENTITY"):
                reader.validate_reader()
        finally:
            admin.execute(sql.SQL("DROP {} ow.reader_probe").format(sql.SQL(kind)))
    reader.validate_reader()


def test_reader_rejects_unreviewed_column_on_allowed_view(databases):
    _, reader, roles = databases
    with psycopg.connect(roles["admin"], autocommit=True) as admin:
        admin.execute("ALTER VIEW ow.source_status RENAME COLUMN last_error TO unreviewed_error")
        try:
            with pytest.raises(WorkbenchError, match="UNSAFE_READER_IDENTITY"):
                reader.validate_reader()
        finally:
            admin.execute(
                "ALTER VIEW ow.source_status RENAME COLUMN unreviewed_error TO last_error"
            )
    reader.validate_reader()


@pytest.mark.parametrize("inherit", [False, True])
def test_reader_rejects_extra_role_even_without_inherited_authority(databases, inherit):
    _, reader, roles = databases
    with psycopg.connect(roles["admin"], autocommit=True) as admin:
        admin.execute("CREATE ROLE ow_reader_probe NOLOGIN")
        try:
            admin.execute("GRANT SELECT (last_error) ON ow.sources TO ow_reader_probe")
            admin.execute(
                sql.SQL("GRANT ow_reader_probe TO ow_test_reader WITH INHERIT {}, SET TRUE").format(
                    sql.SQL("TRUE" if inherit else "FALSE")
                )
            )
            with reader.connect() as conn:
                assert conn.execute(
                    "SELECT pg_has_role(current_user,'ow_reader_probe','SET') AS settable"
                ).fetchone()["settable"]
                assert (
                    conn.execute(
                        "SELECT pg_has_role(current_user,'ow_reader_probe','USAGE') AS inherited"
                    ).fetchone()["inherited"]
                    is inherit
                )
            with pytest.raises(WorkbenchError, match="UNSAFE_READER_IDENTITY"):
                reader.validate_reader()
        finally:
            admin.execute("REVOKE ow_reader_probe FROM ow_test_reader")
            admin.execute("DROP OWNED BY ow_reader_probe")
            admin.execute("DROP ROLE ow_reader_probe")
    reader.validate_reader()


def test_genuine_reader_accepts_core_and_installed_retrieval_projection(databases):
    _, reader, roles = databases
    reader.validate_reader()
    with reader.connect() as conn:
        conn.execute("SELECT document_id FROM ow.visible_documents LIMIT 0")
        conn.execute("SELECT last_error FROM ow.source_status LIMIT 0")
        optional = conn.execute("SELECT to_regclass('ow.retrieval_active') AS relation").fetchone()
        if optional["relation"] is not None:
            for relation in (
                "embedding_spaces",
                "retrieval_generations",
                "retrieval_active",
                "visible_retrieval_members",
                "visible_retrieval_vectors",
                "visible_retrieval_exclusions",
            ):
                conn.execute(
                    sql.SQL("SELECT * FROM ow.{} LIMIT 0").format(sql.Identifier(relation))
                )


def test_reader_rejects_admin_option_for_its_allowed_group(databases):
    _, reader, roles = databases
    reader.validate_reader()
    with psycopg.connect(roles["admin"], autocommit=True) as admin:
        admin.execute("GRANT ow_reader TO ow_test_reader WITH ADMIN OPTION")
        try:
            with pytest.raises(WorkbenchError, match="UNSAFE_READER_IDENTITY"):
                reader.validate_reader()
        finally:
            # Preserve the genuine reader membership while removing delegation.
            admin.execute("REVOKE ADMIN OPTION FOR ow_reader FROM ow_test_reader")
    with reader.connect() as conn:
        assert conn.execute(
            "SELECT pg_has_role(current_user,'ow_reader','USAGE') AS inherited"
        ).fetchone()["inherited"]
    reader.validate_reader()


@pytest.mark.parametrize("grantee", ["ow_test_reader", "ow_reader"])
def test_reader_rejects_effective_schema_usage_delegation(databases, grantee):
    _, reader, roles = databases
    reader.validate_reader()
    with psycopg.connect(roles["admin"], autocommit=True) as admin:
        admin.execute(
            sql.SQL("GRANT USAGE ON SCHEMA ow TO {} WITH GRANT OPTION").format(
                sql.Identifier(grantee)
            )
        )
        try:
            with reader.connect() as conn:
                assert conn.execute(
                    "SELECT has_schema_privilege(current_user,'ow',"
                    "'USAGE WITH GRANT OPTION') AS delegation"
                ).fetchone()["delegation"]
            with pytest.raises(WorkbenchError, match="UNSAFE_READER_IDENTITY"):
                reader.validate_reader()
        finally:
            admin.execute(
                sql.SQL("REVOKE GRANT OPTION FOR USAGE ON SCHEMA ow FROM {}").format(
                    sql.Identifier(grantee)
                )
            )
            if grantee == "ow_test_reader":
                # The login initially receives USAGE through ow_reader only.
                admin.execute("REVOKE USAGE ON SCHEMA ow FROM ow_test_reader")
    reader.validate_reader()
