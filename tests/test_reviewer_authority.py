"""Actual SQL identities, legacy state and the review-to-product boundary."""

import os
from contextlib import closing
from importlib.resources import files

import psycopg
import pytest

from osint_workbench import intelligence, recovery
from osint_workbench.database import MIGRATIONS, Database, migrate
from osint_workbench.errors import WorkbenchError
from osint_workbench.evidence import EvidenceStore
from osint_workbench.reviewer import validate_connection
from osint_workbench.service import ReadService
from osint_workbench.text import digest
from tests.test_intelligence import FixtureGenerator, claim, setup
from tests.test_recovery import (
    _fixture,
    _rewrite,
    isolated,
    policy_arguments,
    published_pair,
)

pytestmark = pytest.mark.integration


def proposal(databases, tmp_path):
    writer, reader, roles, store, doc = setup(databases, tmp_path)
    generator = FixtureGenerator([claim()])
    intelligence.enqueue(writer, generator, doc)
    intelligence.enrich_once(writer, store, generator)
    assertion = intelligence.assertions(reader)["results"][0]["assertion_id"]
    return writer, reader, roles, store, doc, assertion


def append(conn, assertion):
    conn.execute(
        "INSERT INTO ow.assertion_reviews(assertion_id,decision,actor,rationale) "
        "VALUES (%s,'accept','attribution-only','Synthetic reviewed evidence')",
        (assertion,),
    )


@pytest.mark.parametrize(
    "identity", ["writer", "reader", "collector", "lifecycle", "accounting", "admin"]
)
def test_non_reviewer_credentials_refused_before_review(databases, tmp_path, identity):
    _, _, roles, _, _, assertion = proposal(databases, tmp_path)
    with pytest.raises(WorkbenchError, match="UNSAFE_REVIEWER_IDENTITY"):
        intelligence.review(Database(roles[identity]), assertion, "accept", "operator", "Reviewed")
    with psycopg.connect(roles["admin"]) as conn:
        assert conn.execute("SELECT count(*) FROM ow.assertion_reviews").fetchone() == (0,)


def test_authenticated_review_provenance_and_private_reader_projection(databases, tmp_path):
    writer, reader, roles, store, doc, assertion = proposal(databases, tmp_path)
    reviewer = Database(roles["reviewer"])
    intelligence.review(reviewer, assertion, "accept", "a human supplied label", "Reviewed")
    with psycopg.connect(roles["admin"]) as conn:
        assert conn.execute(
            "SELECT actor,authority,database_principal FROM ow.assertion_reviews"
        ).fetchone() == ("a human supplied label", "authenticated_reviewer", "ow_test_reviewer")
    product = intelligence.create_briefing(writer, [doc])
    service = ReadService(reader, EvidenceStore(store.root, read_only=True))
    assert service.briefing(product["briefing_id"])["items"][0]["assertion_id"] == assertion
    assert "database_principal" not in str(service.assertions())
    with pytest.raises(psycopg.errors.InsufficientPrivilege), reader.connect() as conn:
        conn.execute("SELECT database_principal FROM ow.assertion_reviews")
    intelligence.review(reviewer, assertion, "reject", "withdrawal label", "Withdrawn")
    with pytest.raises(WorkbenchError, match="BRIEFING_STALE"):
        service.briefing(product["briefing_id"])


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE ow.assertion_reviews SET decision='accept'",
        "DELETE FROM ow.assertion_reviews",
        "UPDATE ow.assertions SET statement='forged'",
        "UPDATE ow.jobs SET status='ready'",
        "SELECT * FROM ow.remote_operations",
        "SELECT * FROM ow.collection_state",
        "SELECT * FROM ow.assertion_reviews",
    ],
)
def test_reviewer_has_no_producer_or_history_authority(databases, sql):
    with (
        pytest.raises(psycopg.errors.InsufficientPrivilege),
        Database(databases[2]["reviewer"]).connect() as conn,
    ):
        conn.execute(sql)


def test_writer_cannot_insert_review_even_after_accidental_grant(databases, tmp_path):
    writer, _, roles, _, _, assertion = proposal(databases, tmp_path)
    with pytest.raises(psycopg.errors.InsufficientPrivilege), writer.connect() as conn:
        append(conn, assertion)
    with psycopg.connect(roles["admin"]) as conn:
        conn.execute("GRANT INSERT ON ow.assertion_reviews TO ow_test_writer")
        conn.execute("GRANT USAGE ON SEQUENCE ow.assertion_reviews_review_id_seq TO ow_test_writer")
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege), writer.connect() as conn:
            append(conn, assertion)
    finally:
        with psycopg.connect(roles["admin"]) as conn:
            conn.execute("REVOKE INSERT ON ow.assertion_reviews FROM ow_test_writer")
            conn.execute(
                "REVOKE USAGE ON SEQUENCE ow.assertion_reviews_review_id_seq FROM ow_test_writer"
            )


@pytest.mark.parametrize(
    "field,value",
    [
        ("database_principal", "'someone-else'"),
        ("authority", "'authenticated_reviewer'"),
        ("reviewed_at", "'2040-01-01'::timestamptz"),
    ],
)
def test_reviewer_cannot_supply_authenticated_provenance(databases, tmp_path, field, value):
    from psycopg import sql

    _, _, roles, _, _, assertion = proposal(databases, tmp_path)
    # Parameterized assertion; field/value expressions are fixed test cases.
    query = sql.SQL(
        "INSERT INTO ow.assertion_reviews "
        "(assertion_id,decision,actor,rationale,{}) "
        "VALUES (%s,'accept','label','Reviewed',{})"
    ).format(sql.Identifier(field), sql.SQL(value))
    with (
        pytest.raises(psycopg.errors.InsufficientPrivilege),
        Database(roles["reviewer"]).connect() as conn,
    ):
        conn.execute(query, (assertion,))


@pytest.mark.parametrize("set_role", [None, "ow_reviewer", "ow_writer"])
def test_overlapping_reviewer_writer_denied_through_set_role(databases, tmp_path, set_role):
    _, _, roles, _, _, assertion = proposal(databases, tmp_path)
    with psycopg.connect(roles["admin"]) as conn:
        conn.execute("GRANT ow_writer TO ow_test_reviewer WITH INHERIT FALSE")
    try:
        with Database(roles["reviewer"]).connect() as conn:
            if set_role:
                # Fixed test-only roles, never operator SQL.
                from psycopg import sql

                conn.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(set_role)))
            with pytest.raises(WorkbenchError, match="UNSAFE_REVIEWER_IDENTITY"):
                validate_connection(conn)
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                append(conn, assertion)
    finally:
        with psycopg.connect(roles["admin"]) as conn:
            conn.execute("REVOKE ow_writer FROM ow_test_reviewer")


@pytest.mark.parametrize(
    "grant",
    [
        "GRANT INSERT ON ow.assertions TO ow_test_reviewer",
        "GRANT UPDATE(decision) ON ow.assertion_reviews TO PUBLIC",
        "GRANT SELECT ON ow.assertion_reviews TO ow_test_reviewer",
    ],
)
def test_broadened_effective_grants_refused(databases, grant):
    revoke = grant.replace("GRANT ", "REVOKE ", 1).replace(" TO ", " FROM ")
    with psycopg.connect(databases[2]["admin"]) as conn:
        conn.execute(grant)
    try:
        with Database(databases[2]["reviewer"]).connect() as conn:
            with pytest.raises(WorkbenchError, match="UNSAFE_REVIEWER_IDENTITY"):
                validate_connection(conn)
    finally:
        with psycopg.connect(databases[2]["admin"]) as conn:
            conn.execute(revoke)


def test_revoke_applies_to_an_existing_connection(databases, tmp_path):
    _, _, roles, _, _, assertion = proposal(databases, tmp_path)
    with closing(Database(roles["reviewer"]).connect()) as conn:
        validate_connection(conn)
        conn.commit()
        with psycopg.connect(roles["admin"]) as admin:
            admin.execute("REVOKE ow_reviewer FROM ow_test_reviewer")
        try:
            with pytest.raises(WorkbenchError, match="UNSAFE_REVIEWER_IDENTITY"):
                validate_connection(conn)
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                append(conn, assertion)
        finally:
            with psycopg.connect(roles["admin"]) as admin:
                admin.execute("GRANT ow_reviewer TO ow_test_reviewer")


@pytest.mark.parametrize("legacy", [False, True])
def test_checkpoint_preserves_provenance_or_requires_legacy_requalification(
    databases, tmp_path, legacy
):
    writer, _, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    _, assertion, brief, *_ = _fixture(writer, store, roles)
    path = tmp_path / "checkpoint.owcp"
    sha = recovery.checkpoint(Database(roles["admin"]), store, path)["sha256"]
    if legacy:
        # Strip only fields absent in the exact published core11/profile4 pair.
        sha = _rewrite(path, lambda payload: published_pair(payload, 11))
    with isolated(roles, retrieval=os.environ.get("OW_TEST_RETRIEVAL") == "1") as target:
        root = tmp_path / "restored"
        result = recovery.restore(
            Database(target["admin"]), path, sha, root, **policy_arguments(roles, path)
        )
        assert result["adopted_core_v11"] is legacy
        service = ReadService(Database(target["reader"]), EvidenceStore(root, read_only=True))
        with psycopg.connect(target["admin"]) as conn:
            authority, principal = conn.execute(
                "SELECT authority,database_principal FROM ow.assertion_reviews"
            ).fetchone()
        if legacy:
            assert (authority, principal) == ("legacy_writer", None)
            assert service.assertions()["results"][0]["review_state"] == "pending"
            with pytest.raises(WorkbenchError, match="BRIEFING_STALE"):
                service.briefing(brief)
            intelligence.review(
                Database(target["reviewer"]), assertion, "accept", "new label", "Requalified"
            )
        else:
            assert (authority, principal) == ("authenticated_reviewer", "ow_test_reviewer")
        assert service.briefing(brief)["items"][0]["assertion_id"] == assertion


def test_actual_core11_upgrade_preserves_reviews_but_withdraws_legacy_acceptance(roles, tmp_path):
    with isolated(roles, retrieval=False) as target:
        # Start from the exact packaged old migration scripts in a fresh schema.
        with psycopg.connect(target["admin"]) as conn:
            conn.execute("DROP SCHEMA ow CASCADE")
            for version, name in enumerate(MIGRATIONS[:11], 1):
                script = files("osint_workbench").joinpath(name).read_text()
                conn.execute(script)
                conn.execute(
                    "INSERT INTO ow.migrations VALUES (%s,%s)", (version, digest(script.encode()))
                )
        local = (Database(target["writer"]), Database(target["reader"]), target)
        writer, reader, _, store, doc, assertion = proposal(local, tmp_path)
        with writer.connect() as conn:
            append(conn, assertion)
        brief = intelligence.create_briefing(writer, [doc])["briefing_id"]
        with psycopg.connect(target["admin"]) as conn:
            before = conn.execute("SELECT * FROM ow.assertion_reviews").fetchone()
        migrate(target["admin"])
        migrate(target["admin"])
        with psycopg.connect(target["admin"]) as conn:
            after = conn.execute("SELECT * FROM ow.assertion_reviews").fetchone()
        assert after[:-2] == before and after[-2:] == ("legacy_writer", None)
        service = ReadService(reader, EvidenceStore(store.root, read_only=True))
        with pytest.raises(WorkbenchError, match="BRIEFING_STALE"):
            service.briefing(brief)
        intelligence.review(
            Database(target["reviewer"]), assertion, "accept", "reviewer", "Fresh review"
        )
        assert service.briefing(brief)["items"][0]["assertion_id"] == assertion
