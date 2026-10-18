"""Native SQL authority checks; no source-level tenant-isolation claim."""

import uuid

import psycopg
import pytest
from psycopg import sql

from osint_workbench.collection import collect, collect_due
from osint_workbench.contracts import DocumentInput
from osint_workbench.database import SCHEMA_VERSION, Database
from osint_workbench.errors import WorkbenchError
from osint_workbench.evidence import EvidenceStore
from tests.test_lifecycle import change
from tests.test_scheduled_collection import ResponseWire, due, install, source

pytestmark = pytest.mark.integration


def test_collector_native_collection_conditional_and_retirement(databases, tmp_path, monkeypatch):
    writer, reader, roles = databases
    collector = Database(roles["collector"])
    collector.validate_collector()
    store = EvidenceStore(tmp_path / "objects")
    install(monkeypatch, ResponseWire(headers=[(b"etag", b'"v1"')]))
    result = collect_due([source()], collector, store)
    assert result["status"] == "complete"
    assert result["results"][0]["documents"] == 2
    ids = result["results"][0]["document_ids"]
    with writer.connect() as conn:
        assert conn.execute("SELECT DISTINCT kind,status FROM ow.jobs").fetchall() == [
            {"kind": "document.accepted", "status": "ready"}
        ]
    due(writer)
    wire = ResponseWire(304, b"", [(b"etag", b'"v1"')])
    install(monkeypatch, wire)
    assert collect(source(), collector, store, due_only=True)["status"] == "not_modified"
    assert dict(wire.request.headers)[b"if-none-match"] == b'"v1"'
    operator = Database(roles["lifecycle"])
    change(operator, ids[0], "retire")
    due(writer)
    install(monkeypatch, ResponseWire(headers=[(b"etag", b'"v2"')]))
    result = collect(source(), collector, store, due_only=True)
    assert result["suppressed_documents"] == 1 and result["documents"] == 1
    assert reader.search("First") == []
    assert [hit["document_id"] for hit in reader.search("Second")] == [ids[1]]
    # Aggregate status counts retained records; logical suppression is not erasure.
    assert reader.status()["documents"] == 2
    collector.validate_collector()


def test_collector_partial_acceptance_failure_and_replay(databases, tmp_path, monkeypatch):
    writer, _, roles = databases
    collector = Database(roles["collector"])
    collector.validate_collector()
    store = EvidenceStore(tmp_path / "objects")
    install(monkeypatch, ResponseWire(headers=[(b"etag", b'"first"')]))
    put = store.put
    with monkeypatch.context() as patch:

        def fail(data):
            if data == b"Second evidence":
                raise WorkbenchError("SYNTHETIC_STORE_FAILURE")
            return put(data)

        patch.setattr(store, "put", fail)
        with pytest.raises(WorkbenchError, match="SYNTHETIC_STORE_FAILURE"):
            collect(source(), collector, store, due_only=True)
    with writer.connect() as conn:
        assert conn.execute("SELECT count(*) AS n FROM ow.documents").fetchone()["n"] == 1
        assert conn.execute("SELECT etag FROM ow.collection_state").fetchone()["etag"] is None
        run = conn.execute("SELECT status,accepted_documents FROM ow.collection_runs").fetchone()
        assert run == {"status": "failed", "accepted_documents": 1}
    due(writer)
    wire = ResponseWire(headers=[(b"etag", b'"first"')])
    install(monkeypatch, wire)
    assert collect(source(), collector, store, due_only=True)["documents"] == 2
    assert b"if-none-match" not in dict(wire.request.headers)
    with writer.connect() as conn:
        assert conn.execute("SELECT count(*) AS n FROM ow.jobs").fetchone()["n"] == 2


@pytest.mark.parametrize(
    "statement",
    [
        "SELECT body FROM ow.documents",
        "SELECT payload FROM ow.jobs",
        "SELECT rationale FROM ow.lifecycle_events",
        "UPDATE ow.jobs SET status='cancelled'",
        "UPDATE ow.lifecycle_items SET retain_until=clock_timestamp()",
        "DELETE FROM ow.collection_runs",
        "TRUNCATE ow.jobs",
        "CREATE TABLE ow.forbidden(value integer)",
        "INSERT INTO ow.jobs(job_id,kind,dedup_key,payload) "
        "VALUES (gen_random_uuid(),'enrichment.requested','forbidden','{}')",
        "INSERT INTO ow.jobs(job_id,dedup_key,payload,status) "
        "VALUES (gen_random_uuid(),'forbidden','{}','succeeded')",
        "INSERT INTO ow.enrichments(enrichment_id) VALUES ('forbidden')",
    ],
)
def test_collector_native_forbidden_sql(databases, statement):
    _, _, roles = databases
    collector = Database(roles["collector"])
    collector.validate_collector()
    with collector.connect() as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(statement)


@pytest.mark.parametrize(
    "grant,revoke",
    [
        ("SELECT(body) ON ow.documents", "SELECT(body) ON ow.documents"),
        ("UPDATE(status) ON ow.jobs", "UPDATE(status) ON ow.jobs"),
        ("INSERT(kind) ON ow.jobs", "INSERT(kind) ON ow.jobs"),
        ("SELECT ON ow.visible_documents", "SELECT ON ow.visible_documents"),
        (
            "USAGE ON SEQUENCE ow.job_events_event_id_seq",
            "USAGE ON SEQUENCE ow.job_events_event_id_seq",
        ),
        ("CREATE ON SCHEMA ow", "CREATE ON SCHEMA ow"),
        ("MAINTAIN ON ow.documents", "MAINTAIN ON ow.documents"),
    ],
)
def test_collector_rejects_accidental_effective_grants(databases, grant, revoke):
    _, _, roles = databases
    collector = Database(roles["collector"])
    collector.validate_collector()
    with collector.connect() as conn:
        login = conn.info.user
    with psycopg.connect(roles["admin"], autocommit=True) as admin:
        admin.execute(sql.SQL("GRANT " + grant + " TO {}").format(sql.Identifier(login)))
        try:
            with pytest.raises(WorkbenchError, match="UNSAFE_COLLECTOR_IDENTITY"):
                collector.validate_collector()
        finally:
            admin.execute(sql.SQL("REVOKE " + revoke + " FROM {}").format(sql.Identifier(login)))
    collector.validate_collector()


def test_collector_rejects_public_grants_and_definer_escape(databases):
    _, _, roles = databases
    collector = Database(roles["collector"])
    collector.validate_collector()
    with psycopg.connect(roles["admin"], autocommit=True) as admin:
        admin.execute("GRANT SELECT(body) ON ow.documents TO PUBLIC")
        try:
            with pytest.raises(WorkbenchError, match="UNSAFE_COLLECTOR_IDENTITY"):
                collector.validate_collector()
        finally:
            admin.execute("REVOKE SELECT(body) ON ow.documents FROM PUBLIC")
        admin.execute(
            "CREATE FUNCTION ow.collector_escape() RETURNS integer "
            "LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'"
        )
        try:
            with pytest.raises(WorkbenchError, match="UNSAFE_COLLECTOR_IDENTITY"):
                collector.validate_collector()
        finally:
            admin.execute("DROP FUNCTION ow.collector_escape()")
    collector.validate_collector()


def test_collector_rejects_set_role_even_without_inherited_extra_permissions(databases):
    _, _, roles = databases
    collector = Database(roles["collector"])
    with collector.connect() as conn:
        login = conn.info.user
    extra = "ow_test_extra_" + uuid.uuid4().hex
    with psycopg.connect(roles["admin"], autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(extra)))
        admin.execute(
            sql.SQL("GRANT SELECT(body) ON ow.documents TO {}").format(sql.Identifier(extra))
        )
        admin.execute(
            sql.SQL("GRANT {} TO {} WITH INHERIT FALSE").format(
                sql.Identifier(extra), sql.Identifier(login)
            )
        )
        try:
            with collector.connect() as conn:
                assert not conn.execute(
                    "SELECT has_column_privilege(current_user,"
                    "'ow.documents','body','SELECT') AS body"
                ).fetchone()["body"]
                assert conn.execute(
                    "SELECT pg_has_role(current_user,%s,'MEMBER') AS reachable", (extra,)
                ).fetchone()["reachable"]
            with pytest.raises(WorkbenchError, match="UNSAFE_COLLECTOR_IDENTITY"):
                collector.validate_collector()
        finally:
            admin.execute(
                sql.SQL("REVOKE {} FROM {}").format(sql.Identifier(extra), sql.Identifier(login))
            )
            admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(extra)))
            admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(extra)))
    collector.validate_collector()


@pytest.mark.parametrize(
    "attribute,restore",
    [
        ("REPLICATION", "NOREPLICATION"),
        ("CREATEROLE", "NOCREATEROLE"),
        ("BYPASSRLS", "NOBYPASSRLS"),
    ],
)
def test_collector_rejects_dangerous_group_powers(databases, attribute, restore):
    _, _, roles = databases
    collector = Database(roles["collector"])
    with psycopg.connect(roles["admin"], autocommit=True) as admin:
        admin.execute("ALTER ROLE ow_collector " + attribute)
        try:
            with pytest.raises(WorkbenchError, match="UNSAFE_COLLECTOR_IDENTITY"):
                collector.validate_collector()
        finally:
            admin.execute("ALTER ROLE ow_collector " + restore)
    collector.validate_collector()


def test_collector_rejects_owned_objects_and_broad_writer(databases):
    _, _, roles = databases
    collector = Database(roles["collector"])
    with collector.connect() as conn:
        login = conn.info.user
    with psycopg.connect(roles["admin"], autocommit=True) as admin:
        admin.execute("CREATE TABLE ow.collector_owned(value integer)")
        admin.execute(
            sql.SQL("ALTER TABLE ow.collector_owned OWNER TO {}").format(sql.Identifier(login))
        )
        try:
            with pytest.raises(WorkbenchError, match="UNSAFE_COLLECTOR_IDENTITY"):
                collector.validate_collector()
        finally:
            admin.execute("DROP TABLE ow.collector_owned")
    for name in ("admin", "writer", "reader", "lifecycle"):
        with pytest.raises(WorkbenchError, match="UNSAFE_COLLECTOR_IDENTITY"):
            Database(roles[name]).validate_collector()
    collector.validate_collector()


@pytest.mark.parametrize("delegation", ["column", "schema", "membership"])
def test_collector_rejects_delegation_options(databases, delegation):
    _, _, roles = databases
    collector = Database(roles["collector"])
    collector.validate_collector()
    with collector.connect() as conn:
        login = conn.info.user
    with psycopg.connect(roles["admin"], autocommit=True) as admin:
        if delegation == "column":
            grant = "GRANT SELECT(document_id) ON ow.documents TO {} WITH GRANT OPTION"
            revoke = "REVOKE SELECT(document_id) ON ow.documents FROM {}"
        elif delegation == "schema":
            grant = "GRANT USAGE ON SCHEMA ow TO {} WITH GRANT OPTION"
            revoke = "REVOKE USAGE ON SCHEMA ow FROM {}"
        else:
            grant = "GRANT ow_collector TO {} WITH ADMIN OPTION"
            revoke = "REVOKE ADMIN OPTION FOR ow_collector FROM {}"
        admin.execute(sql.SQL(grant).format(sql.Identifier(login)))
        try:
            with pytest.raises(WorkbenchError, match="UNSAFE_COLLECTOR_IDENTITY"):
                collector.validate_collector()
        finally:
            admin.execute(sql.SQL(revoke).format(sql.Identifier(login)))
    collector.validate_collector()


@pytest.mark.parametrize("corruption", ["default", "missing-default", "digest", "future"])
def test_collector_refuses_mixed_schema_or_changed_default(databases, corruption):
    _, _, roles = databases
    collector = Database(roles["collector"])
    collector.validate_collector()
    with psycopg.connect(roles["admin"], autocommit=True) as admin:
        prior = admin.execute("SELECT sha256 FROM ow.migrations WHERE version=6").fetchone()[0]
        if corruption == "default":
            admin.execute("ALTER TABLE ow.jobs ALTER COLUMN kind SET DEFAULT 'forbidden'")
        elif corruption == "missing-default":
            admin.execute("ALTER TABLE ow.jobs ALTER COLUMN kind DROP DEFAULT")
        elif corruption == "digest":
            admin.execute("UPDATE ow.migrations SET sha256=%s WHERE version=6", ("0" * 64,))
        else:
            admin.execute(
                "INSERT INTO ow.migrations(version,sha256) VALUES (%s,%s)",
                (SCHEMA_VERSION + 1, "0" * 64),
            )
        try:
            with pytest.raises(WorkbenchError, match="UNSAFE_COLLECTOR_IDENTITY"):
                collector.validate_collector()
        finally:
            if corruption in ("default", "missing-default"):
                admin.execute(
                    "ALTER TABLE ow.jobs ALTER COLUMN kind SET DEFAULT 'document.accepted'"
                )
            elif corruption == "digest":
                admin.execute("UPDATE ow.migrations SET sha256=%s WHERE version=6", (prior,))
            else:
                admin.execute("DELETE FROM ow.migrations WHERE version=%s", (SCHEMA_VERSION + 1,))
    collector.validate_collector()


@pytest.mark.parametrize("forced", [False, True])
def test_collector_refuses_row_filtered_retirement_policy(databases, tmp_path, forced):
    writer, _, roles = databases
    collector = Database(roles["collector"])
    store = EvidenceStore(tmp_path / "objects")
    document = writer.ingest(
        DocumentInput(source_id="fixture", external_id="retired", title="Fixture", text="Evidence"),
        b"raw",
        store,
    )
    change(Database(roles["lifecycle"]), document, "retire")
    collector.validate_collector()
    with psycopg.connect(roles["admin"], autocommit=True) as admin:
        admin.execute("ALTER TABLE ow.lifecycle_tombstones ENABLE ROW LEVEL SECURITY")
        if forced:
            admin.execute("ALTER TABLE ow.lifecycle_tombstones FORCE ROW LEVEL SECURITY")
        admin.execute(
            "CREATE POLICY collector_hidden_tombstones ON ow.lifecycle_tombstones "
            "FOR SELECT USING (false)"
        )
        try:
            with collector.connect() as conn:
                assert not conn.execute("SELECT source_id FROM ow.lifecycle_tombstones").fetchall()
            with pytest.raises(WorkbenchError, match="UNSAFE_COLLECTOR_IDENTITY"):
                collector.validate_collector()
        finally:
            admin.execute("DROP POLICY collector_hidden_tombstones ON ow.lifecycle_tombstones")
            admin.execute("ALTER TABLE ow.lifecycle_tombstones DISABLE ROW LEVEL SECURITY")
            admin.execute("ALTER TABLE ow.lifecycle_tombstones NO FORCE ROW LEVEL SECURITY")
    collector.validate_collector()


def test_reader_refuses_settable_collector_role_without_inherited_writes(databases):
    _, reader, roles = databases
    reader.validate_reader()
    with reader.connect() as conn:
        login = conn.info.user
    with psycopg.connect(roles["admin"], autocommit=True) as admin:
        admin.execute(
            sql.SQL("GRANT ow_collector TO {} WITH INHERIT FALSE").format(sql.Identifier(login))
        )
        try:
            with reader.connect() as conn:
                assert not conn.execute(
                    "SELECT pg_has_role(current_user,'ow_collector','USAGE') AS inherited"
                ).fetchone()["inherited"]
                assert conn.execute(
                    "SELECT pg_has_role(current_user,'ow_collector','MEMBER') AS settable"
                ).fetchone()["settable"]
            with pytest.raises(WorkbenchError, match="UNSAFE_READER_IDENTITY"):
                reader.validate_reader()
        finally:
            admin.execute(sql.SQL("REVOKE ow_collector FROM {}").format(sql.Identifier(login)))
    reader.validate_reader()


def test_reader_rejects_maintain_authority(databases):
    _, reader, roles = databases
    reader.validate_reader()
    with reader.connect() as conn:
        login = conn.info.user
    with psycopg.connect(roles["admin"], autocommit=True) as admin:
        admin.execute(sql.SQL("GRANT MAINTAIN ON ow.documents TO {}").format(sql.Identifier(login)))
        try:
            with pytest.raises(WorkbenchError, match="UNSAFE_READER_IDENTITY"):
                reader.validate_reader()
        finally:
            admin.execute(
                sql.SQL("REVOKE MAINTAIN ON ow.documents FROM {}").format(sql.Identifier(login))
            )
    reader.validate_reader()


@pytest.mark.parametrize("identity", ["reader", "collector"])
def test_narrow_current_role_cannot_conceal_broader_session_identity(
    databases, monkeypatch, identity
):
    _, _, roles = databases
    narrow = Database(roles[identity])
    with narrow.connect() as conn:
        login = conn.info.user
    administrator = Database(roles["admin"])

    def scoped_connection():
        # A real administrative connection selects a genuinely narrow login;
        # RESET ROLE could recover its session authority if accepted here.
        conn = administrator.connect()
        conn.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(login)))
        return conn

    monkeypatch.setattr(narrow, "connect", scoped_connection)
    validate = narrow.validate_reader if identity == "reader" else narrow.validate_collector
    with pytest.raises(WorkbenchError, match=f"UNSAFE_{identity.upper()}_IDENTITY"):
        validate()
