"""Data-only parser inputs and source-scoped early failure boundaries."""

import json
import socket

import psycopg
import pytest

from osint_workbench import cli
from osint_workbench.collection import collect, collect_due, feed_documents
from osint_workbench.contracts import Source, SourceConfig
from osint_workbench.database import Database
from osint_workbench.errors import WorkbenchError
from osint_workbench.evidence import EvidenceStore
from osint_workbench.fetch import fetch_response, validate_url
from tests.test_scheduled_collection import ResponseWire, install
from tests.test_workflows import FEED


@pytest.mark.parametrize("kind", ["path", "file-url"])
def test_parser_child_treats_existing_feed_path_as_data(tmp_path, kind):
    outside = tmp_path / "synthetic-feed.xml"
    outside.write_bytes(FEED)
    raw = str(outside).encode() if kind == "path" else outside.as_uri().encode()
    with pytest.raises(WorkbenchError, match="FEED_PARSE_FAILED"):
        feed_documents(raw, "fixture")


def test_parser_child_treats_local_http_url_as_data_without_connecting():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(0.05)
        raw = ("http:" + f"//127.0.0.1:{listener.getsockname()[1]}/feed").encode()
        with pytest.raises(WorkbenchError, match="FEED_PARSE_FAILED"):
            feed_documents(raw, "fixture")
        with pytest.raises(TimeoutError):
            listener.accept()


@pytest.mark.parametrize(
    "url",
    [
        "https://füttern.invalid/feed",
        "https://feed.fixture.invalid/über",
        "https://feed.fixture.invalid/feed?q=über",
        "https://feed.fixture.invalid/\x7f",
    ],
)
def test_non_ascii_or_del_url_is_typed_before_any_transport(url, monkeypatch):
    def unavailable(*args, **kwargs):
        raise AssertionError("URL validation must precede network dispatch")

    monkeypatch.setattr("osint_workbench.fetch._PublicBackend.connect_tcp", unavailable)
    with pytest.raises(WorkbenchError, match="INVALID_SOURCE_URL"):
        fetch_response(url)


def test_explicit_ascii_idna_and_percent_encoding_preserve_resource():
    assert validate_url("https://xn--fttern-3ya.invalid/%C3%BCber?q=%C3%BCber") == (
        "xn--fttern-3ya.invalid",
        443,
    )


def test_early_database_connection_failure_is_sanitized(tmp_path, monkeypatch):
    db = Database("synthetic-unused")
    attempts = []

    def fail(**kwargs):
        attempts.append(True)
        raise psycopg.OperationalError("synthetic-private-backend-canary")

    monkeypatch.setattr(db, "connect", fail)
    with pytest.raises(WorkbenchError, match="COLLECT_BACKEND_FAILURE") as caught:
        collect(
            Source(source_id="fixture", url="http://example.invalid/feed"),
            db,
            EvidenceStore(tmp_path / "objects"),
        )
    assert attempts == [True]
    assert caught.value.args == ("COLLECT_BACKEND_FAILURE",)
    assert "canary" not in repr(caught.value)


@pytest.mark.integration
@pytest.mark.parametrize("interface", ["due", "manual-cli"])
def test_native_setup_failure_does_not_abort_independent_sources(
    databases, tmp_path, monkeypatch, capsys, interface
):
    _, reader, roles = databases
    sources = [
        Source(source_id=name, url="http://example.invalid/feed")
        for name in ("blocked-fixture", "independent-fixture")
    ]
    root = tmp_path / "objects"
    db = Database(roles["collector"])
    install(monkeypatch, ResponseWire())
    with psycopg.connect(roles["admin"], autocommit=True) as admin:
        admin.execute("""CREATE FUNCTION ow.reject_audit_source() RETURNS trigger
          LANGUAGE plpgsql AS $$ BEGIN
          IF NEW.source_id='blocked-fixture' THEN
            RAISE EXCEPTION 'synthetic-private-backend-canary';
          END IF; RETURN NEW; END $$""")
        admin.execute(
            "CREATE TRIGGER audit_reject BEFORE INSERT OR UPDATE ON ow.sources "
            "FOR EACH ROW EXECUTE FUNCTION ow.reject_audit_source()"
        )
        try:
            if interface == "due":
                result = collect_due(sources, db, EvidenceStore(root))
                rows = result["results"]
                assert result["status"] == "failed"
            else:
                config = tmp_path / "sources.json"
                config.write_text(SourceConfig(sources=sources).model_dump_json())
                monkeypatch.setenv("OW_COLLECTOR_DSN", roles["collector"])
                monkeypatch.setenv("OW_EVIDENCE_ROOT", str(root))
                monkeypatch.setattr(
                    "sys.argv", ["osint-workbench", "collect", "--config", str(config)]
                )
                with pytest.raises(SystemExit) as exit_status:
                    cli.main()
                assert exit_status.value.code == 1
                rows = json.loads(capsys.readouterr().out)
            assert rows[0]["error"] == "COLLECT_BACKEND_FAILURE"
            assert rows[1]["status"] == "success" and rows[1]["documents"] == 2
            assert "canary" not in repr(rows)
            assert reader.status()["documents"] == 2
            assert admin.execute("SELECT count(*) FROM ow.collection_runs").fetchone()[0] == 1
        finally:
            admin.execute("DROP TRIGGER audit_reject ON ow.sources")
            admin.execute("DROP FUNCTION ow.reject_audit_source()")
