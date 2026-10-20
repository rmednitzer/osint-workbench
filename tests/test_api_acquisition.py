"""API page acceptance using actual TLS, isolated parsing and native collector SQL."""

import json
import time

import psycopg
import pytest

from osint_workbench import api_acquisition, kev_projection
from osint_workbench.api_acquisition import ApiAuth, collect_api
from osint_workbench.api_parser import parse
from osint_workbench.credentials import CredentialRef
from osint_workbench.database import Database
from osint_workbench.errors import WorkbenchError
from osint_workbench.evidence import EvidenceStore
from osint_workbench.text import digest
from tests.test_api_transport import response, source
from tests.test_kev import RECORD, catalogue
from tests.test_kev import raw as kev_raw
from tests.test_oauth import ACCESS_TOKEN, CLIENT_SECRET, client, token_response
from tests.tls_fixture import generate_certificates, tls_peer

pytestmark = pytest.mark.integration
TOKEN = "synthetic-api-credential-canary-91"


@pytest.fixture(scope="module")
def collection_certificates(tmp_path_factory):
    return generate_certificates(tmp_path_factory.mktemp("api-collection") / "certs")


def body(identity, cursor=None, text="Synthetic API evidence"):
    return json.dumps(
        {
            "items": [{"id": identity, "title": "API fixture", "text": text}],
            "next_cursor": cursor,
        }
    ).encode()


def configured(tmp_path):
    token = tmp_path / "provider-token"
    token.write_text(TOKEN)
    token.chmod(0o400)
    return source(
        auth=ApiAuth(
            kind="bearer",
            context="synthetic-provider",
            credential=CredentialRef(kind="file", path=str(token)),
        )
    )


def make_due(roles):
    with psycopg.connect(roles["admin"]) as conn:
        conn.execute(
            "UPDATE ow.collection_state SET next_attempt=clock_timestamp()-interval '1 second'"
        )


def state(roles):
    with Database(roles["writer"]).connect() as conn:
        progress = conn.execute("SELECT * FROM ow.collection_state").fetchone()
        source_state = conn.execute("SELECT last_success,last_error FROM ow.sources").fetchone()
        heads = conn.execute("SELECT count(*) AS n FROM ow.document_heads").fetchone()["n"]
        return progress, source_state, heads


def assert_no_secret(roles, store):
    with psycopg.connect(roles["admin"]) as conn:
        for relation in ("documents", "snapshots", "collection_state", "collection_runs", "jobs"):
            rows = conn.execute(f"SELECT row_to_json(t)::text FROM ow.{relation} t").fetchall()
            assert TOKEN not in repr(rows)
    assert all(
        TOKEN.encode() not in file.read_bytes() for file in store.root.rglob("*") if file.is_file()
    )


def oauth_source(tmp_path, **changes):
    secret = tmp_path / "oauth-secret"
    secret.write_text(CLIENT_SECRET)
    secret.chmod(0o400)
    return source(
        auth=ApiAuth(
            kind="oauth-client-credentials",
            context="synthetic-oauth-account",
            credential=CredentialRef(kind="file", path=str(secret)),
            oauth=client(),
        ),
        **changes,
    )


def assert_oauth_not_retained(roles, store):
    with psycopg.connect(roles["admin"]) as conn:
        for relation in ("documents", "snapshots", "collection_state", "collection_runs", "jobs"):
            rows = conn.execute(f"SELECT row_to_json(t)::text FROM ow.{relation} t").fetchall()
            assert CLIENT_SECRET not in repr(rows) and ACCESS_TOKEN not in repr(rows)
    for file in store.root.rglob("*"):
        if file.is_file():
            data = file.read_bytes()
            assert CLIENT_SECRET.encode() not in data and ACCESS_TOKEN.encode() not in data


def test_actual_oauth_token_resource_sql_and_non_due_no_dispatch(
    databases, tmp_path, monkeypatch, collection_certificates
):
    _, _, roles = databases
    configuration = oauth_source(tmp_path)
    collector, store = Database(roles["collector"]), EvidenceStore(tmp_path / "objects")
    wire_body = body("oauth-record")
    original_page = api_acquisition._page
    before = time.monotonic()

    def bounded_page(source, cursor, secret, deadline):
        assert before < deadline < before + 11
        return original_page(source, cursor, secret, deadline)

    monkeypatch.setattr(api_acquisition, "_page", bounded_page)
    with tls_peer(
        monkeypatch,
        collection_certificates,
        wires=[response(token_response(expires_in=10)), response(wire_body)],
    ) as peer:
        result = collect_api(configuration, collector, store)
    assert result["status"] == "success" and result["documents"] == 1
    assert peer.sni == ["auth.fixture.invalid", "feed.fixture.invalid"]
    assert b"Basic " in peer.requests[0] and b"Bearer " not in peer.requests[0]
    assert b"Bearer " + ACCESS_TOKEN.encode() in peer.requests[1]
    assert store.get(digest(wire_body)) == wire_body
    (tmp_path / "oauth-secret").unlink()
    monkeypatch.setattr(
        api_acquisition, "obtain_token", lambda *args: pytest.fail("unexpected token request")
    )
    assert collect_api(configuration, collector, store)["status"] == "not_due"
    with psycopg.connect(roles["admin"]) as conn:
        conn.execute(
            "UPDATE ow.collection_state SET api_page=128,"
            "next_attempt=clock_timestamp()-interval '1 second'"
        )
    with pytest.raises(WorkbenchError, match="^API_CYCLE_PAGE_LIMIT$"):
        collect_api(configuration, collector, store)
    assert_oauth_not_retained(roles, store)


@pytest.mark.parametrize("reflected", [ACCESS_TOKEN, CLIENT_SECRET])
def test_actual_oauth_reflection_of_either_secret_refused_before_storage(
    databases, tmp_path, monkeypatch, collection_certificates, reflected
):
    _, _, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    wire_body = body("reflection", text=reflected).replace(b"synthetic", b"\\u0073ynthetic")
    with tls_peer(
        monkeypatch,
        collection_certificates,
        wires=[response(token_response()), response(wire_body)],
    ):
        with pytest.raises(WorkbenchError, match="^API_CREDENTIAL_REFLECTED$"):
            collect_api(oauth_source(tmp_path), Database(roles["collector"]), store)
    assert state(roles)[2] == 0
    assert not any(p.is_file() for p in store.root.rglob("*"))
    assert_oauth_not_retained(roles, store)


@pytest.mark.parametrize("stage", ["token", "resource"])
def test_actual_oauth_denial_never_reauthenticates_or_persists_response(
    databases, tmp_path, monkeypatch, collection_certificates, stage
):
    _, _, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    denied = response(token_response(), b"401 Unauthorized")
    wires = [denied] if stage == "token" else [response(token_response()), denied]
    with tls_peer(monkeypatch, collection_certificates, wires=wires) as peer:
        with pytest.raises(WorkbenchError) as caught:
            collect_api(oauth_source(tmp_path), Database(roles["collector"]), store)
    assert caught.value.code == (
        "OAUTH_TOKEN_REJECTED" if stage == "token" else "API_AUTHENTICATION_FAILED"
    )
    assert len(peer.requests) == (1 if stage == "token" else 2)
    assert state(roles)[2] == 0 and not any(p.is_file() for p in store.root.rglob("*"))
    assert_oauth_not_retained(roles, store)


def test_disabled_oauth_source_never_resolves_secret_or_token_endpoint(
    databases, tmp_path, monkeypatch
):
    _, _, roles = databases
    config = oauth_source(tmp_path, enabled=False)
    (tmp_path / "oauth-secret").unlink()
    monkeypatch.setattr(
        api_acquisition, "obtain_token", lambda *args: pytest.fail("disabled dispatch")
    )
    assert collect_api(config, Database(roles["collector"]), None)["status"] == "disabled"


def test_actual_oauth_token_retry_after_persisted_without_resource_request(
    databases, tmp_path, monkeypatch, collection_certificates
):
    _, _, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    wire = response(b"synthetic-token-failure", b"503 Unavailable", b"Retry-After: 120\r\n")
    with tls_peer(monkeypatch, collection_certificates, wire=wire) as peer:
        with pytest.raises(WorkbenchError, match="^SOURCE_HTTP_ERROR$"):
            collect_api(oauth_source(tmp_path), Database(roles["collector"]), store)
    assert len(peer.requests) == 1 and state(roles)[2] == 0
    with psycopg.connect(roles["admin"]) as conn:
        assert conn.execute(
            "SELECT next_attempt>clock_timestamp()+interval '110 seconds' FROM ow.collection_state"
        ).fetchone()[0]
    assert_oauth_not_retained(roles, store)


def test_actual_kev_tls_replay_revision_absence_and_atomic_rejection(
    databases, tmp_path, monkeypatch, collection_certificates
):
    _, _, roles = databases
    collector = Database(roles["collector"])
    collector.validate_collector()
    store = EvidenceStore(tmp_path / "objects")
    configuration = source(adapter="cisa-kev/1")
    second = dict(RECORD, cveID="CVE-2099-10002")
    pages = [
        catalogue([RECORD, second]),
        catalogue([RECORD, second], catalogVersion="synthetic-2"),
        catalogue([dict(RECORD, shortDescription="Revised synthetic evidence")]),
        catalogue([]),
    ]
    for page in pages:
        wire_body = kev_raw(page)
        with tls_peer(monkeypatch, collection_certificates, wire=response(wire_body)) as peer:
            result = collect_api(configuration, collector, store)
        assert result["status"] == "success" and result["documents"] == page["count"]
        assert peer.requests[0].startswith(b"GET /records HTTP/1.1\r\n")
        assert b"Authorization:" not in peer.requests[0]
        assert store.get(digest(wire_body)) == wire_body
        make_due(roles)
    with Database(roles["writer"]).connect() as conn:
        assert conn.execute("SELECT count(*) AS n FROM ow.documents").fetchone()["n"] == 3
        assert conn.execute("SELECT count(*) AS n FROM ow.document_heads").fetchone()["n"] == 2
        assert conn.execute("SELECT count(*) AS n FROM ow.jobs").fetchone()["n"] == 3
        assert (
            conn.execute(
                "SELECT count(*) AS n FROM ow.collection_runs WHERE raw_sha256 IS NOT NULL "
                "AND status='succeeded'"
            ).fetchone()["n"]
            == 4
        )
        rows = conn.execute(
            "SELECT d.body,d.published_at,s.extractor FROM ow.document_heads h "
            "JOIN ow.documents d USING(document_id) JOIN ow.snapshots s USING(snapshot_id)"
        ).fetchall()
        assert {json.loads(row["body"])["shortDescription"] for row in rows} == {
            "Revised synthetic evidence",
            RECORD["shortDescription"],
        }
        assert all(row["published_at"] is None and row["extractor"] == "cisa-kev/1" for row in rows)
    reader = Database(roles["reader"])
    readonly = EvidenceStore(store.root, read_only=True)
    projected = [
        kev_projection.project(reader, readonly, row["document_id"], "declared-source")
        for row in reader.search("synthetic")
    ]
    assert len(projected) == 2
    assert {p["payload"]["record"]["description"] for p in projected} == {
        "Revised synthetic evidence",
        RECORD["shortDescription"],
    }
    # The later empty catalogue does not withdraw previous immutable observations.
    assert all(p["payload"]["current_catalogue_membership"] == "not_established" for p in projected)
    before = {p.name for p in store.root.rglob("*") if p.is_file()}
    bad = kev_raw(catalogue([dict(RECORD, shortDescription="Must not be admitted")], count=2))
    with tls_peer(monkeypatch, collection_certificates, wire=response(bad)):
        with pytest.raises(WorkbenchError, match="^API_PARSE_FAILED$"):
            collect_api(configuration, collector, store)
    assert {p.name for p in store.root.rglob("*") if p.is_file()} == before
    progress, source_state, heads = state(roles)
    assert heads == 2 and progress["api_cursor"] is None
    assert (
        source_state["last_success"] is not None
        and source_state["last_error"] == "API_PARSE_FAILED"
    )


def test_actual_kev_full_catalogue_exceeds_generic_page_size(
    databases, tmp_path, monkeypatch, collection_certificates
):
    _, _, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    items = [dict(RECORD, cveID=f"CVE-2099-{10000 + n}") for n in range(1001)]
    wire_body = kev_raw(catalogue(items))
    with tls_peer(monkeypatch, collection_certificates, wire=response(wire_body)):
        result = collect_api(source(adapter="cisa-kev/1"), Database(roles["collector"]), store)
    assert result["status"] == "success" and result["documents"] == 1001
    progress, source_state, heads = state(roles)
    assert heads == 1001 and progress["raw_sha256"] == digest(wire_body)
    assert source_state["last_success"] is not None


def test_adapter_change_discards_generic_continuation_before_provider_request(
    databases, tmp_path, monkeypatch, collection_certificates
):
    _, _, roles = databases
    store = EvidenceStore(tmp_path / "objects")
    collector = Database(roles["collector"])
    with tls_peer(
        monkeypatch, collection_certificates, wire=response(body("generic", "old-cursor"))
    ):
        assert collect_api(source(), collector, store)["status"] == "partial"
    with tls_peer(monkeypatch, collection_certificates, wire=response(kev_raw())) as peer:
        assert collect_api(source(adapter="cisa-kev/1"), collector, store)["status"] == "success"
    assert peer.requests[0].startswith(b"GET /records HTTP/1.1\r\n")
    progress, _, heads = state(roles)
    assert heads == 2 and progress["api_cursor"] is None and progress["api_seen_cursors"] == []


def test_actual_tls_partial_acceptance_and_escaped_resume(
    databases, tmp_path, monkeypatch, collection_certificates
):
    _, _, roles = databases
    collector = Database(roles["collector"])
    collector.validate_collector()
    store = EvidenceStore(tmp_path / "objects")
    configuration = configured(tmp_path)
    cursor = "next +/%?&=#"
    with tls_peer(
        monkeypatch, collection_certificates, wire=response(body("first", cursor))
    ) as peer:
        first = collect_api(configuration, collector, store)
    assert first["status"] == "partial" and first["documents"] == first["pages"] == 1
    assert b"Authorization: Bearer " + TOKEN.encode() in peer.requests[0]
    progress, source_state, heads = state(roles)
    assert progress["api_cursor"] == cursor and progress["api_page"] == 1
    assert progress["api_seen_cursors"] == [digest(cursor.encode())]
    assert source_state == {"last_success": None, "last_error": "API_PARTIAL"}
    assert heads == 1
    assert collect_api(configuration, collector, store)["status"] == "not_due"
    make_due(roles)
    with tls_peer(monkeypatch, collection_certificates, wire=response(body("second"))) as peer:
        second = collect_api(configuration, collector, store)
    assert second["status"] == "success" and second["documents"] == second["pages"] == 1
    assert peer.requests[0].startswith(
        b"GET /records?cursor=next+%2B%2F%25%3F%26%3D%23 HTTP/1.1\r\n"
    )
    progress, source_state, heads = state(roles)
    assert progress["api_cursor"] is None and progress["api_page"] == 0
    assert progress["api_seen_cursors"] == []
    assert source_state["last_success"] is not None and source_state["last_error"] is None
    assert heads == 2
    assert_no_secret(roles, store)


@pytest.mark.parametrize(
    "wire,error",
    [
        (response(TOKEN.encode(), b"401 Unauthorized"), "API_AUTHENTICATION_FAILED"),
        (
            response(TOKEN.encode(), b"429 Too Many Requests", b"Retry-After: 3600\r\n"),
            "SOURCE_HTTP_ERROR",
        ),
        (
            response(TOKEN.encode(), b"302 Found", b"Location: https://other.fixture.invalid/\r\n"),
            "API_REDIRECT_REFUSED",
        ),
        (response(b'{"items":[],"next_cursor":null,"extra":true}'), "API_PARSE_FAILED"),
        (response(body("reflected", text=TOKEN)), "API_CREDENTIAL_REFLECTED"),
        # JSON-decoded reflection must be rejected even when raw substring scanning misses it.
        (
            response(body("reflected", text=TOKEN).replace(b"synthetic", b"\\u0073ynthetic")),
            "API_CREDENTIAL_REFLECTED",
        ),
    ],
)
def test_actual_tls_failures_admit_no_content_or_credentials(
    databases, tmp_path, monkeypatch, collection_certificates, wire, error
):
    _, _, roles = databases
    collector = Database(roles["collector"])
    store = EvidenceStore(tmp_path / "objects")
    with tls_peer(monkeypatch, collection_certificates, wire=wire):
        with pytest.raises(WorkbenchError) as caught:
            collect_api(configured(tmp_path), collector, store)
    assert caught.value.args == (error,)
    progress, source_state, heads = state(roles)
    assert heads == 0 and progress["api_cursor"] is None
    assert progress["raw_sha256"] is None
    assert not any(path.is_file() for path in store.root.rglob("*"))
    assert source_state == {"last_success": None, "last_error": error}
    if error == "SOURCE_HTTP_ERROR":
        with psycopg.connect(roles["admin"]) as conn:
            assert conn.execute(
                "SELECT next_attempt>clock_timestamp()+interval '3500 seconds' "
                "FROM ow.collection_state"
            ).fetchone() == (True,)
    assert_no_secret(roles, store)


def test_native_cursor_loop_across_ticks_does_not_accept_repeated_page(
    databases, tmp_path, monkeypatch
):
    _, _, roles = databases
    collector = Database(roles["collector"])
    store = EvidenceStore(tmp_path / "objects")
    pages = iter([body("first", "A"), body("second", "B"), body("third", "A")])
    requests = []

    def scripted(_source, cursor, _secret, _deadline):
        requests.append(cursor)
        return next(pages)

    monkeypatch.setattr(api_acquisition, "_page", scripted)
    # This test isolates native SQL progress/loop behavior; the test above uses
    # actual TLS and the disposable parser instead of substituting either.
    monkeypatch.setattr(
        api_acquisition,
        "_documents",
        lambda raw, source_id, deadline, adapter: parse(raw, source_id, adapter),
    )
    assert collect_api(source(), collector, store)["status"] == "partial"
    make_due(roles)
    assert collect_api(source(), collector, store)["status"] == "partial"
    make_due(roles)
    with pytest.raises(WorkbenchError, match="^API_CURSOR_LOOP$"):
        collect_api(source(), collector, store)
    progress, source_state, heads = state(roles)
    assert requests == [None, "A", "B"]
    assert progress["api_cursor"] == "B" and progress["api_page"] == 2
    assert heads == 2 and source_state["last_error"] == "API_CURSOR_LOOP"


def test_native_failed_page_rolls_back_documents_and_cursor_together(
    databases, tmp_path, monkeypatch
):
    _, _, roles = databases
    collector = Database(roles["collector"])
    store = EvidenceStore(tmp_path / "objects")
    raw = json.dumps(
        {
            "items": [
                {"id": "first", "title": "first", "text": "first evidence"},
                {"id": "second", "title": "second", "text": "second evidence"},
            ],
            "next_cursor": "advance",
        }
    ).encode()
    monkeypatch.setattr(api_acquisition, "_page", lambda *args: raw)
    monkeypatch.setattr(
        api_acquisition,
        "_documents",
        lambda raw, source_id, deadline, adapter: parse(raw, source_id, adapter),
    )
    original = collector.ingest_stored

    def failed_accept(conn, document, *args, **kwargs):
        if document.external_id == "second":
            raise WorkbenchError("SYNTHETIC_ACCEPT_FAILED")
        return original(conn, document, *args, **kwargs)

    monkeypatch.setattr(collector, "ingest_stored", failed_accept)
    with pytest.raises(WorkbenchError, match="^SYNTHETIC_ACCEPT_FAILED$"):
        collect_api(source(), collector, store)
    progress, _, heads = state(roles)
    assert heads == 0 and progress["api_cursor"] is None and progress["api_page"] == 0


def test_actual_tls_escaped_publication_timestamp_token_is_not_stored(
    databases, tmp_path, monkeypatch, collection_certificates
):
    _, _, roles = databases
    collector = Database(roles["collector"])
    store = EvidenceStore(tmp_path / "objects")
    date_token = "2026-10-18T18:00:00Z"
    token = tmp_path / "date-token"
    token.write_text(date_token)
    token.chmod(0o400)
    configuration = source(
        auth=ApiAuth(
            kind="bearer",
            context="date-token-fixture",
            credential=CredentialRef(kind="file", path=str(token)),
        )
    )
    raw = (
        json.dumps(
            {
                "items": [
                    {
                        "id": "date-reflection",
                        "title": "Fixture",
                        "text": "Evidence",
                        "published_at": date_token,
                    }
                ],
                "next_cursor": None,
            }
        )
        .encode()
        .replace(b"2026", b"\\u0032\\u0030\\u0032\\u0036")
    )
    # The JSON string decodes to the credential; raw-byte scanning cannot see it.
    assert date_token.encode() not in raw
    assert json.loads(raw)["items"][0]["published_at"] == date_token
    with tls_peer(monkeypatch, collection_certificates, wire=response(raw)):
        with pytest.raises(WorkbenchError, match="^API_CREDENTIAL_REFLECTED$"):
            collect_api(configuration, collector, store)
    progress, _, heads = state(roles)
    assert heads == 0 and progress["raw_sha256"] is None
    assert not any(path.is_file() for path in store.root.rglob("*"))


def test_native_empty_and_reused_pages_retain_each_raw_attempt(databases, tmp_path, monkeypatch):
    _, _, roles = databases
    collector = Database(roles["collector"])
    store = EvidenceStore(tmp_path / "objects")
    responses = [
        body("same-record", "A"),
        body("same-record", "B"),
        b'{"items":[],"next_cursor":null}',
    ]
    pages = iter(responses)
    monkeypatch.setattr(api_acquisition, "_page", lambda *args: next(pages))
    monkeypatch.setattr(
        api_acquisition,
        "_documents",
        lambda raw, source_id, deadline, adapter: parse(raw, source_id, adapter),
    )
    results = []
    for index in range(3):
        if index:
            make_due(roles)
        results.append(collect_api(source(), collector, store))
    assert [result["status"] for result in results] == ["partial", "partial", "success"]
    with Database(roles["writer"]).connect() as conn:
        runs = conn.execute(
            "SELECT run_id,raw_sha256 FROM ow.collection_runs ORDER BY started_at,run_id"
        ).fetchall()
    assert len(runs) == len({row["run_id"] for row in runs}) == 3
    assert {row["raw_sha256"] for row in runs} == {digest(raw) for raw in responses}
    for raw in responses:
        assert store.get(digest(raw)) == raw
    assert state(roles)[2] == 1


def test_native_disabled_source_updates_state_without_resolving_missing_secret(
    databases, tmp_path, monkeypatch
):
    _, _, roles = databases
    collector = Database(roles["collector"])
    store = EvidenceStore(tmp_path / "objects")
    monkeypatch.setattr(api_acquisition, "_page", lambda *args: body("first", "A"))
    monkeypatch.setattr(
        api_acquisition,
        "_documents",
        lambda raw, source_id, deadline, adapter: parse(raw, source_id, adapter),
    )
    assert collect_api(source(), collector, store)["status"] == "partial"

    def forbidden(*args):
        raise AssertionError("disabled source must not fetch or resolve a credential")

    monkeypatch.setattr(api_acquisition, "_page", forbidden)
    monkeypatch.setattr(api_acquisition, "resolve_credential", forbidden)
    disabled = source(
        enabled=False,
        auth=ApiAuth(
            kind="bearer",
            context="disabled-provider",
            credential=CredentialRef(kind="file", path=str(tmp_path / "missing-token")),
        ),
    )
    assert collect_api(disabled, collector, store) == {
        "status": "disabled",
        "documents": 0,
        "pages": 0,
    }
    with Database(roles["writer"]).connect() as conn:
        assert conn.execute("SELECT enabled FROM ow.sources").fetchone() == {"enabled": False}
        assert conn.execute("SELECT count(*) AS n FROM ow.collection_runs").fetchone() == {"n": 1}


def test_native_not_due_does_not_resolve_credentials(databases, tmp_path, monkeypatch):
    _, _, roles = databases
    collector = Database(roles["collector"])
    store = EvidenceStore(tmp_path / "objects")
    configuration = configured(tmp_path)
    monkeypatch.setattr(api_acquisition, "_page", lambda *args: body("first", "A"))
    monkeypatch.setattr(
        api_acquisition,
        "_documents",
        lambda raw, source_id, deadline, adapter: parse(raw, source_id, adapter),
    )
    assert collect_api(configuration, collector, store)["status"] == "partial"

    def forbidden(*args):
        raise AssertionError("not-due source must not resolve credentials")

    monkeypatch.setattr(api_acquisition, "resolve_credential", forbidden)
    assert collect_api(configuration, collector, store)["status"] == "not_due"


def test_native_explicit_restart_clears_cursor_history_success_and_due_state(
    databases, tmp_path, monkeypatch
):
    _, _, roles = databases
    collector = Database(roles["collector"])
    store = EvidenceStore(tmp_path / "objects")
    pages = iter([body("first", "old-cursor"), body("second", "fresh-cursor")])
    requests = []

    def scripted(_source, cursor, _secret, _deadline):
        requests.append(cursor)
        return next(pages)

    monkeypatch.setattr(api_acquisition, "_page", scripted)
    monkeypatch.setattr(
        api_acquisition,
        "_documents",
        lambda raw, source_id, deadline, adapter: parse(raw, source_id, adapter),
    )
    assert collect_api(source(), collector, store)["status"] == "partial"
    with psycopg.connect(roles["admin"]) as conn:
        conn.execute("UPDATE ow.sources SET last_success=clock_timestamp()-interval '1 day'")
    # Same profile and future next_attempt: only explicit restart allows this attempt.
    assert collect_api(source(), collector, store, restart=True)["status"] == "partial"
    progress, source_state, heads = state(roles)
    assert requests == [None, None]
    assert progress["api_cursor"] == "fresh-cursor" and progress["api_page"] == 1
    assert progress["api_seen_cursors"] == [digest(b"fresh-cursor")]
    assert source_state["last_success"] is None and heads == 2


def test_native_disabled_source_obeys_active_collector_lock(databases, tmp_path, monkeypatch):
    _, _, roles = databases
    collector = Database(roles["collector"])
    disabled = source(
        enabled=False,
        auth=ApiAuth(
            kind="bearer",
            context="disabled-provider",
            credential=CredentialRef(kind="file", path=str(tmp_path / "missing-token")),
        ),
    )

    def forbidden(*args):
        raise AssertionError("disabled source must not fetch or resolve a credential")

    monkeypatch.setattr(api_acquisition, "_page", forbidden)
    monkeypatch.setattr(api_acquisition, "resolve_credential", forbidden)
    with psycopg.connect(roles["admin"], autocommit=True) as active:
        active.execute(
            "INSERT INTO ow.sources(source_id,enabled) VALUES (%s,true)",
            (disabled.source_id,),
        )
        active.execute(
            "SELECT pg_advisory_lock(hashtextextended(%s,418287406))",
            (disabled.source_id,),
        )
        # An unusable store must not be inspected on this control-only path.
        assert collect_api(disabled, collector, object()) == {
            "status": "busy",
            "documents": 0,
            "pages": 0,
        }
        assert active.execute(
            "SELECT enabled FROM ow.sources WHERE source_id=%s", (disabled.source_id,)
        ).fetchone() == (True,)
    # Closing the active session releases its advisory lock. Disable can now
    # complete without the missing secret, a usable CAS, or a network request.
    assert collect_api(disabled, collector, object()) == {
        "status": "disabled",
        "documents": 0,
        "pages": 0,
    }
    with Database(roles["writer"]).connect() as conn:
        assert conn.execute("SELECT enabled FROM ow.sources").fetchone() == {"enabled": False}
        assert conn.execute("SELECT count(*) AS n FROM ow.collection_runs").fetchone() == {"n": 0}
