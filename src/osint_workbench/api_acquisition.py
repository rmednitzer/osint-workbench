"""Explicit unmetered JSON-page acquisition; restricted content is not admitted."""

import json
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import timedelta
from typing import Literal
from urllib.parse import urlencode, urlsplit

from psycopg.types.json import Jsonb
from pydantic import Field, model_serializer, model_validator

from . import fetch
from .api_http import request_json
from .api_parser import item_limit
from .collection import _collection_connection
from .contracts import DocumentInput, Identifier, StrictModel
from .credentials import CredentialRef, resolve_credential
from .errors import SourceHTTPError, WorkbenchError
from .lifecycle import assert_key_visible
from .oauth import OAuthClient, obtain_token
from .text import digest


class ApiAuth(StrictModel):
    kind: Literal["none", "bearer", "api-key", "oauth-client-credentials"] = "none"
    credential: CredentialRef | None = Field(default=None, repr=False)
    header: Literal["X-API-Key", "apiKey"] = "X-API-Key"
    context: Identifier = "public"
    oauth: OAuthClient | None = Field(default=None, repr=False)

    @model_validator(mode="after")
    def coherent(self):
        if (self.kind == "none") != (self.credential is None):
            raise ValueError("API_AUTH_CONFIGURATION_INVALID")
        if (self.kind == "oauth-client-credentials") != (self.oauth is not None):
            raise ValueError("OAUTH_CONFIGURATION_INVALID")
        if self.kind != "none" and self.context == "public":
            raise ValueError("API_AUTH_CONTEXT_REQUIRED")
        return self

    @model_serializer(mode="wrap")
    def serialize(self, handler):
        result = handler(self)
        # Preserve legacy profile hashes and pending cursors for unchanged sources.
        if self.oauth is None:
            result.pop("oauth", None)
        return result


class ApiSource(StrictModel):
    source_id: Identifier
    endpoint: str = Field(min_length=1, max_length=4096, repr=False)
    enabled: bool = False
    adapter: Literal["bounded-json-pages/1", "cisa-kev/1"] = "bounded-json-pages/1"
    # Explicit operator attestations, not inferred legal clearance. Existing
    # consumers cannot enforce narrower rights, so those sources fail validation.
    rights: Literal["all-existing-uses-permitted"]
    request_billing: Literal["unmetered"]
    auth: ApiAuth = Field(default_factory=ApiAuth, repr=False)
    poll_seconds: int = Field(default=900, ge=60, le=86400)
    freshness_seconds: int = Field(default=86400, ge=60, le=31536000)

    @model_validator(mode="after")
    def destination(self):
        fetch.validate_url(self.endpoint)
        part = urlsplit(self.endpoint)
        if part.scheme != "https" or "?" in self.endpoint or "#" in self.endpoint:
            raise ValueError("API_ENDPOINT_INVALID")
        return self


def _page(source, cursor, secret, deadline):
    """No redirect, proxy, cookie jar, SDK retry or data-selected destination."""
    if source.adapter == "cisa-kev/1" and cursor is not None:
        raise WorkbenchError("API_CURSOR_INVALID")
    url = source.endpoint + ("?" + urlencode({"cursor": cursor}) if cursor is not None else "")
    headers = [("Accept", "application/json"), ("Accept-Encoding", "identity")]
    if source.auth.kind in {"bearer", "oauth-client-credentials"}:
        headers.append(("Authorization", "Bearer " + secret))
    elif source.auth.kind == "api-key":
        headers.append((source.auth.header, secret))
    return request_json(url, headers, deadline)


def _documents(raw, source_id, deadline, adapter="bounded-json-pages/1"):
    limit = item_limit(adapter)
    with tempfile.TemporaryFile() as output:
        try:
            result = subprocess.run(  # noqa: S603
                [sys.executable, "-I", "-m", "osint_workbench.api_parser", source_id, adapter],
                input=raw,
                stdout=output,
                stderr=subprocess.DEVNULL,
                env={"PYTHONIOENCODING": "utf-8"},
                timeout=min(8, fetch._remaining(deadline)),
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise WorkbenchError("API_PARSE_TIMEOUT") from None
        output.seek(0)
        data = output.read(16 * 1024 * 1024 + 1)
    fetch._remaining(deadline)
    if result.returncode or len(data) > 16 * 1024 * 1024:
        raise WorkbenchError("API_PARSE_FAILED")
    try:
        decoded = json.loads(data)
        if set(decoded) != {"documents", "next_cursor"} or len(decoded["documents"]) > limit:
            raise ValueError
        documents = [
            DocumentInput.model_validate_json(json.dumps(row)) for row in decoded["documents"]
        ]
        if any(d.source_id != source_id for d in documents):
            raise ValueError
        cursor = decoded["next_cursor"]
        if adapter == "cisa-kev/1" and cursor is not None:
            raise ValueError
        if cursor is not None and (
            not isinstance(cursor, str)
            or len(cursor) > 1024
            or any(not 32 <= ord(c) <= 126 for c in cursor)
        ):
            raise ValueError
        return documents, cursor
    except (ValueError, TypeError, KeyError):
        raise WorkbenchError("API_PARSE_FAILED") from None


def _no_reflection(raw, documents, cursor, secret):
    # Exact active-token and JSON-decoded reflection checks are a backstop,
    # not detection of arbitrary encodings or unknown secrets from a provider.
    if not secret:
        return
    # Already admitted by the strict depth/byte-bounded disposable parser.
    # Inspect original strings before timestamp normalization can hide a token.
    pending = [json.loads(raw)]
    while pending:
        value = pending.pop()
        if isinstance(value, str) and secret in value:
            raise WorkbenchError("API_CREDENTIAL_REFLECTED")
        if isinstance(value, dict):
            pending.extend(value.keys())
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)


def collect_api(source: ApiSource, db, store, *, max_pages=1, timeout=60, restart=False):
    """One bounded tick. Accepted pages and private continuation advance together."""
    if (
        type(max_pages) is not int
        or max_pages != 1
        or type(restart) is not bool
        or type(timeout) not in (int, float)
        or not 0 < timeout <= 120
    ):
        raise WorkbenchError("API_LIMIT_INVALID")
    # Revalidate objects even when constructed with a validation-bypass API.
    try:
        source = ApiSource.model_validate_json(source.model_dump_json())
    except ValueError:
        raise WorkbenchError("API_CONFIGURATION_INVALID") from None
    profile = digest(source.model_dump_json().encode())
    deadline = time.monotonic() + timeout
    with _collection_connection(db, store if source.enabled else None) as conn:
        if not conn.execute(
            "SELECT pg_try_advisory_lock(hashtextextended(%s,418287406)) AS locked",
            (source.source_id,),
        ).fetchone()["locked"]:
            conn.commit()
            return {"status": "busy", "documents": 0, "pages": 0}
        if not source.enabled:
            conn.execute(
                "UPDATE ow.sources SET enabled=false WHERE source_id=%s", (source.source_id,)
            )
            conn.commit()
            return {"status": "disabled", "documents": 0, "pages": 0}
        conn.execute(
            "INSERT INTO ow.sources(source_id,enabled,freshness_seconds) VALUES (%s,true,%s) "
            "ON CONFLICT(source_id) DO UPDATE SET "
            "enabled=true,freshness_seconds=excluded.freshness_seconds",
            (source.source_id, source.freshness_seconds),
        )
        conn.execute(
            "UPDATE ow.collection_runs SET "
            "status='interrupted',error_code='COLLECTOR_LOST',finished_at=clock_timestamp() "
            "WHERE source_id=%s AND status='running'",
            (source.source_id,),
        )
        conn.execute(
            "INSERT INTO ow.collection_state(source_id,resource_sha256) VALUES (%s,%s) ON "
            "CONFLICT(source_id) DO NOTHING",
            (source.source_id, profile),
        )
        state = conn.execute(
            "SELECT *,next_attempt<=clock_timestamp() AS due FROM ow.collection_state WHERE "
            "source_id=%s",
            (source.source_id,),
        ).fetchone()
        if restart or state["api_profile_sha256"] != profile or state["resource_sha256"] != profile:
            conn.execute(
                "UPDATE ow.collection_state SET "
                "resource_sha256=%s,api_profile_sha256=%s,api_cursor=NULL,api_page=0,api_seen_cursors='[]',etag=NULL,last_modified=NULL,raw_sha256=NULL,failures=0,next_attempt=clock_timestamp()"
                " WHERE source_id=%s",
                (profile, profile, source.source_id),
            )
            conn.execute(
                "UPDATE ow.sources SET last_success=NULL,last_error=NULL WHERE source_id=%s",
                (source.source_id,),
            )
            state.update(api_cursor=None, api_page=0, api_seen_cursors=[], failures=0, due=True)
        if not state["due"]:
            conn.commit()
            return {"status": "not_due", "documents": 0, "pages": 0}
        delay = min(86400, source.poll_seconds * 2 ** min(state["failures"], 16))
        run_id = uuid.uuid4()
        conn.execute(
            "UPDATE ow.collection_state SET "
            "failures=least(failures+1,32),next_attempt=clock_timestamp()+make_interval(secs=>%s)"
            " WHERE source_id=%s",
            (delay, source.source_id),
        )
        conn.execute(
            "UPDATE ow.sources SET last_attempt=clock_timestamp() WHERE source_id=%s",
            (source.source_id,),
        )
        conn.execute(
            "INSERT INTO ow.collection_runs(run_id,source_id,status) VALUES (%s,%s,'running')",
            (run_id, source.source_id),
        )
        conn.commit()
        accepted = pages = 0
        cursor, page, seen = state["api_cursor"], state["api_page"], state["api_seen_cursors"]
        try:
            if page >= 128:
                raise WorkbenchError("API_CYCLE_PAGE_LIMIT")
            credential = (
                resolve_credential(source.auth.credential).get_secret_value()
                if source.auth.credential
                else ""
            )
            secret, resource_deadline = credential, deadline
            if source.auth.kind == "oauth-client-credentials":
                grant = obtain_token(source.auth.oauth, credential, deadline)
                secret = grant.token.get_secret_value()
                resource_deadline = min(deadline, grant.expires_at)
            sensitive = {value for value in (secret, credential) if value}
            for _ in range(max_pages):
                raw = _page(source, cursor, secret, resource_deadline)
                if any(value.encode() in raw for value in sensitive):
                    raise WorkbenchError("API_CREDENTIAL_REFLECTED")
                documents, next_cursor = _documents(raw, source.source_id, deadline, source.adapter)
                for value in sensitive:
                    _no_reflection(raw, documents, next_cursor, value)
                token = digest(next_cursor.encode()) if next_cursor is not None else None
                if token is not None and token in seen:
                    raise WorkbenchError("API_CURSOR_LOOP")
                remaining_ms = max(1, int(fetch._remaining(deadline) * 1000))
                conn.execute(
                    "SELECT "
                    "set_config('statement_timeout',%s,true),set_config('lock_timeout',%s,true)",
                    (str(remaining_ms), str(remaining_ms)),
                )
                raw_sha = store.put(raw)
                count = suppressed = 0
                for document in documents:
                    fetch._remaining(deadline)
                    try:
                        assert_key_visible(
                            conn, document.source_id, digest(document.external_id.encode())
                        )
                        text_sha = store.put(document.text.encode())
                        db.ingest_stored(
                            conn,
                            document,
                            raw_sha,
                            text_sha,
                            source.adapter,
                            store=store,
                            observed_current=True,
                        )
                        count += 1
                    except WorkbenchError as exc:
                        if exc.code != "DOCUMENT_RETIRED_OR_EXPIRED":
                            raise
                        suppressed += 1
                page += 1
                seen = seen + ([token] if token is not None else [])
                fetch._remaining(deadline)
                conn.execute(
                    "UPDATE ow.collection_state SET "
                    "api_cursor=%s,api_page=%s,api_seen_cursors=%s,raw_sha256=%s WHERE "
                    "source_id=%s",
                    (
                        next_cursor,
                        page if next_cursor is not None else 0,
                        Jsonb(seen if next_cursor is not None else []),
                        raw_sha,
                        source.source_id,
                    ),
                )
                conn.execute(
                    "UPDATE ow.collection_runs SET "
                    "accepted_documents=accepted_documents+%s,suppressed_documents=suppressed_documents+%s,raw_sha256=%s,http_status=200"
                    " WHERE run_id=%s",
                    (count, suppressed, raw_sha, run_id),
                )
                if next_cursor is None:
                    conn.execute(
                        "UPDATE ow.sources SET last_success=clock_timestamp(),last_error=NULL"
                        " WHERE source_id=%s",
                        (source.source_id,),
                    )
                    conn.execute(
                        "UPDATE ow.collection_state SET failures=0 WHERE source_id=%s",
                        (source.source_id,),
                    )
                conn.commit()
                accepted += count
                pages += 1
                cursor = next_cursor
                if cursor is None:
                    break
            complete = cursor is None
            conn.execute(
                "UPDATE ow.collection_runs SET "
                "status=%s,finished_at=clock_timestamp(),error_code=%s WHERE "
                "run_id=%s",
                (
                    "succeeded" if complete else "failed",
                    None if complete else "API_PARTIAL",
                    run_id,
                ),
            )
            conn.execute(
                "UPDATE ow.collection_state SET "
                "failures=0,next_attempt=clock_timestamp()+make_interval(secs=>%s) WHERE "
                "source_id=%s",
                (source.poll_seconds, source.source_id),
            )
            if not complete:
                conn.execute(
                    "UPDATE ow.sources SET last_error='API_PARTIAL' WHERE source_id=%s",
                    (source.source_id,),
                )
            conn.commit()
            return {
                "status": "success" if complete else "partial",
                "documents": accepted,
                "pages": pages,
                "run_id": str(run_id),
            }
        except Exception as exc:
            code = exc.code if isinstance(exc, WorkbenchError) else "API_BACKEND_FAILURE"
            try:
                conn.rollback()
                retry_at = None
                if isinstance(exc, SourceHTTPError):
                    now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
                    if exc.retry_after_seconds is not None:
                        retry_at = now + timedelta(seconds=exc.retry_after_seconds)
                    elif exc.retry_after_at is not None:
                        retry_at = exc.retry_after_at
                    if retry_at is not None:
                        retry_at = min(
                            retry_at, now + timedelta(seconds=fetch.MAX_RETRY_AFTER_SECONDS)
                        )
                conn.execute(
                    "UPDATE ow.collection_runs SET "
                    "status='failed',error_code=%s,finished_at=clock_timestamp() WHERE "
                    "run_id=%s",
                    (code, run_id),
                )
                conn.execute(
                    "UPDATE ow.collection_state SET "
                    "next_attempt=greatest(next_attempt,%s::timestamptz) WHERE source_id=%s",
                    (retry_at, source.source_id),
                )
                conn.execute(
                    "UPDATE ow.sources SET last_error=%s WHERE source_id=%s",
                    (code, source.source_id),
                )
                conn.commit()
            except Exception:
                conn.close()
                raise WorkbenchError("COLLECTION_STATE_PERSIST_FAILED") from None
            raise WorkbenchError(code) from None
