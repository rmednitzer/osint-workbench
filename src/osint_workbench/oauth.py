"""Explicit confidential-client OAuth grant; no discovery, cache or refresh loop."""

import base64
import ipaddress
import json
import re
import time
from dataclasses import dataclass, field
from urllib.parse import quote_plus, urlencode, urlsplit

from pydantic import Field, SecretStr, model_validator

from . import fetch
from .api_http import request_json
from .api_parser import _bounded_depth, _object, _reject_constant
from .contracts import StrictModel
from .errors import SourceHTTPError, WorkbenchError

MAX_RESPONSE = 16384
_SCOPE = re.compile(r"[\x21\x23-\x5b\x5d-\x7e]{1,128}")
_TOKEN = re.compile(r"[A-Za-z0-9._~+/-]+={0,}")


class OAuthClient(StrictModel):
    token_endpoint: str = Field(min_length=1, max_length=4096, repr=False)
    client_id: str = Field(min_length=1, max_length=256, repr=False)
    scopes: list[str] = Field(min_length=1, max_length=32, repr=False)

    @model_validator(mode="after")
    def valid(self):
        host, _ = fetch.validate_url(self.token_endpoint)
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            fetch.public_addresses([str(literal)])
        if (
            urlsplit(self.token_endpoint).scheme != "https"
            or "?" in self.token_endpoint
            or "#" in self.token_endpoint
            or any(not 0x21 <= ord(c) <= 0x7E for c in self.client_id)
            or len(set(self.scopes)) != len(self.scopes)
            or any(not _SCOPE.fullmatch(scope) for scope in self.scopes)
        ):
            raise ValueError("OAUTH_CONFIGURATION_INVALID")
        return self


@dataclass(frozen=True)
class AccessGrant:
    token: SecretStr = field(repr=False)
    expires_at: float


def parse_token(raw: bytes, client: OAuthClient, started: float) -> AccessGrant:
    """Narrow RFC 6749/6750 profile; extensions are inert and never retained."""
    try:
        if len(raw) > MAX_RESPONSE:
            raise ValueError
        text = raw.decode("utf-8")
        _bounded_depth(text)
        value = json.loads(text, object_pairs_hook=_object, parse_constant=_reject_constant)
        if type(value) is not dict or "error" in value:
            raise ValueError
        token = value["access_token"]
        kind = value["token_type"]
        lifetime = value["expires_in"]
        if (
            type(token) is not str
            or not 1 <= len(token) <= 4096
            or not _TOKEN.fullmatch(token)
            or type(kind) is not str
            or kind.lower() != "bearer"
            or type(lifetime) is not int
            or not 1 <= lifetime <= 86400
        ):
            raise ValueError
        if "scope" in value:
            scope = value["scope"]
            if type(scope) is not str or len(scope) > 4127:
                raise ValueError
            scopes = scope.split(" ")
            if (
                any(not _SCOPE.fullmatch(s) for s in scopes)
                or len(set(scopes)) != len(scopes)
                or set(scopes) != set(client.scopes)
            ):
                raise ValueError
        # Start before dispatch rather than receipt, conservatively including
        # token-endpoint latency in the declared lifetime. No JWT claims trusted.
        expires_at = started + lifetime
        if expires_at <= time.monotonic():
            raise WorkbenchError("OAUTH_TOKEN_EXPIRED")
        return AccessGrant(SecretStr(token), expires_at)
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
        raise WorkbenchError("OAUTH_INVALID_RESPONSE") from None


def obtain_token(client: OAuthClient, secret: str, deadline: float) -> AccessGrant:
    # OAuth client_password authentication encodes each component as form data
    # before joining and Base64 encoding; raw colon concatenation is ambiguous.
    credentials = quote_plus(client.client_id, safe="") + ":" + quote_plus(secret, safe="")
    authorization = "Basic " + base64.b64encode(credentials.encode("ascii")).decode("ascii")
    content = urlencode(
        {"grant_type": "client_credentials", "scope": " ".join(client.scopes)}
    ).encode()
    started = time.monotonic()
    try:
        raw = request_json(
            client.token_endpoint,
            [
                ("Authorization", authorization),
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Accept", "application/json"),
                ("Accept-Encoding", "identity"),
                ("Cache-Control", "no-store"),
            ],
            deadline,
            method="POST",
            content=content,
            maximum=MAX_RESPONSE,
        )
    except SourceHTTPError:
        raise
    except WorkbenchError as exc:
        code = {
            "API_REDIRECT_REFUSED": "OAUTH_REDIRECT_REFUSED",
            "API_AUTHENTICATION_FAILED": "OAUTH_TOKEN_REJECTED",
            "API_ENTITLEMENT_DENIED": "OAUTH_TOKEN_REJECTED",
            "API_HTTP_ERROR": "OAUTH_TOKEN_REJECTED",
            "API_MEDIA_TYPE_INVALID": "OAUTH_INVALID_RESPONSE",
            "UNSUPPORTED_CONTENT_ENCODING": "OAUTH_INVALID_RESPONSE",
            "SOURCE_TOO_LARGE": "OAUTH_RESPONSE_TOO_LARGE",
        }.get(exc.code, "OAUTH_UNAVAILABLE")
        raise WorkbenchError(code) from None
    return parse_token(raw, client, started)
