"""Governed declared-compatible remote generation: policy, ledger and adapter.

Dispatch is denied by default. Every attempt records its decision and a
conservative reservation before any network activity; see ADR-0042.
"""

import hashlib
import ipaddress
import json
import os
import re
import stat
import time
import uuid
from datetime import date
from decimal import ROUND_CEILING, Decimal
from typing import Annotated, Literal
from urllib.parse import urlsplit

import httpcore
import psycopg
from jsonschema import Draft202012Validator
from pydantic import BeforeValidator, Field, field_validator, model_validator

from . import fetch
from .contracts import Digest, StrictModel
from .database import Database
from .errors import WorkbenchError
from .text import digest

# EU member states plus EEA EFTA states. Controlling-entity jurisdiction is a
# legal-control fact, not a hosting location.
EU_EEA = frozenset(
    "AT BE BG HR CY CZ DK EE FI FR DE GR HU IE IT LV LT LU MT NL PL PT RO SK SI ES SE "
    "IS LI NO".split()
)
DataClass = Literal["public", "internal", "personal", "special"]
Task = Literal["structured_extraction"]
MAX_POLICY_BYTES = 65536
MAX_RESPONSE_BYTES = 1024 * 1024
# Input is reserved per UTF-8 byte of the whole request body, not per prompt
# character: byte-level and byte-fallback tokenizers emit at most one token per
# byte, while one character can need several tokens.
_MILLION = Decimal(1_000_000)
# Stored amounts stay within 15 significant digits so checkpoint JSON numbers
# round-trip exactly through binary floating point.
MAX_MONEY = Decimal("999999.999999999")
_CREDENTIAL = re.compile(r"[\x21-\x7e]{1,4096}")


def _decimal_text(value):
    # Money is exact decimal text; a JSON float is ambiguous in a pricebook.
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,6}(\.[0-9]{1,9})?", value):
        raise ValueError("decimal amounts must be plain decimal strings")
    return Decimal(value)


Money = Annotated[
    Decimal,
    BeforeValidator(_decimal_text),
    Field(ge=0, le=MAX_MONEY, max_digits=15, decimal_places=9),
]
Region = Annotated[str, Field(pattern=r"^([A-Z]{2}|unknown)$")]


def _is_address(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


class ProviderFacts(StrictModel):
    controlling_jurisdiction: Region
    processing_regions: list[Region] = Field(min_length=1, max_length=32)
    foreign_legal_exposure: Literal["none", "material", "unknown"]
    retention_training: Literal["none", "retained", "unknown"]
    evidence_date: date

    def conformity(self):
        facts = [self.controlling_jurisdiction, *self.processing_regions]
        if (
            "unknown" in facts
            or self.foreign_legal_exposure == "unknown"
            or self.retention_training == "unknown"
        ):
            return "unknown"
        if (
            set(facts) <= EU_EEA
            and self.foreign_legal_exposure == "none"
            and self.retention_training == "none"
        ):
            return "conforming"
        return "nonconforming"


class Pricebook(StrictModel):
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    input_per_million: Money
    output_per_million: Money
    effective_date: date

    @model_validator(mode="after")
    def priced(self):
        # An all-zero pricebook would reserve nothing and never enforce a cap.
        if self.input_per_million == 0 and self.output_per_million == 0:
            raise ValueError("a pricebook needs at least one positive rate")
        return self


class SovereigntyException(StrictModel):
    rationale: str = Field(min_length=1, max_length=500)
    tasks: list[Task] = Field(min_length=1)


class Route(StrictModel):
    route_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,63}$")
    adapter: Literal["openai-compatible-chat"]
    endpoint: str = Field(min_length=1, max_length=2048, repr=False)
    model: str = Field(pattern=r"^[\x21-\x7e]{1,200}$")
    credential_env: str = Field(pattern=r"^OW_[A-Z0-9_]{1,64}$")
    tasks: list[Task] = Field(min_length=1)
    data_classes: list[DataClass] = Field(min_length=1)
    provider: ProviderFacts
    exception: SovereigntyException | None = None
    pricebook: Pricebook
    cap: Money
    max_input_chars: int = Field(ge=1, le=200_000)
    max_output_tokens: int = Field(ge=1, le=32_768)
    timeout_seconds: int = Field(default=60, ge=1, le=120)
    enabled: bool = True

    @field_validator("endpoint")
    @classmethod
    def https_origin(cls, value):
        try:
            host, port = fetch.validate_url(value)
        except WorkbenchError:
            raise ValueError("invalid endpoint") from None
        if not value.startswith("https://") or port != 443:
            raise ValueError("endpoint must be HTTPS on port 443")
        # A query can carry secrets to the provider and its logs; credentials
        # belong in the environment. Require a named public host.
        if urlsplit(value).query or "?" in value:
            raise ValueError("endpoint must not carry a query")
        if _is_address(host) or "." not in host or host.endswith(".") or host == "localhost":
            raise ValueError("endpoint must name a qualified public host")
        return value

    @model_validator(mode="after")
    def positive_cap(self):
        if self.cap <= 0:
            raise ValueError("cap must be positive")
        return self


class CloudPolicy(StrictModel):
    schema_version: Literal[1]
    routes: list[Route] = Field(max_length=32)

    @field_validator("routes")
    @classmethod
    def unique_routes(cls, routes):
        if len({r.route_id for r in routes}) != len(routes):
            raise ValueError("duplicate route identifier")
        return routes


def load_policy(data: bytes):
    """Validate operator policy bytes and bind decisions to their digest."""
    if len(data) > MAX_POLICY_BYTES:
        raise WorkbenchError("CLOUD_POLICY_TOO_LARGE")
    try:
        policy = CloudPolicy.model_validate_json(data)
    except ValueError:
        raise WorkbenchError("CLOUD_POLICY_INVALID") from None
    return policy, hashlib.sha256(data).hexdigest()


def decide(route: Route | None, task, data_class, *, environ=None):
    """Return (decision, reason). Unknown or missing facts always deny."""
    environ = os.environ if environ is None else environ
    if route is None:
        return "denied", "ROUTE_UNKNOWN"
    if not route.enabled:
        return "denied", "ROUTE_DISABLED"
    if task not in route.tasks:
        return "denied", "TASK_NOT_ALLOWED"
    if data_class is None:
        return "denied", "DATA_CLASS_UNKNOWN"
    if data_class not in route.data_classes:
        return "denied", "DATA_CLASS_NOT_ALLOWED"
    conformity = route.provider.conformity()
    if conformity == "unknown":
        return "denied", "SOVEREIGNTY_UNKNOWN"
    decision = "conforming"
    if conformity == "nonconforming":
        if route.exception is None or task not in route.exception.tasks:
            return "denied", "SOVEREIGNTY_NONCONFORMING"
        decision = "exception"
    credential = environ.get(route.credential_env)
    if not credential:
        return "denied", "CREDENTIAL_MISSING"
    if not _CREDENTIAL.fullmatch(credential):
        # Never send a value that cannot be a single header token.
        return "denied", "CREDENTIAL_INVALID"
    return decision, None


def worst_case_cost(route: Route, input_bytes: int):
    price = route.pricebook
    amount = (
        Decimal(input_bytes) * price.input_per_million
        + Decimal(route.max_output_tokens) * price.output_per_million
    ) / _MILLION
    return amount.quantize(Decimal("0.000000001"), rounding=ROUND_CEILING)


def observed_cost(route: Route, input_tokens: int, output_tokens: int):
    price = route.pricebook
    amount = (
        Decimal(input_tokens) * price.input_per_million
        + Decimal(output_tokens) * price.output_per_million
    ) / _MILLION
    return amount.quantize(Decimal("0.000000001"), rounding=ROUND_CEILING)


# Anything that could have cost money counts at its reservation unless usage
# was reported; denied and released attempts never reached the provider. An
# operator settlement bound to provider evidence replaces either estimate.
_EXPOSURE = """SELECT coalesce(sum(CASE
    WHEN settlement_basis IS NOT NULL THEN settled_cost
    WHEN status IN ('denied','released') THEN 0
    WHEN usage='reported' THEN estimated_cost
    ELSE reserved END),0) AS exposure
    FROM ow.remote_operations WHERE route_id=%s AND currency=%s"""


def exposure(db: Database, route_id: str, currency: str):
    with db.connect() as conn:
        return conn.execute(_EXPOSURE, (route_id, currency)).fetchone()["exposure"]


class Ledger:
    def __init__(self, db: Database):
        self.db = db

    def record(
        self,
        *,
        operation_id,
        route,
        policy_sha,
        task,
        data_class,
        decision,
        reason,
        packet_sha,
        reserve,
    ):
        """Persist the decision and, when allowed, an atomic capped reservation."""
        attempt, route_id = uuid.uuid4(), route.route_id
        currency = route.pricebook.currency
        with self.db.connect() as conn:
            if decision != "denied":
                # Serialize reservations per route and currency across workers.
                # A job binds one route, so this also serializes its attempts.
                conn.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                    ("ow.remote:" + route_id + ":" + currency,),
                )
                # No blind replay: any attempt that may have reached the provider
                # blocks another for the same logical operation until settled.
                prior = conn.execute(
                    "SELECT 1 FROM ow.remote_operations WHERE operation_id=%s "
                    "AND status NOT IN ('denied','released') "
                    "AND settlement_basis IS NULL LIMIT 1",
                    (operation_id,),
                ).fetchone()
                current = conn.execute(_EXPOSURE, (route_id, currency)).fetchone()["exposure"]
                if prior:
                    decision, reason = "denied", "PRIOR_ATTEMPT_UNRESOLVED"
                elif current + reserve > route.cap:
                    decision, reason = "denied", "BUDGET_EXHAUSTED"
            status = "denied" if decision == "denied" else "reserved"
            conn.execute(
                """INSERT INTO ow.remote_operations(attempt_id,operation_id,route_id,
                policy_sha256,task,data_class,decision,reason,packet_sha256,currency,
                reserved,status) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    attempt,
                    operation_id,
                    route_id,
                    policy_sha,
                    task,
                    data_class,
                    decision,
                    reason,
                    packet_sha,
                    currency,
                    reserve if status == "reserved" else Decimal(0),
                    status,
                ),
            )
        return attempt, decision, reason

    def transition(self, attempt, expected, status, **fields):
        columns = {"status": status, **fields}
        allowed = {
            "status",
            "input_tokens",
            "output_tokens",
            "usage",
            "estimated_cost",
            "response_sha256",
            "error_code",
        }
        if set(columns) - allowed:
            raise WorkbenchError("INVALID_LEDGER_TRANSITION")
        assignments = ",".join(f"{name}=%s" for name in columns)  # fixed internal names
        try:
            with self.db.connect() as conn:
                row = conn.execute(
                    "UPDATE ow.remote_operations SET "  # noqa: S608
                    + assignments
                    + ",updated_at=clock_timestamp() WHERE attempt_id=%s AND status=%s "
                    "RETURNING attempt_id",
                    (*columns.values(), attempt, expected),
                ).fetchone()
        except (psycopg.errors.CheckViolation, psycopg.errors.SerializationFailure):
            # A settled attempt is final; a late worker outcome is refused.
            raise WorkbenchError("INVALID_LEDGER_TRANSITION") from None
        if row is None:
            raise WorkbenchError("INVALID_LEDGER_TRANSITION")


# Settlement replaces conservative exposure with an operator-asserted amount
# bound to private provider evidence by digest. The writer never settles.
MAX_EVIDENCE_BYTES = 64 * 1024 * 1024
MAX_LISTED = 500
# Mirrors migration 10: reserved or dispatched rows younger than this may still
# belong to a live worker and are refused by the database as well.
_IN_FLIGHT = (
    "status IN ('reserved','dispatched') AND updated_at > clock_timestamp() - interval '10 minutes'"
)
_ATTEMPT = (
    "attempt_id,operation_id,route_id,currency,status,reserved,usage,estimated_cost,"
    "error_code,created_at,updated_at,settlement_basis,settled_cost,"
    "settlement_evidence_sha256,settled_by,settlement_rationale,settled_at,"
    "(" + _IN_FLIGHT + ") AS in_flight"
)


class Settlement(StrictModel):
    attempt_id: uuid.UUID
    basis: Literal["invoice", "usage_export", "provider_statement", "not_dispatched"]
    cost: Money
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    evidence_sha256: Digest | None = None
    actor: str = Field(min_length=1, max_length=96)
    rationale: str = Field(min_length=1, max_length=2000)

    @model_validator(mode="after")
    def evidence_bound(self):
        # Only a reservation that never reached dispatch is settled without
        # provider evidence, and then only at zero.
        if self.basis == "not_dispatched":
            if self.cost != 0 or self.evidence_sha256 is not None:
                raise ValueError("not_dispatched settles at zero without evidence")
        elif self.evidence_sha256 is None:
            raise ValueError("provider evidence is required")
        return self


def evidence_digest(path):
    """Digest an operator evidence file without following a final symlink."""
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_EVIDENCE_BYTES:
            raise WorkbenchError("SETTLEMENT_EVIDENCE_INVALID")
        hasher, total = hashlib.sha256(), 0
        with os.fdopen(fd, "rb") as stream:
            fd = None
            while block := stream.read(1024 * 1024):
                total += len(block)
                if total > MAX_EVIDENCE_BYTES:
                    raise WorkbenchError("SETTLEMENT_EVIDENCE_INVALID")
                hasher.update(block)
    except OSError:
        raise WorkbenchError("SETTLEMENT_EVIDENCE_UNAVAILABLE") from None
    finally:
        if fd is not None:
            os.close(fd)
    return hasher.hexdigest()


def _accounting(conn):
    # Admit authority from the catalog before reading ledger rows. Writer
    # membership is refused so the identity that spends cannot settle.
    row = conn.execute(
        "SELECT coalesce(pg_has_role(current_user,to_regrole('ow_accounting')::oid,'USAGE'),"
        "false) AS accounting,pg_has_role(current_user,'ow_writer','MEMBER') AS writer"
    ).fetchone()
    if not row["accounting"] or row["writer"]:
        raise WorkbenchError("ACCOUNTING_OPERATOR_REQUIRED")


def _view(row):
    def text(value):
        if value is None or isinstance(value, bool | int | str):
            return value
        if isinstance(value, Decimal):
            return str(value)
        return value.isoformat() if hasattr(value, "isoformat") else str(value)

    return {key: text(value) for key, value in row.items()}


def unsettled(db: Database, *, route_id=None, include_estimated=False, limit=MAX_LISTED):
    """Attempts that still hold estimated exposure, oldest first."""
    if not 1 <= limit <= MAX_LISTED:
        raise WorkbenchError("INVALID_LIST_LIMIT")
    with db.connect() as conn:
        _accounting(conn)
        rows = conn.execute(
            "SELECT " + _ATTEMPT + " FROM ow.remote_operations "  # noqa: S608
            "WHERE settlement_basis IS NULL AND status NOT IN ('denied','released') "
            "AND (%s OR usage IS DISTINCT FROM 'reported') "
            "AND (%s::text IS NULL OR route_id=%s) "
            "ORDER BY created_at,attempt_id LIMIT %s",
            (include_estimated, route_id, route_id, limit + 1),
        ).fetchall()
    return {
        "attempts": [_view(r) for r in rows[:limit]],
        "truncated": len(rows) > limit,
    }


def settle(db: Database, settlement: Settlement):
    """Record one immutable settlement; an identical retry returns its receipt."""
    with db.connect() as conn:
        _accounting(conn)
        # The row lock orders this against a late worker outcome; the trigger
        # then refuses any later transition of a settled attempt.
        row = conn.execute(
            "SELECT " + _ATTEMPT + " FROM ow.remote_operations "  # noqa: S608
            "WHERE attempt_id=%s FOR UPDATE",
            (settlement.attempt_id,),
        ).fetchone()
        if row is None:
            raise WorkbenchError("ATTEMPT_NOT_FOUND")
        if row["settlement_basis"] is not None:
            same = (
                row["settlement_basis"] == settlement.basis
                and row["settled_cost"] == settlement.cost
                and row["currency"] == settlement.currency
                and row["settlement_evidence_sha256"] == settlement.evidence_sha256
                and row["settled_by"] == settlement.actor
                and row["settlement_rationale"] == settlement.rationale
            )
            if not same:
                raise WorkbenchError("SETTLEMENT_CONFLICT")
            return {**_receipt(row), "replayed": True}
        if row["status"] in ("denied", "released"):
            raise WorkbenchError("SETTLEMENT_NOT_REQUIRED")
        if row["currency"] != settlement.currency:
            raise WorkbenchError("SETTLEMENT_CURRENCY_MISMATCH")
        if settlement.basis == "not_dispatched" and row["status"] != "reserved":
            raise WorkbenchError("SETTLEMENT_BASIS_INVALID")
        if row["in_flight"]:
            raise WorkbenchError("SETTLEMENT_IN_FLIGHT")
        try:
            row = conn.execute(
                "UPDATE ow.remote_operations SET settlement_basis=%s,settled_cost=%s,"  # noqa: S608
                "settlement_evidence_sha256=%s,settled_by=%s,settlement_rationale=%s "
                "WHERE attempt_id=%s AND settlement_basis IS NULL RETURNING " + _ATTEMPT,
                (
                    settlement.basis,
                    settlement.cost,
                    settlement.evidence_sha256,
                    settlement.actor,
                    settlement.rationale,
                    settlement.attempt_id,
                ),
            ).fetchone()
        except psycopg.errors.CheckViolation:
            raise WorkbenchError("SETTLEMENT_REFUSED") from None
        conn.commit()
    return {**_receipt(row), "replayed": False}


def _receipt(row):
    view = _view(row)
    return {
        key: view[key]
        for key in (
            "attempt_id",
            "operation_id",
            "route_id",
            "currency",
            "status",
            "reserved",
            "settlement_basis",
            "settled_cost",
            "settlement_evidence_sha256",
            "settled_by",
            "settled_at",
        )
    }


class _NotSent(Exception):
    """The request provably never left: policy, DNS, TCP or TLS setup failed."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def post_json(url, body: bytes, headers, deadline, max_bytes=MAX_RESPONSE_BYTES):
    """POST over the public-destination, verified-TLS transport. No redirects."""
    fetch.validate_url(url)
    try:
        fetch._remaining(deadline)
    except WorkbenchError:
        # A worker that stalled past its deadline before sending never sends.
        raise _NotSent("REMOTE_DEADLINE_BEFORE_SEND") from None
    try:
        with httpcore.ConnectionPool(
            network_backend=fetch._PublicBackend(deadline),
            max_connections=1,
            max_keepalive_connections=0,
            retries=0,
        ) as pool:
            with pool.stream(
                "POST",
                url,
                headers=[
                    ("Accept-Encoding", "identity"),
                    ("Content-Type", "application/json"),
                    ("User-Agent", "osint-workbench/0.1"),
                    *headers,
                ],
                content=body,
                extensions={
                    "timeout": {
                        "connect": fetch._remaining(deadline),
                        "read": fetch._remaining(deadline),
                        "write": fetch._remaining(deadline),
                    }
                },
            ) as response:
                encoding = fetch._single_header(
                    response.headers, b"content-encoding", "REMOTE_PROTOCOL_ERROR"
                )
                if encoding is not None and encoding.lower() != b"identity":
                    raise WorkbenchError("REMOTE_PROTOCOL_ERROR")
                content = bytearray()
                for block in response.iter_stream():
                    fetch._remaining(deadline)
                    if len(content) + len(block) > max_bytes:
                        raise WorkbenchError("REMOTE_RESULT_LIMIT")
                    content.extend(block)
                return response.status, bytes(content)
    except WorkbenchError as exc:
        # Destination policy and resolver refusals happen before any connection.
        if exc.code == "DESTINATION_BLOCKED" or exc.code.startswith("DNS_"):
            raise _NotSent(exc.code) from None
        raise WorkbenchError("REMOTE_OUTCOME_UNKNOWN") from None
    except (httpcore.ConnectError, httpcore.ConnectTimeout):
        # TCP and TLS establishment failed; no request bytes were written.
        raise _NotSent("REMOTE_CONNECT_FAILED") from None
    except Exception:
        raise WorkbenchError("REMOTE_OUTCOME_UNKNOWN") from None


class GovernedGenerator:
    """A remote route presented through the local generator interface."""

    governed = True

    class Manifest:
        def __init__(self, route, policy_sha):
            self.route, self.policy_sha = route, policy_sha
            self.timeout_seconds = route.timeout_seconds

        def identity(self):
            # Jobs bind the exact route definition, not just its name.
            return digest(
                json.dumps(
                    ["remote-route/1", self.route.model_dump(mode="json")], sort_keys=True
                ).encode()
            )

    def __init__(
        self, db: Database, policy: CloudPolicy, policy_sha: str, route_id: str, *, environ=None
    ):
        self.db, self.policy_sha, self.route_id = db, policy_sha, route_id
        self.route = next((r for r in policy.routes if r.route_id == route_id), None)
        if self.route is None:
            raise WorkbenchError("ROUTE_UNKNOWN")
        self.manifest = self.Manifest(self.route, policy_sha)
        self.environ = os.environ if environ is None else environ
        self.ledger = Ledger(db)

    def generate(self, prompt: str, schema: dict, *, operation):
        route = self.route
        if not isinstance(prompt, str) or not 1 <= len(prompt) <= route.max_input_chars:
            raise WorkbenchError("INVALID_GENERATION_INPUT")
        Draft202012Validator.check_schema(schema)
        request = {
            "model": route.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0,
            "max_tokens": route.max_output_tokens,
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "proposals", "schema": schema, "strict": True},
            },
        }
        body = json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode()
        packet_sha = digest(body)
        decision, reason = decide(
            route, operation["task"], operation.get("data_class"), environ=self.environ
        )
        attempt, decision, reason = self.ledger.record(
            operation_id=operation["operation_id"],
            route=route,
            policy_sha=self.policy_sha,
            task=operation["task"],
            data_class=operation.get("data_class"),
            decision=decision,
            reason=reason,
            packet_sha=packet_sha,
            reserve=worst_case_cost(route, len(body)),
        )
        if decision == "denied":
            raise WorkbenchError("REMOTE_" + reason)
        credential = self.environ.get(route.credential_env, "")
        # The deadline starts before the dispatched row commits, so no request
        # byte leaves after the settlement window for in-flight attempts opens.
        deadline = time.monotonic() + route.timeout_seconds
        self.ledger.transition(attempt, "reserved", "dispatched")
        try:
            status, content = post_json(
                route.endpoint,
                body,
                [("Authorization", "Bearer " + credential)],
                deadline,
            )
        except _NotSent as exc:
            self.ledger.transition(attempt, "dispatched", "released", error_code=exc.code)
            raise WorkbenchError("REMOTE_UNAVAILABLE") from None
        except WorkbenchError:
            # The request may have been accepted and billed; never assume either way.
            self.ledger.transition(
                attempt, "dispatched", "outcome_unknown", error_code="REMOTE_OUTCOME_UNKNOWN"
            )
            raise WorkbenchError("REMOTE_OUTCOME_UNKNOWN") from None
        outcome, code, fields, output, text_sha = self._classify(status, content, schema, len(body))
        recorded = fields.pop("error_code", code)
        self.ledger.transition(attempt, "dispatched", outcome, error_code=recorded, **fields)
        if code is not None:
            raise WorkbenchError(code)
        return {
            "output": output,
            "response_sha256": text_sha,
            "prompt_sha256": digest(prompt.encode()),
            "generator_id": self.manifest.identity(),
        }

    def _classify(self, status, content, schema, request_bytes):
        """Pure classification of a complete response; it cannot leave a paid
        attempt in `dispatched`. Any unexpected shape is a protocol failure."""
        fields = {"response_sha256": digest(content), "usage": "missing"}
        if status != 200:
            recorded = f"HTTP_{status}" if 100 <= status <= 599 else "HTTP_INVALID"
            fields.update(usage=None, error_code=recorded)
            return "failed", "REMOTE_HTTP_FAILURE", fields, None, None
        try:
            decoded = json.loads(content)
            choice = decoded["choices"][0]
            message = choice["message"]
            if not isinstance(message, dict):
                raise TypeError
            finish = choice.get("finish_reason")
            usage = decoded.get("usage")
        except Exception:
            # Includes RecursionError from adversarial nesting.
            return "failed", "REMOTE_PROTOCOL_ERROR", fields, None, None
        if (
            isinstance(usage, dict)
            and type(usage.get("prompt_tokens")) is int
            and type(usage.get("completion_tokens")) is int
            # Reported usage must be physically possible for this request;
            # otherwise it is unknown and the reservation stands.
            and 1 <= usage["prompt_tokens"] <= request_bytes
            and 0 <= usage["completion_tokens"] <= self.route.max_output_tokens
        ):
            fields.update(
                input_tokens=usage["prompt_tokens"],
                output_tokens=usage["completion_tokens"],
                usage="reported",
                estimated_cost=observed_cost(
                    self.route, usage["prompt_tokens"], usage["completion_tokens"]
                ),
            )
        if message.get("refusal") or finish == "content_filter":
            return "refused", "REMOTE_REFUSED", fields, None, None
        if finish == "length":
            return "incomplete", "GENERATION_INCOMPLETE", fields, None, None
        if finish != "stop":
            return "failed", "REMOTE_PROTOCOL_ERROR", fields, None, None
        text = message.get("content")
        try:
            if not isinstance(text, str) or len(text) > 65536:
                raise ValueError
            # Lone surrogates cannot be stored or hashed as UTF-8 evidence.
            text_sha = digest(text.encode("utf-8"))
            output = json.loads(text)
            Draft202012Validator(schema).validate(output)
        except Exception:
            return "completed", "INVALID_MODEL_RESULT", fields, None, None
        return "completed", None, fields, output, text_sha
