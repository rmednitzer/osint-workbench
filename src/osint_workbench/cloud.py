"""Governed declared-compatible remote generation: policy, ledger and adapter.

Dispatch is denied by default. Every attempt records its decision and a
conservative reservation before any network activity; see ADR-0042.
"""

import hashlib
import json
import os
import time
import uuid
from datetime import date
from decimal import ROUND_CEILING, Decimal
from typing import Annotated, Literal

import httpcore
from jsonschema import Draft202012Validator
from pydantic import BeforeValidator, Field, field_validator, model_validator

from . import fetch
from .contracts import StrictModel
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
# Characters per token is not a model fact; one token per character bounds any
# tokenizer that emits at most one token per input character for the request.
_MILLION = Decimal(1_000_000)


def _decimal_text(value):
    # Money is exact decimal text; a JSON float is ambiguous in a pricebook.
    if not isinstance(value, str):
        raise ValueError("decimal amounts must be strings")
    return Decimal(value)


Money = Annotated[
    Decimal, BeforeValidator(_decimal_text), Field(ge=0, max_digits=20, decimal_places=9)
]
Region = Annotated[str, Field(pattern=r"^([A-Z]{2}|unknown)$")]


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
            _, port = fetch.validate_url(value)
        except WorkbenchError:
            raise ValueError("invalid endpoint") from None
        if not value.startswith("https://") or port != 443:
            raise ValueError("endpoint must be HTTPS on port 443")
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
    if not environ.get(route.credential_env):
        return "denied", "CREDENTIAL_MISSING"
    return decision, None


def worst_case_cost(route: Route, input_chars: int):
    price = route.pricebook
    amount = (
        Decimal(input_chars) * price.input_per_million
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
# was reported; denied and released attempts never reached the provider.
_EXPOSURE = """SELECT coalesce(sum(CASE
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
                # blocks another for the same logical operation until reconciled.
                prior = conn.execute(
                    "SELECT 1 FROM ow.remote_operations WHERE operation_id=%s "
                    "AND status NOT IN ('denied','released') LIMIT 1",
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
        with self.db.connect() as conn:
            row = conn.execute(
                "UPDATE ow.remote_operations SET "  # noqa: S608
                + assignments
                + ",updated_at=clock_timestamp() WHERE attempt_id=%s AND status=%s "
                "RETURNING attempt_id",
                (*columns.values(), attempt, expected),
            ).fetchone()
        if row is None:
            raise WorkbenchError("INVALID_LEDGER_TRANSITION")


class _NotSent(Exception):
    """The request provably never left: policy, DNS, TCP or TLS setup failed."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def post_json(url, body: bytes, headers, timeout, max_bytes=MAX_RESPONSE_BYTES):
    """POST over the public-destination, verified-TLS transport. No redirects."""
    fetch.validate_url(url)
    deadline = time.monotonic() + timeout
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
            reserve=worst_case_cost(route, len(prompt)),
        )
        if decision == "denied":
            raise WorkbenchError("REMOTE_" + reason)
        credential = self.environ.get(route.credential_env, "")
        self.ledger.transition(attempt, "reserved", "dispatched")
        try:
            status, content = post_json(
                route.endpoint,
                body,
                [("Authorization", "Bearer " + credential)],
                route.timeout_seconds,
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
        return self._settle(attempt, status, content, schema, prompt)

    def _settle(self, attempt, status, content, schema, prompt):
        route = self.route
        response_sha = digest(content)
        if status != 200:
            self.ledger.transition(
                attempt,
                "dispatched",
                "failed",
                error_code=f"HTTP_{status}" if 100 <= status <= 599 else "HTTP_INVALID",
                response_sha256=response_sha,
            )
            raise WorkbenchError("REMOTE_HTTP_FAILURE")
        try:
            decoded = json.loads(content)
            choice = decoded["choices"][0]
            message = choice["message"]
            finish = choice.get("finish_reason")
        except (ValueError, KeyError, IndexError, TypeError):
            self.ledger.transition(
                attempt,
                "dispatched",
                "failed",
                error_code="REMOTE_PROTOCOL_ERROR",
                response_sha256=response_sha,
            )
            raise WorkbenchError("REMOTE_PROTOCOL_ERROR") from None
        usage = decoded.get("usage") if isinstance(decoded, dict) else None
        tokens = {}
        if (
            isinstance(usage, dict)
            and type(usage.get("prompt_tokens")) is int
            and type(usage.get("completion_tokens")) is int
            and usage["prompt_tokens"] >= 0
            and usage["completion_tokens"] >= 0
        ):
            tokens = {
                "input_tokens": usage["prompt_tokens"],
                "output_tokens": usage["completion_tokens"],
                "usage": "reported",
                "estimated_cost": observed_cost(
                    route, usage["prompt_tokens"], usage["completion_tokens"]
                ),
            }
        else:
            # Missing or malformed usage is unknown, never zero.
            tokens = {"usage": "missing"}
        if isinstance(message, dict) and message.get("refusal"):
            outcome, code = "refused", "REMOTE_REFUSED"
        elif finish == "content_filter":
            outcome, code = "refused", "REMOTE_REFUSED"
        elif finish == "length":
            outcome, code = "incomplete", "GENERATION_INCOMPLETE"
        elif finish != "stop":
            outcome, code = "failed", "REMOTE_PROTOCOL_ERROR"
        else:
            outcome, code = "completed", None
        text = message.get("content") if isinstance(message, dict) else None
        output = None
        if outcome == "completed":
            try:
                if not isinstance(text, str) or len(text) > 65536:
                    raise ValueError
                output = json.loads(text)
                Draft202012Validator(schema).validate(output)
            except Exception:
                outcome, code = "completed", "INVALID_MODEL_RESULT"
        self.ledger.transition(
            attempt, "dispatched", outcome, response_sha256=response_sha, error_code=code, **tokens
        )
        if code is not None:
            raise WorkbenchError(code)
        return {
            "output": output,
            "response_sha256": digest(text.encode()),
            "prompt_sha256": digest(prompt.encode()),
            "generator_id": self.manifest.identity(),
        }
