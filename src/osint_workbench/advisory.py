"""Versioned offline envelope for independently attributed vulnerability observations.

Scope is deliberately narrow: strict shape validation, bounded parsing and canonical
serialization. This module does not acquire records, parse CVE/OSV/vendor formats,
match inventories, detect exposure, prioritise, calculate CVSS scores or emit STIX.
Evidence references validate shape only; nothing here opens a snapshot or claims a
span supports a statement. See docs/advisory-records.md.

Parser errors are redacted to fixed codes. Raw pydantic ``ValidationError`` text from
direct construction is not part of that guarantee (inputs are hidden, locations are not).
"""

import json
import math
import re
import unicodedata
from datetime import UTC, date, datetime
from decimal import Decimal, InvalidOperation
from typing import Annotated, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    ValidationError,
    ValidationInfo,
    model_validator,
)

__all__ = [
    "AdvisoryFormatError",
    "AdvisoryRecord",
    "AdvisoryStatus",
    "CvssObservation",
    "EpssObservation",
    "EvidenceReference",
    "ExploitationObservation",
    "parse_advisory_record",
    "serialize_advisory_record",
]

SCHEMA_VERSION = 1
MAX_INPUT_BYTES = 262_144
MAX_NESTING_DEPTH = 8
MAX_COLLECTION_ITEMS = 64
MAX_OBSERVATION_EVIDENCE = 8
MAX_DESCRIPTION_CHARS = 4096
MAX_LABEL_CHARS = 64
MAX_RECORD_ID_CHARS = 128
MAX_REVISION_CHARS = 64
MAX_CVE_ID_CHARS = 28  # "CVE-" + 4 + "-" + 19
MAX_VECTOR_CHARS = 512
MAX_OFFSET = 2**63 - 1
MAX_INTEGER_LITERAL_DIGITS = 19
MAX_FLOAT_LITERAL_CHARS = 32

PAYLOAD_NOT_BYTES = "ADVISORY_PAYLOAD_NOT_BYTES"
PAYLOAD_TOO_LARGE = "ADVISORY_PAYLOAD_TOO_LARGE"
PAYLOAD_INVALID_UTF8 = "ADVISORY_PAYLOAD_INVALID_UTF8"
PAYLOAD_TOO_DEEP = "ADVISORY_PAYLOAD_TOO_DEEP"
PAYLOAD_INVALID_JSON = "ADVISORY_PAYLOAD_INVALID_JSON"
PAYLOAD_DUPLICATE_KEY = "ADVISORY_PAYLOAD_DUPLICATE_KEY"
PAYLOAD_NONFINITE_NUMBER = "ADVISORY_PAYLOAD_NONFINITE_NUMBER"
PAYLOAD_NUMBER_TOO_LONG = "ADVISORY_PAYLOAD_NUMBER_TOO_LONG"
PAYLOAD_NUMBER_PRECISION = "ADVISORY_PAYLOAD_NUMBER_PRECISION"
PAYLOAD_INVALID_UNICODE = "ADVISORY_PAYLOAD_INVALID_UNICODE"
PAYLOAD_NOT_OBJECT = "ADVISORY_PAYLOAD_NOT_OBJECT"
SCHEMA_VERSION_UNSUPPORTED = "ADVISORY_SCHEMA_VERSION_UNSUPPORTED"
RECORD_INVALID = "ADVISORY_RECORD_INVALID"
RECORD_NOT_SERIALIZABLE = "ADVISORY_RECORD_NOT_SERIALIZABLE"


class AdvisoryFormatError(ValueError):
    """Redacted parse/serialize failure. ``str()`` and ``args`` hold one fixed code only."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


# --------------------------------------------------------------------------- scalars

_FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cs"})  # C0/DEL/C1 controls and lone surrogates


def _no_controls(value: str) -> str:
    if any(unicodedata.category(char) in _FORBIDDEN_CATEGORIES for char in value):
        raise ValueError("text contains a control or surrogate code point")
    return value


def _pattern(regex: str, message: str):
    compiled = re.compile(regex)

    def check(value: str) -> str:
        if compiled.fullmatch(value) is None:
            raise ValueError(message)
        return value

    return check


def _json_number(value: object) -> object:
    # Rejects bool (an int subclass), numeric strings, Decimal and other look-alikes.
    if type(value) not in (int, float):
        raise ValueError("a JSON number is required")
    return value


def _canonical_float(value: float) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("number must be finite")
    return result + 0.0  # normalise negative zero


def _exact_int(value: object) -> object:
    if type(value) is not int:
        raise ValueError("an integer is required")
    return value


_DATETIME = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?"
    r"(?:Z|[+-][0-9]{2}:[0-9]{2})"
)
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


def _datetime_input(value: object, info: ValidationInfo) -> object:
    if info.mode == "json":
        if type(value) is not str or _DATETIME.fullmatch(value) is None:
            raise ValueError("timestamp must be RFC 3339 with an explicit offset")
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            pass
        raise ValueError("invalid timestamp")
    if not isinstance(value, datetime):
        raise ValueError("a datetime instance is required")
    return value


def _to_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    try:
        return value.astimezone(UTC)
    except OverflowError:
        pass
    raise ValueError("timestamp outside the supported range")


def _date_input(value: object, info: ValidationInfo) -> object:
    if info.mode == "json":
        if type(value) is not str or _DATE.fullmatch(value) is None:
            raise ValueError("date must be YYYY-MM-DD")
        try:
            return date.fromisoformat(value)
        except ValueError:
            pass
        raise ValueError("invalid date")
    if type(value) is not date:  # datetime is a date subclass and is rejected
        raise ValueError("a date instance is required")
    return value


PublisherLabel = Annotated[
    str,
    Field(min_length=1, max_length=MAX_LABEL_CHARS),
    AfterValidator(_pattern(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", "invalid publisher label")),
]
RecordId = Annotated[
    str,
    Field(min_length=1, max_length=MAX_RECORD_ID_CHARS),
    AfterValidator(_pattern(r"[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}", "invalid record id")),
]
Revision = Annotated[
    str,
    Field(min_length=1, max_length=MAX_REVISION_CHARS),
    AfterValidator(_pattern(r"[A-Za-z0-9][A-Za-z0-9._:+-]{0,63}", "invalid revision")),
]
CveId = Annotated[
    str,
    Field(min_length=13, max_length=MAX_CVE_ID_CHARS),
    AfterValidator(_pattern(r"CVE-[0-9]{4}-[0-9]{4,19}", "invalid CVE identifier")),
]
Sha256Hex = Annotated[
    str,
    Field(min_length=64, max_length=64),
    AfterValidator(_pattern(r"[0-9a-f]{64}", "invalid SHA-256 digest")),
]
CvssVector = Annotated[
    str,
    Field(min_length=1, max_length=MAX_VECTOR_CHARS),
    AfterValidator(_pattern(r"[\x21-\x7e]{1,512}", "invalid CVSS vector text")),
]
Description = Annotated[
    str,
    Field(min_length=1, max_length=MAX_DESCRIPTION_CHARS),
    AfterValidator(_no_controls),
]
CvssScore = Annotated[
    float,
    Field(ge=0, le=10, allow_inf_nan=False),
    BeforeValidator(_json_number),
    AfterValidator(_canonical_float),
]
UnitScore = Annotated[
    float,
    Field(ge=0, le=1, allow_inf_nan=False),
    BeforeValidator(_json_number),
    AfterValidator(_canonical_float),
]
SpanStart = Annotated[int, Field(ge=0, le=MAX_OFFSET - 1), BeforeValidator(_exact_int)]
SpanEnd = Annotated[int, Field(ge=1, le=MAX_OFFSET), BeforeValidator(_exact_int)]
UtcDatetime = Annotated[datetime, BeforeValidator(_datetime_input), AfterValidator(_to_utc)]
CalendarDate = Annotated[date, BeforeValidator(_date_input)]
SchemaVersion = Annotated[Literal[1], BeforeValidator(_exact_int)]
AdvisoryStatus = Literal["published", "rejected", "withdrawn", "unknown"]


# ------------------------------------------------------------------ canonical encoding


def _format_datetime(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("naive timestamp")
    utc = value.astimezone(UTC).replace(tzinfo=None)
    return utc.isoformat(timespec="microseconds" if utc.microsecond else "seconds") + "Z"


def _wire(value: object) -> object:
    if isinstance(value, BaseModel):
        if set(value.__dict__) - type(value).model_fields.keys():
            raise ValueError("unknown model fields")
        result = {}
        for name in type(value).model_fields:
            item = getattr(value, name)
            if item is not None:
                result[name] = _wire(item)
        return result
    if isinstance(value, (tuple, list)):
        return [_wire(item) for item in value]
    if isinstance(value, datetime):
        return _format_datetime(value)
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, bool):
        raise TypeError("boolean values are not part of the advisory schema")
    if isinstance(value, (str, int, float)):
        return value
    raise TypeError("unsupported value")


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _encode(record: "AdvisoryRecord") -> bytes:
    return _canonical_json(_wire(record))


def _unique(items: tuple) -> tuple:
    keys = [_canonical_json(_wire(item)) for item in items]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate item")
    return items


# ---------------------------------------------------------------------------- models


class _Frozen(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        validate_default=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
    )


class EvidenceReference(_Frozen):
    """Half-open UTF-8 byte span [start, end) in an externally preserved snapshot.

    Shape only: no file/network access and no claim the span exists or supports anything.
    """

    snapshot_sha256: Sha256Hex
    start: SpanStart
    end: SpanEnd

    @model_validator(mode="after")
    def check_span_order(self):
        if self.start >= self.end:
            raise ValueError("evidence start must precede end")
        return self


ObservationEvidence = Annotated[
    tuple[EvidenceReference, ...],
    Field(min_length=1, max_length=MAX_OBSERVATION_EVIDENCE),
    AfterValidator(_unique),
]


class CvssObservation(_Frozen):
    """A publisher's declared CVSS data. Never recalculated or checked against the vector."""

    publisher_id: PublisherLabel
    cve_id: CveId
    version: Literal["2.0", "3.0", "3.1", "4.0"]
    vector: CvssVector
    base_score: CvssScore
    evidence: ObservationEvidence


class EpssObservation(_Frozen):
    """A publisher's declared EPSS score/percentile for one model date."""

    publisher_id: PublisherLabel
    cve_id: CveId
    score: UnitScore
    percentile: UnitScore
    score_date: CalendarDate
    evidence: ObservationEvidence


class ExploitationObservation(_Frozen):
    """A publisher's exploitation statement. There is deliberately no negative status."""

    publisher_id: PublisherLabel
    cve_id: CveId
    status: Literal["reported", "unknown"]
    observation_date: CalendarDate | None = None
    evidence: ObservationEvidence


class AdvisoryRecord(_Frozen):
    """Schema-version-1 envelope. Identity is the opaque (publisher_id, record_id) pair."""

    schema_version: SchemaVersion
    publisher_id: PublisherLabel
    record_id: RecordId
    revision: Revision
    status: AdvisoryStatus
    description: Description | None = None
    observed_at: UtcDatetime
    published_at: UtcDatetime | None = None
    modified_at: UtcDatetime | None = None
    cve_ids: Annotated[
        tuple[CveId, ...],
        Field(min_length=1, max_length=MAX_COLLECTION_ITEMS),
        AfterValidator(_unique),
    ]
    evidence: Annotated[
        tuple[EvidenceReference, ...],
        Field(min_length=1, max_length=MAX_COLLECTION_ITEMS),
        AfterValidator(_unique),
    ]
    cvss: Annotated[
        tuple[CvssObservation, ...],
        Field(max_length=MAX_COLLECTION_ITEMS),
        AfterValidator(_unique),
    ] = ()
    epss: Annotated[
        tuple[EpssObservation, ...],
        Field(max_length=MAX_COLLECTION_ITEMS),
        AfterValidator(_unique),
    ] = ()
    exploitation: Annotated[
        tuple[ExploitationObservation, ...],
        Field(max_length=MAX_COLLECTION_ITEMS),
        AfterValidator(_unique),
    ] = ()

    @model_validator(mode="after")
    def check_record(self):
        identifiers = set(self.cve_ids)
        if any(
            observation.cve_id not in identifiers
            for group in (self.cvss, self.epss, self.exploitation)
            for observation in group
        ):
            raise ValueError("observation CVE absent from record")
        if (
            self.published_at is not None
            and self.modified_at is not None
            and self.modified_at < self.published_at
        ):
            raise ValueError("modified_at precedes published_at")
        if len(_encode(self)) > MAX_INPUT_BYTES:
            raise ValueError("canonical encoding exceeds the parser size limit")
        return self

    @property
    def source_key(self) -> tuple[str, str]:
        return (self.publisher_id, self.record_id)


# ---------------------------------------------------------------------------- parser


class _DuplicateKey(Exception):
    pass


class _NonFinite(Exception):
    pass


class _NumberTooLong(Exception):
    pass


class _NumberPrecision(Exception):
    pass


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey
        result[key] = value
    return result


def _reject_constant(_text):
    raise _NonFinite


def _float_literal(text: str) -> float:
    if len(text) > MAX_FLOAT_LITERAL_CHARS:
        raise _NumberTooLong
    value = float(text)
    if not math.isfinite(value):
        raise _NonFinite
    # Reject lexical values that would change at the binary64 wire boundary.
    # This catches underflow and rounding across score admission boundaries.
    try:
        precise = Decimal(text)
    except InvalidOperation:
        raise _NumberPrecision from None
    if precise != Decimal(repr(value)):
        raise _NumberPrecision
    return value


def _int_literal(text: str) -> int:
    if len(text.lstrip("-")) > MAX_INTEGER_LITERAL_DIGITS:
        raise _NumberTooLong
    return int(text)


def _nesting_exceeds(text: str, limit: int) -> bool:
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char == "{" or char == "[":
            depth += 1
            if depth > limit:
                return True
        elif char == "}" or char == "]":
            depth -= 1
    return False


_SURROGATE = re.compile("[\ud800-\udfff]")


def _has_surrogate(value: object) -> bool:
    if isinstance(value, str):
        return _SURROGATE.search(value) is not None
    if isinstance(value, dict):
        return any(_has_surrogate(k) or _has_surrogate(v) for k, v in value.items())
    if isinstance(value, list):
        return any(_has_surrogate(item) for item in value)
    return False


def parse_advisory_record(payload: bytes) -> AdvisoryRecord:
    """Parse one bounded UTF-8 JSON object. Failures raise ``AdvisoryFormatError``.

    Errors are raised outside exception handlers so no cause/context chains leak.
    """
    if type(payload) is not bytes:
        raise AdvisoryFormatError(PAYLOAD_NOT_BYTES)
    if len(payload) > MAX_INPUT_BYTES:
        raise AdvisoryFormatError(PAYLOAD_TOO_LARGE)
    code = None
    text = ""
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        code = PAYLOAD_INVALID_UTF8
    if code is not None:
        raise AdvisoryFormatError(code)
    if _nesting_exceeds(text, MAX_NESTING_DEPTH):
        raise AdvisoryFormatError(PAYLOAD_TOO_DEEP)
    value = None
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
            parse_float=_float_literal,
            parse_int=_int_literal,
        )
    except _DuplicateKey:
        code = PAYLOAD_DUPLICATE_KEY
    except _NonFinite:
        code = PAYLOAD_NONFINITE_NUMBER
    except _NumberTooLong:
        code = PAYLOAD_NUMBER_TOO_LONG
    except _NumberPrecision:
        code = PAYLOAD_NUMBER_PRECISION
    except (ValueError, TypeError, RecursionError):
        code = PAYLOAD_INVALID_JSON
    if code is not None:
        raise AdvisoryFormatError(code)
    if type(value) is not dict:
        raise AdvisoryFormatError(PAYLOAD_NOT_OBJECT)
    if _has_surrogate(value):
        raise AdvisoryFormatError(PAYLOAD_INVALID_UNICODE)
    version = value.get("schema_version")
    if type(version) is not int or version != SCHEMA_VERSION:
        raise AdvisoryFormatError(SCHEMA_VERSION_UNSUPPORTED)
    record = None
    try:
        record = AdvisoryRecord.model_validate_json(payload, strict=True)
    except (ValidationError, ValueError, TypeError, OverflowError, RecursionError):
        code = RECORD_INVALID
    if code is not None or type(record) is not AdvisoryRecord:
        raise AdvisoryFormatError(RECORD_INVALID)
    return record


def serialize_advisory_record(record: AdvisoryRecord) -> bytes:
    """Canonical UTF-8 JSON: sorted keys, ``,``/``:`` separators, no ASCII escaping.

    Output is re-parsed and re-encoded before return, so bytes produced here are
    always accepted by :func:`parse_advisory_record` and are byte-stable. Records
    with invalid fields altered behind validation fail loudly; valid copies remain valid.
    """
    if type(record) is not AdvisoryRecord:
        raise AdvisoryFormatError(RECORD_NOT_SERIALIZABLE)
    data = b""
    stable = False
    try:
        record = AdvisoryRecord.model_validate(record)
        data = _encode(record)
        stable = _encode(parse_advisory_record(data)) == data
    except (ValueError, TypeError, OverflowError, AttributeError, RecursionError):
        stable = False
    if not stable:
        raise AdvisoryFormatError(RECORD_NOT_SERIALIZABLE)
    return data
