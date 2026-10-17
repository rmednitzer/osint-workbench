"""Behavioural tests for the offline advisory envelope. All fixtures are synthetic."""

import hashlib
import json
from datetime import UTC, date, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from osint_workbench.advisory import (
    MAX_COLLECTION_ITEMS,
    MAX_INPUT_BYTES,
    MAX_OFFSET,
    AdvisoryFormatError,
    AdvisoryRecord,
    CvssObservation,
    EpssObservation,
    EvidenceReference,
    ExploitationObservation,
    parse_advisory_record,
    serialize_advisory_record,
)

SNAP_A = hashlib.sha256(b"synthetic snapshot a").hexdigest()
SNAP_B = hashlib.sha256(b"synthetic snapshot b").hexdigest()
CANARY = "CANARY-7f3e91-PRIVATE"


def ref(start=0, end=16, snapshot=SNAP_A):
    return {"snapshot_sha256": snapshot, "start": start, "end": end}


def base_payload():
    return {
        "schema_version": 1,
        "publisher_id": "synthetic-cna",
        "record_id": "SYN-ADV-2099-0001",
        "revision": "r1",
        "status": "published",
        "observed_at": "2099-01-05T08:00:00Z",
        "cve_ids": ["CVE-2099-0001"],
        "evidence": [ref()],
    }


def full_payload():
    payload = base_payload()
    payload.update(
        description="Synthetic overflow in an invented component.",
        published_at="2099-01-02T00:00:00Z",
        modified_at="2099-01-03T00:00:00Z",
        cvss=[
            {
                "publisher_id": "synthetic-scorer-a",
                "cve_id": "CVE-2099-0001",
                "version": "3.1",
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "base_score": 9.8,
                "evidence": [ref(100, 140)],
            }
        ],
        epss=[
            {
                "publisher_id": "synthetic-epss",
                "cve_id": "CVE-2099-0001",
                "score": 0.25,
                "percentile": 0.9,
                "score_date": "2099-01-04",
                "evidence": [ref(0, 8, SNAP_B)],
            }
        ],
        exploitation=[
            {
                "publisher_id": "synthetic-catalogue",
                "cve_id": "CVE-2099-0001",
                "status": "reported",
                "observation_date": "2099-01-01",
                "evidence": [ref(8, 24, SNAP_B)],
            }
        ],
    )
    return payload


def encode(obj) -> bytes:
    return json.dumps(obj).encode("utf-8")


def parse(obj) -> AdvisoryRecord:
    return parse_advisory_record(encode(obj))


def rejected(data: bytes) -> AdvisoryFormatError:
    with pytest.raises(AdvisoryFormatError) as info:
        parse_advisory_record(data)
    return info.value


def assert_redacted(error: BaseException, *secrets: str):
    for text in (str(error), repr(error), *map(str, error.args)):
        for secret in (CANARY, *secrets):
            assert secret not in text
    assert error.__cause__ is None
    assert error.__context__ is None


def reverse_keys(obj):
    if isinstance(obj, dict):
        return {k: reverse_keys(obj[k]) for k in reversed(list(obj))}
    if isinstance(obj, list):
        return [reverse_keys(item) for item in obj]
    return obj


def evidence(start=0, end=16, snapshot=SNAP_A):
    return EvidenceReference(snapshot_sha256=snapshot, start=start, end=end)


def record(**overrides):
    fields = dict(
        schema_version=1,
        publisher_id="synthetic-cna",
        record_id="SYN-ADV-2099-0001",
        revision="r1",
        status="published",
        observed_at=datetime(2099, 1, 5, 8, tzinfo=UTC),
        cve_ids=("CVE-2099-0001",),
        evidence=(evidence(),),
    )
    fields.update(overrides)
    return AdvisoryRecord(**fields)


# ------------------------------------------------------------------ positive paths


def test_minimal_record_keeps_absent_fields_absent():
    parsed = parse(base_payload())
    assert parsed.published_at is None and parsed.modified_at is None
    assert parsed.description is None
    assert parsed.cvss == () and parsed.epss == () and parsed.exploitation == ()
    assert parsed.source_key == ("synthetic-cna", "SYN-ADV-2099-0001")
    out = json.loads(serialize_advisory_record(parsed))
    assert "published_at" not in out and "modified_at" not in out and "description" not in out
    assert out["exploitation"] == []


def test_round_trip_is_canonical_and_independent_of_key_order():
    payload = full_payload()
    first = serialize_advisory_record(parse(payload))
    shuffled = json.dumps(reverse_keys(payload), indent=3).encode()
    assert serialize_advisory_record(parse_advisory_record(shuffled)) == first
    reparsed = parse_advisory_record(first)
    assert reparsed == parse(payload)
    assert serialize_advisory_record(reparsed) == first
    expected = json.dumps(
        json.loads(first), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    assert first == expected
    assert b" :" not in first and b": " not in first and b"\n" not in first


def test_unicode_and_timezone_normalisation_round_trip():
    payload = base_payload()
    payload["description"] = "Synthetischer Überlauf — 測試 🛡 \u202ebidi stays data"
    payload["observed_at"] = "2099-03-01T12:00:00.5+02:00"
    payload["published_at"] = "2099-02-28T23:30:00-05:00"
    parsed = parse(payload)
    assert parsed.observed_at == datetime(2099, 3, 1, 10, 0, 0, 500000, tzinfo=UTC)
    assert parsed.observed_at.tzinfo is UTC
    data = serialize_advisory_record(parsed)
    assert "Überlauf — 測試 🛡".encode() in data and b"\\u" not in data
    out = json.loads(data)
    assert out["observed_at"] == "2099-03-01T10:00:00.500000Z"
    assert out["published_at"] == "2099-03-01T04:30:00Z"
    assert parse_advisory_record(data) == parsed


def test_records_built_through_constructors_serialize_to_parseable_bytes():
    built = record(
        description="Synthetic text ✓",
        observed_at=datetime(2099, 1, 5, 8, tzinfo=timezone(timedelta(hours=5, minutes=30))),
        cvss=(
            CvssObservation(
                cve_id="CVE-2099-0001",
                publisher_id="synthetic-scorer-a",
                version="4.0",
                vector="CVSS:4.0/AV:N",
                base_score=10,
                evidence=(evidence(1, 2),),
            ),
            CvssObservation(
                cve_id="CVE-2099-0001",
                publisher_id="synthetic-scorer-b",
                version="2.0",
                vector="AV:L/AC:H",
                base_score=0.0,
                evidence=(evidence(1, 2),),
            ),
        ),
        epss=(
            EpssObservation(
                cve_id="CVE-2099-0001",
                publisher_id="synthetic-epss",
                score=0,
                percentile=1,
                score_date=date(2099, 1, 4),
                evidence=(evidence(),),
            ),
        ),
    )
    assert type(built.cvss[0].base_score) is float and type(built.epss[0].score) is float
    assert built.observed_at == datetime(2099, 1, 5, 2, 30, tzinfo=UTC)
    data = serialize_advisory_record(built)
    out = json.loads(data)
    assert [c["base_score"] for c in out["cvss"]] == [10.0, 0.0]
    assert b'"base_score":10.0' in data and b'"score":0.0' in data
    assert out["epss"][0]["percentile"] == 1.0
    assert parse_advisory_record(data) == built


def test_numeric_lexical_contract_is_binary64():
    payload = full_payload()
    payload["cvss"][0]["base_score"] = 7
    payload["epss"][0]["score"] = 1e-7
    raw = encode(payload).replace(b'"base_score": 7', b'"base_score": 7.50')
    parsed = parse_advisory_record(raw)
    assert parsed.cvss[0].base_score == 7.5
    assert parsed.epss[0].score == 1e-7
    data = serialize_advisory_record(parsed)
    assert b'"base_score":7.5' in data
    assert parse_advisory_record(data).epss[0].score == 1e-7
    negative_zero = full_payload()
    negative_zero["epss"][0]["percentile"] = -0.0
    assert b'"percentile":0.0' in serialize_advisory_record(parse(negative_zero))


def test_distinct_dates_are_preserved_without_inference():
    parsed = parse(full_payload())
    assert parsed.published_at == datetime(2099, 1, 2, tzinfo=UTC)
    assert parsed.modified_at == datetime(2099, 1, 3, tzinfo=UTC)
    assert parsed.observed_at == datetime(2099, 1, 5, 8, tzinfo=UTC)
    assert parsed.epss[0].score_date == date(2099, 1, 4)
    assert parsed.exploitation[0].observation_date == date(2099, 1, 1)
    only_modified = base_payload()
    only_modified["modified_at"] = "2099-01-03T00:00:00Z"
    parsed = parse(only_modified)
    assert parsed.published_at is None and parsed.modified_at is not None
    same = base_payload()
    same["published_at"] = same["modified_at"] = "2099-01-03T00:00:00Z"
    assert parse(same).modified_at == parse(same).published_at


def test_modified_before_published_rejected_by_parser_and_constructor():
    payload = base_payload()
    payload["published_at"] = "2099-01-03T00:00:00Z"
    payload["modified_at"] = "2099-01-02T23:59:59Z"
    assert rejected(encode(payload)).code == "ADVISORY_RECORD_INVALID"
    with pytest.raises(ValidationError):
        record(
            published_at=datetime(2099, 1, 3, tzinfo=UTC),
            modified_at=datetime(2099, 1, 2, tzinfo=UTC),
        )


def test_status_is_declared_never_inferred():
    for status in ("published", "rejected", "withdrawn", "unknown"):
        payload = base_payload()
        payload["status"] = status
        payload["description"] = "** REJECT ** synthetic text that a heuristic might misread"
        assert parse(payload).status == status
    for bad in ("Published", "disputed", "", 1, None):
        payload = base_payload()
        payload["status"] = bad
        rejected(encode(payload))


# ---------------------------------------------------------------- identifiers/text


def test_cve_ids_keep_first_seen_order():
    payload = base_payload()
    payload["cve_ids"] = ["CVE-2099-1002", "CVE-2099-0001", "CVE-2099-" + "9" * 19]
    assert parse(payload).cve_ids == tuple(payload["cve_ids"])


@pytest.mark.parametrize(
    "cve",
    [
        "cve-2099-0001",
        "Cve-2099-0001",
        "CVE-99-0001",
        "CVE-2099-001",
        "CVE-2099-" + "1" * 20,
        " CVE-2099-0001",
        "CVE-2099-0001\n",
        "CVE-２０９９-0001",
        "CVE-2099-0001x",
        "",
        2099,
    ],
)
def test_noncanonical_cve_ids_rejected_not_normalised(cve):
    payload = base_payload()
    payload["cve_ids"] = [cve]
    assert rejected(encode(payload)).code == "ADVISORY_RECORD_INVALID"


def test_duplicate_or_missing_cve_ids_rejected():
    for ids in ([], ["CVE-2099-0001", "CVE-2099-0001"]):
        payload = base_payload()
        payload["cve_ids"] = ids
        rejected(encode(payload))
    payload = base_payload()
    del payload["cve_ids"]
    rejected(encode(payload))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("publisher_id", "vendor.example"),
        ("publisher_id", "synthetic cna"),
        ("publisher_id", "-leading"),
        ("publisher_id", "x" * 65),
        ("publisher_id", ""),
        ("record_id", "SYN\x00ADV"),
        ("record_id", "SYN/ADV"),
        ("record_id", "x" * 129),
        ("revision", ""),
        ("revision", "r" * 65),
        ("description", ""),
        ("description", "x" * 4097),
        ("description", "bell\x07"),
        ("description", "line\nbreak"),
        ("description", "c1\u0085control"),
        ("description", "del\x7f"),
    ],
)
def test_textual_fields_bounded_and_control_free(field, value):
    payload = base_payload()
    payload[field] = value
    assert rejected(encode(payload)).code == "ADVISORY_RECORD_INVALID"


def test_text_length_boundaries_accepted():
    payload = base_payload()
    payload.update(
        publisher_id="p" * 64, record_id="R" * 128, revision="v" * 64, description="d" * 4096
    )
    parsed = parse(payload)
    assert parse_advisory_record(serialize_advisory_record(parsed)) == parsed


def test_publisher_labels_are_opaque_and_case_distinct():
    payload = full_payload()
    payload["cvss"].append(dict(payload["cvss"][0], publisher_id="Synthetic-Scorer-A"))
    labels = [c.publisher_id for c in parse(payload).cvss]
    assert labels == ["synthetic-scorer-a", "Synthetic-Scorer-A"]


# ---------------------------------------------------------------------- evidence


@pytest.mark.parametrize(
    "bad",
    [
        ref(snapshot=SNAP_A.upper()),
        ref(snapshot=SNAP_A[:63]),
        ref(snapshot=SNAP_A + "0"),
        ref(snapshot="g" * 64),
        ref(start=5, end=5),
        ref(start=6, end=5),
        ref(start=-1, end=5),
        ref(start=0, end=0),
        ref(start=True, end=5),
        ref(start=0, end=True),
        ref(start=0, end=1.0),
        ref(start=0, end="10"),
        ref(start=MAX_OFFSET, end=MAX_OFFSET),
        ref(start=0, end=MAX_OFFSET + 1),
        {"snapshot_sha256": SNAP_A, "start": 0},
        dict(ref(), path="/tmp/x"),
    ],
)
def test_malformed_evidence_rejected(bad):
    payload = base_payload()
    payload["evidence"] = [bad]
    rejected(encode(payload))


def test_evidence_references_validate_shape_only():
    payload = base_payload()
    payload["evidence"] = [
        ref(0, 1),
        ref(0, 1, SNAP_B),
        ref(MAX_OFFSET - 1, MAX_OFFSET, hashlib.sha256(b"never stored").hexdigest()),
    ]
    assert len(parse(payload).evidence) == 3
    payload["evidence"].append(ref(0, 1))
    rejected(encode(payload))
    payload["evidence"] = []
    rejected(encode(payload))


def test_observations_require_their_own_evidence_and_publisher():
    for group in ("cvss", "epss", "exploitation"):
        for mutate in (
            lambda o: o.pop("evidence"),
            lambda o: o.update(evidence=[]),
            lambda o: o.pop("publisher_id"),
            lambda o: o.update(publisher_id=""),
            lambda o: o.update(evidence=[ref(0, 1), ref(0, 1)]),
            lambda o: o.update(evidence=[ref(i, i + 1) for i in range(9)]),
        ):
            payload = full_payload()
            mutate(payload[group][0])
            rejected(encode(payload))
        payload = full_payload()
        payload[group][0]["evidence"] = [ref(i, i + 1) for i in range(8)]
        assert len(getattr(parse(payload), group)[0].evidence) == 8


# ------------------------------------------------------------------ observations


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("version", "3"),
        ("version", "3.2"),
        ("version", 3.1),
        ("base_score", 10.0001),
        ("base_score", -0.1),
        ("base_score", True),
        ("base_score", "7.5"),
        ("base_score", None),
        ("vector", ""),
        ("vector", "CVSS:3.1/AV:N AC:L"),
        ("vector", "x" * 513),
        ("vector", "CVSS:3.1/AV:N\x00"),
    ],
)
def test_cvss_bounds(key, value):
    payload = full_payload()
    payload["cvss"][0][key] = value
    rejected(encode(payload))


def test_cvss_vector_and_score_are_not_reconciled():
    payload = full_payload()
    payload["cvss"][0].update(version="2.0", vector="CVSS:3.1/AV:N/C:H", base_score=0)
    observation = parse(payload).cvss[0]
    assert (observation.version, observation.base_score) == ("2.0", 0.0)
    assert observation.vector == "CVSS:3.1/AV:N/C:H"


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("score", 1.01),
        ("score", -0.01),
        ("score", False),
        ("percentile", "0.5"),
        ("score_date", "2099-1-04"),
        ("score_date", "2099-02-30"),
        ("score_date", "2099-01-04T00:00:00Z"),
        ("score_date", 20990104),
        ("score_date", None),
    ],
)
def test_epss_bounds(key, value):
    payload = full_payload()
    payload["epss"][0][key] = value
    rejected(encode(payload))


def test_epss_zero_is_a_value_and_absence_is_not_zero():
    payload = full_payload()
    payload["epss"][0].update(score=0, percentile=0)
    assert parse(payload).epss[0].score == 0.0
    assert parse(base_payload()).epss == ()
    payload["epss"][0].pop("score")
    rejected(encode(payload))


@pytest.mark.parametrize("status", ["not_exploited", "none", "exploited", "false", "", None])
def test_exploitation_has_no_negative_status(status):
    payload = full_payload()
    payload["exploitation"][0]["status"] = status
    rejected(encode(payload))


def test_unknown_exploitation_keeps_its_evidence_and_implies_nothing():
    payload = full_payload()
    payload["exploitation"] = [
        {
            "publisher_id": "synthetic-catalogue",
            "cve_id": "CVE-2099-0001",
            "status": "unknown",
            "evidence": [ref(3, 9)],
        }
    ]
    observation = parse(payload).exploitation[0]
    assert observation.status == "unknown" and observation.observation_date is None
    assert observation.evidence == (evidence(3, 9),)
    fields = set(ExploitationObservation.model_fields)
    assert fields == {"publisher_id", "cve_id", "status", "observation_date", "evidence"}


def test_conflicting_publisher_observations_are_all_retained_in_order():
    payload = full_payload()
    first = payload["cvss"][0]
    payload["cvss"] = [
        first,
        dict(first, publisher_id="synthetic-scorer-b", base_score=5.3),
        dict(first, base_score=7.5),  # same publisher, contradictory score
    ]
    payload["epss"].append(dict(payload["epss"][0], score=0.01, percentile=0.1))
    payload["exploitation"].append(
        {
            "publisher_id": "synthetic-catalogue-b",
            "cve_id": "CVE-2099-0001",
            "status": "unknown",
            "evidence": [ref(1, 2)],
        }
    )
    parsed = parse(payload)
    assert [(c.publisher_id, c.base_score) for c in parsed.cvss] == [
        ("synthetic-scorer-a", 9.8),
        ("synthetic-scorer-b", 5.3),
        ("synthetic-scorer-a", 7.5),
    ]
    assert [e.score for e in parsed.epss] == [0.25, 0.01]
    assert [x.status for x in parsed.exploitation] == ["reported", "unknown"]
    assert parse_advisory_record(serialize_advisory_record(parsed)) == parsed
    payload["cvss"].append(first)  # an exact repeat is an error, not silently dropped
    rejected(encode(payload))


def test_envelope_offers_no_applicability_exposure_or_priority_conclusion():
    fields = set(AdvisoryRecord.model_fields)
    assert fields == {
        "schema_version",
        "publisher_id",
        "record_id",
        "revision",
        "status",
        "description",
        "observed_at",
        "published_at",
        "modified_at",
        "cve_ids",
        "evidence",
        "cvss",
        "epss",
        "exploitation",
    }
    parsed = parse(full_payload())
    for word in ("affected", "applicable", "exposed", "exploited", "priority", "deadline"):
        assert not any(word in name for name in dir(parsed))
    for key in ("affected", "exposure", "priority", "kev"):
        payload = full_payload()
        payload[key] = True
        rejected(encode(payload))


# ---------------------------------------------------------- strict primitives


@pytest.mark.parametrize("version", [True, "1", 1.0, 2, 0, None, [1]])
def test_unknown_or_non_integer_schema_versions_rejected(version):
    payload = base_payload()
    payload["schema_version"] = version
    assert rejected(encode(payload)).code == "ADVISORY_SCHEMA_VERSION_UNSUPPORTED"
    del payload["schema_version"]
    assert rejected(encode(payload)).code == "ADVISORY_SCHEMA_VERSION_UNSUPPORTED"


@pytest.mark.parametrize(
    "stamp",
    [
        "2099-03-01T12:00:00",
        "2099-03-01 12:00:00Z",
        "2099-03-01T12:00:00z",
        "2099-03-01T12:00:00.1234567Z",
        "2099-03-01T24:00:00Z",
        "2099-03-01T12:00:60Z",
        "2099-03-01T12:00:00+0200",
        "2099-03-01",
        "0001-01-01T00:00:00+01:00",
        1700000000,
        "",
    ],
)
def test_timestamp_lexical_contract(stamp):
    payload = base_payload()
    payload["observed_at"] = stamp
    assert rejected(encode(payload)).code == "ADVISORY_RECORD_INVALID"


def test_nonfinite_and_oversized_number_literals_rejected():
    template = encode(full_payload())
    assert b'"base_score": 9.8' in template
    for literal, code in (
        (b"NaN", "ADVISORY_PAYLOAD_NONFINITE_NUMBER"),
        (b"Infinity", "ADVISORY_PAYLOAD_NONFINITE_NUMBER"),
        (b"-Infinity", "ADVISORY_PAYLOAD_NONFINITE_NUMBER"),
        (b"1e400", "ADVISORY_PAYLOAD_NONFINITE_NUMBER"),
        (b"9." + b"1" * 40, "ADVISORY_PAYLOAD_NUMBER_TOO_LONG"),
        (b"1" * 20, "ADVISORY_PAYLOAD_NUMBER_TOO_LONG"),
    ):
        data = template.replace(b'"base_score": 9.8', b'"base_score": ' + literal)
        assert rejected(data).code == code


def test_unknown_keys_rejected_at_every_level():
    for path in ((), ("cvss", 0), ("epss", 0), ("exploitation", 0), ("evidence", 0)):
        payload = full_payload()
        target = payload
        for step in path:
            target = target[step]
        target["unexpected"] = 1
        assert rejected(encode(payload)).code == "ADVISORY_RECORD_INVALID"


# ------------------------------------------------------------ envelope parsing


def test_duplicate_keys_rejected_at_every_level():
    template = encode(full_payload())
    cases = [
        template.replace(b'"revision": "r1"', b'"revision": "r1", "revision": "r2"'),
        template.replace(
            b'"start": 0, "end": 16}', b'"start": 0, "end": 16, "end": 17}'
        ),  # record evidence
        template.replace(
            b'"start": 100, "end": 140}', b'"start": 100, "start": 101, "end": 140}'
        ),  # nested observation evidence (depth five)
        template.replace(b'"score": 0.25', b'"score": 0.25, "score": 0.25'),
    ]
    for data in cases:
        assert data != template
        assert rejected(data).code == "ADVISORY_PAYLOAD_DUPLICATE_KEY"


@pytest.mark.parametrize(
    ("data", "code"),
    [
        (b"", "ADVISORY_PAYLOAD_INVALID_JSON"),
        (b"[]", "ADVISORY_PAYLOAD_NOT_OBJECT"),
        (b"null", "ADVISORY_PAYLOAD_NOT_OBJECT"),
        (b'"text"', "ADVISORY_PAYLOAD_NOT_OBJECT"),
        (b"{} {}", "ADVISORY_PAYLOAD_INVALID_JSON"),
        (b'{"schema_version": 1} trailing', "ADVISORY_PAYLOAD_INVALID_JSON"),
        (b"\xef\xbb\xbf{}", "ADVISORY_PAYLOAD_INVALID_JSON"),
        (b'{"a": "\xff"}', "ADVISORY_PAYLOAD_INVALID_UTF8"),
        (b'{"a": "\xc0\xaf"}', "ADVISORY_PAYLOAD_INVALID_UTF8"),
        (b'{"a": "\xed\xa0\x80"}', "ADVISORY_PAYLOAD_INVALID_UTF8"),
        (b"{'schema_version': 1}", "ADVISORY_PAYLOAD_INVALID_JSON"),
        (b'{"schema_version": 1,}', "ADVISORY_PAYLOAD_INVALID_JSON"),
    ],
)
def test_malformed_envelopes_rejected(data, code):
    assert rejected(data).code == code


@pytest.mark.parametrize("payload", ["{}", bytearray(b"{}"), memoryview(b"{}"), None, {}])
def test_only_bytes_accepted(payload):
    assert rejected(payload).code == "ADVISORY_PAYLOAD_NOT_BYTES"


def test_lone_surrogate_escape_rejected():
    payload = base_payload()
    payload["description"] = "half \ud800 pair"
    data = encode(payload)
    assert b"\\ud800" in data
    assert rejected(data).code == "ADVISORY_PAYLOAD_INVALID_UNICODE"


def test_size_limit_is_checked_before_parsing_and_never_truncates():
    data = encode(base_payload())
    padded = data + b" " * (MAX_INPUT_BYTES - len(data))
    assert len(padded) == MAX_INPUT_BYTES
    assert parse_advisory_record(padded) == parse_advisory_record(data)
    assert rejected(padded + b" ").code == "ADVISORY_PAYLOAD_TOO_LARGE"
    assert rejected(b"[" * (MAX_INPUT_BYTES + 1)).code == "ADVISORY_PAYLOAD_TOO_LARGE"


def test_nesting_limit_rejects_deep_structures_without_recursion():
    payload = base_payload()
    payload["unexpected"] = [[[[[[[[1]]]]]]]]
    assert rejected(encode(payload)).code == "ADVISORY_PAYLOAD_TOO_DEEP"
    assert rejected(b"[" * 100_000).code == "ADVISORY_PAYLOAD_TOO_DEEP"
    assert rejected(b'{"a":' * 20_000 + b"1" + b"}" * 20_000).code == "ADVISORY_PAYLOAD_TOO_DEEP"
    brackets = base_payload()
    brackets["description"] = '[[[[[[[[[[{{{{{{{{{{ \\" ]]'
    assert parse(brackets).description == brackets["description"]


def test_collection_count_limits():
    groups = {
        "cve_ids": lambda i: "CVE-2099-0001" if i == 0 else f"CVE-2099-{i:05d}",
        "evidence": lambda i: ref(i, i + 1),
        "cvss": lambda i: dict(full_payload()["cvss"][0], publisher_id=f"scorer-{i}"),
        "epss": lambda i: dict(full_payload()["epss"][0], publisher_id=f"epss-{i}"),
        "exploitation": lambda i: dict(full_payload()["exploitation"][0], publisher_id=f"k-{i}"),
    }
    for key, make in groups.items():
        payload = full_payload()
        payload[key] = [make(i) for i in range(MAX_COLLECTION_ITEMS)]
        assert len(getattr(parse(payload), key)) == MAX_COLLECTION_ITEMS
        payload[key].append(make(MAX_COLLECTION_ITEMS))
        assert rejected(encode(payload)).code == "ADVISORY_RECORD_INVALID"


def test_hostile_inputs_produce_redacted_errors():
    hostile = []
    payload = base_payload()
    payload[CANARY] = CANARY
    hostile.append(encode(payload))
    payload = base_payload()
    payload["record_id"] = CANARY + "\x1b[31m"
    hostile.append(encode(payload))
    payload = base_payload()
    payload["description"] = CANARY + "\u0000"
    hostile.append(encode(payload))
    payload = base_payload()
    payload["schema_version"] = CANARY
    hostile.append(encode(payload))
    hostile.append(b'{"' + CANARY.encode() + b'": 1, "' + CANARY.encode() + b'": 2}')
    hostile.append(CANARY.encode() + b"\xff")
    hostile.append(b'{"x": "' + CANARY.encode() + b'"')
    hostile.append(b'{"x": ' + CANARY.encode() + b"}")
    hostile.append(b'{"x": "' + CANARY.encode() + b'\\ud800"}')
    for data in hostile:
        error = rejected(data)
        assert error.args == (error.code,)
        assert_redacted(error, "\x1b", "\\u0000")


# ------------------------------------------------------- direct construction


def test_constructor_enforces_same_semantics():
    bad_inputs = [
        dict(schema_version=True),
        dict(schema_version=2),
        dict(status="exploited"),
        dict(cve_ids=("cve-2099-0001",)),
        dict(cve_ids=["CVE-2099-0001"]),  # lists are rejected; tuples only
        dict(cve_ids=()),
        dict(cve_ids=tuple(f"CVE-2099-{i:05d}" for i in range(65))),
        dict(evidence=(evidence(), evidence())),
        dict(evidence=tuple(evidence(i, i + 1) for i in range(65))),
        dict(observed_at=datetime(2099, 1, 5, 8)),  # naive
        dict(observed_at="2099-01-05T08:00:00Z"),  # strings only on the wire
        dict(published_at=date(2099, 1, 5)),
        dict(description="tab\tseparated"),
        dict(publisher_id="host.example"),
        dict(unexpected="value"),
    ]
    for overrides in bad_inputs:
        with pytest.raises(ValidationError):
            record(**overrides)
    for kwargs in (
        dict(start=True, end=2),
        dict(start=0, end=2.0),
        dict(start=3, end=3),
        dict(start=-1, end=3),
    ):
        with pytest.raises(ValidationError):
            EvidenceReference(snapshot_sha256=SNAP_A, **kwargs)
    common = dict(
        cve_id="CVE-2099-0001", publisher_id="synthetic-scorer-a", version="3.1", vector="AV:N"
    )
    for score in (True, "7.5", float("nan"), float("inf"), 10.5, -1):
        with pytest.raises(ValidationError):
            CvssObservation(**common, base_score=score, evidence=(evidence(),))
    with pytest.raises(ValidationError):
        CvssObservation(**common, base_score=1.0, evidence=())
    with pytest.raises(ValidationError):
        EpssObservation(
            cve_id="CVE-2099-0001",
            publisher_id="synthetic-epss",
            score=0.1,
            percentile=0.1,
            score_date=datetime(2099, 1, 4, tzinfo=UTC),
            evidence=(evidence(),),
        )
    with pytest.raises(ValidationError):
        EpssObservation(
            cve_id="CVE-2099-0001",
            publisher_id="synthetic-epss",
            score=0.1,
            percentile=0.1,
            score_date="2099-01-04",
            evidence=(evidence(),),
        )


def test_constructed_records_are_immutable_with_validated_empty_defaults():
    built = record()
    assert built.cvss == () and isinstance(built.cve_ids, tuple)
    assert isinstance(built.evidence, tuple)
    with pytest.raises(ValidationError):
        built.status = "withdrawn"
    with pytest.raises(AttributeError):
        built.cve_ids.append("CVE-2099-0002")
    assert hash(built) == hash(record())


def test_constructor_errors_hide_input_values():
    with pytest.raises(ValidationError) as info:
        record(description=CANARY + "\x07")
    assert CANARY not in str(info.value)


def test_tampered_records_fail_serialization_loudly():
    built = record()
    tampered = [
        built.model_copy(update={"cve_ids": ("cve-2099-0001",)}),
        built.model_copy(update={"observed_at": datetime(2099, 1, 1)}),
        built.model_copy(update={"evidence": ()}),
        AdvisoryRecord.model_construct(**dict(built.__dict__, status="exploited")),
    ]
    for item in tampered:
        with pytest.raises(AdvisoryFormatError) as info:
            serialize_advisory_record(item)
        assert info.value.code == "ADVISORY_RECORD_NOT_SERIALIZABLE"
    with pytest.raises(AdvisoryFormatError):
        serialize_advisory_record(full_payload())


def _large_observations(count, refs):
    vector = "CVSS:3.1/" + "X" * 503
    cvss, epss, exploitation = [], [], []
    for i in range(count):
        label = (f"synthetic-publisher-{i:02d}-" + "x" * 64)[:64]
        spans = tuple(evidence(MAX_OFFSET - 2 - j, MAX_OFFSET) for j in range(refs))
        cvss.append(
            CvssObservation(
                cve_id="CVE-2099-0001",
                publisher_id=label,
                version="3.1",
                vector=vector,
                base_score=10,
                evidence=spans,
            )
        )
        epss.append(
            EpssObservation(
                cve_id="CVE-2099-0001",
                publisher_id=label,
                score=0.123456789,
                percentile=0.987654321,
                score_date=date(2099, 1, 4),
                evidence=spans,
            )
        )
        exploitation.append(
            ExploitationObservation(
                cve_id="CVE-2099-0001",
                publisher_id=label,
                status="unknown",
                observation_date=date(2099, 1, 4),
                evidence=spans,
            )
        )
    return tuple(cvss), tuple(epss), tuple(exploitation)


def test_large_constructed_record_round_trips_and_oversize_is_rejected():
    cvss, epss, exploitation = _large_observations(MAX_COLLECTION_ITEMS, 8)
    large = record(description="d" * 4096, cvss=cvss, epss=epss)
    data = serialize_advisory_record(large)
    assert 150_000 < len(data) <= MAX_INPUT_BYTES
    assert parse_advisory_record(data) == large
    with pytest.raises(ValidationError):
        record(description="d" * 4096, cvss=cvss, epss=epss, exploitation=exploitation)


@pytest.mark.parametrize(
    "literal",
    [
        b"-1e-10000",
        b"1e-10000",
        b"1.000000000000000000000000001",
        b"0.999999999999999999999999999",
        b"1e-999999999999999999999999999",
    ],
)
def test_numeric_lexemes_cannot_round_across_admission_boundaries(literal):
    raw = encode(full_payload()).replace(b'"score": 0.25', b'"score": ' + literal)
    error = rejected(raw)
    assert error.code == "ADVISORY_PAYLOAD_NUMBER_PRECISION"
    assert_redacted(error, literal.decode())


@pytest.mark.parametrize("group", ["cvss", "epss", "exploitation"])
def test_observations_bind_to_a_declared_cve(group):
    payload = full_payload()
    payload["cve_ids"].append("CVE-2099-0002")
    payload[group].append(dict(payload[group][0], cve_id="CVE-2099-0002"))
    parsed = parse(payload)
    assert [o.cve_id for o in getattr(parsed, group)] == ["CVE-2099-0001", "CVE-2099-0002"]
    assert parse_advisory_record(serialize_advisory_record(parsed)) == parsed
    payload[group][-1]["cve_id"] = "CVE-2099-0003"
    rejected(encode(payload))
    payload = full_payload()
    del payload[group][0]["cve_id"]
    rejected(encode(payload))


def test_direct_parent_construction_revalidates_nested_instances():
    forged_evidence = EvidenceReference.model_construct(snapshot_sha256="invalid", start=0, end=1)
    with pytest.raises(ValidationError):
        CvssObservation(
            publisher_id="synthetic-scorer-a",
            cve_id="CVE-2099-0001",
            version="3.1",
            vector="AV:N",
            base_score=1.0,
            evidence=(forged_evidence,),
        )
    valid = parse(full_payload())
    forged_score = valid.cvss[0].model_copy(update={"base_score": 11.0})
    with pytest.raises(ValidationError):
        record(cvss=(forged_score,))
    unassociated = valid.cvss[0].model_copy(update={"cve_id": "CVE-2099-0002"})
    with pytest.raises(ValidationError):
        record(cvss=(unassociated,))


def test_unknown_tampered_fields_fail_instead_of_disappearing():
    valid = parse(full_payload())
    bad_root = valid.model_copy(update={CANARY: CANARY})
    bad_nested = valid.model_copy(
        update={"cvss": (valid.cvss[0].model_copy(update={CANARY: CANARY}),)}
    )
    for bad in (bad_root, bad_nested):
        with pytest.raises(AdvisoryFormatError) as info:
            serialize_advisory_record(bad)
        assert info.value.code == "ADVISORY_RECORD_NOT_SERIALIZABLE"
        assert_redacted(info.value)
    assert serialize_advisory_record(valid.model_copy()) == serialize_advisory_record(valid)
