# Offline advisory record envelope (foundation only)

Status: bounded foundation for the vulnerability profile. It does **not** complete
the vulnerability profile or any of its acceptance scenarios. See `STATUS.md` for
authoritative implemented/verified scope; this document is not an execution receipt.

Module: `osint_workbench.advisory`. Public API:

- `AdvisoryRecord` (plus `EvidenceReference`, `CvssObservation`, `EpssObservation`,
  `ExploitationObservation`, `AdvisoryFormatError`)
- `parse_advisory_record(payload: bytes) -> AdvisoryRecord`
- `serialize_advisory_record(record: AdvisoryRecord) -> bytes`

No CLI, MCP, database, migration or dependency changes accompany this module.

## What is implemented

A strict, versioned (`schema_version: 1`) normalized envelope for one publisher's
vulnerability record, together with independently attributed CVSS, EPSS and
exploitation observations. All models are frozen Pydantic v2 models with
`extra="forbid"` and `strict=True`; collections are tuples.

It is **not** a CVE JSON 5, OSV, CSAF or vendor parser, an inventory/SBOM matcher,
an exposure or applicability detector, a prioritizer, a CVSS calculator or a STIX
implementation. Producing an envelope from an upstream format is future adapter work.

### Record fields

| Field | Contract |
| --- | --- |
| `publisher_id` | Opaque configured label `[A-Za-z0-9][A-Za-z0-9_-]{0,63}`. Case-sensitive; dots are disallowed. The label confers no authority and its syntax does not establish anonymity. |
| `record_id` | Publisher-scoped id `[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}`. Identity is the pair `(publisher_id, record_id)` (`record.source_key`). |
| `revision` | Opaque string `[A-Za-z0-9][A-Za-z0-9._:+-]{0,63}`; no ordering is implied. |
| `status` | `published`, `rejected`, `withdrawn` or `unknown`, exactly as declared. Never inferred from description text, timestamps or absence. |
| `description` | Optional, 1–4096 code points, no `Cc` (C0, DEL, C1 — including newline and tab) or surrogate code points. Not authoritative text: line structure lives in the preserved snapshot. |
| `observed_at` | Required UTC-aware instant at which the producer observed the record. |
| `published_at`, `modified_at` | Each optional and independent; absent stays absent. `modified_at < published_at` is rejected when both exist; equality is allowed. |
| `cve_ids` | 1–64 ids matching `CVE-[0-9]{4}-[0-9]{4,19}` (ASCII digits, uppercase prefix). First-seen order is preserved; duplicates and lowercase/whitespace variants are rejected, never normalized. No registry check is made. |
| `evidence` | 1–64 unique `EvidenceReference` objects. |
| `cvss`, `epss`, `exploitation` | Each 0–64 observations; default empty tuple. |

### Evidence references and the byte-span boundary

`{"snapshot_sha256": <64 lowercase hex>, "start": <int>, "end": <int>}` denotes the
half-open span `[start, end)` measured in **UTF-8 bytes** of an externally preserved
snapshot identified by its SHA-256. `0 <= start < end <= 2**63-1`. Duplicates within
one list are rejected; the same span may be cited by different observations.

Validation is of reference *shape only*. The module opens no file, makes no network
call, and does not claim the snapshot exists, that the span decodes on a character
boundary, or that it supports any statement.

### Attributed observations

Each observation carries its own `publisher_id`, required `cve_id` and 1–8 unique evidence references.
The observation CVE must be present in the enclosing record's `cve_ids`; scores
and exploitation claims never implicitly apply to every CVE in a multi-CVE record.
Record-level evidence never stands in for observation evidence.

- **CVSS**: `version` ∈ `2.0`, `3.0`, `3.1`, `4.0`; raw `vector` (1–512 printable
  ASCII, no spaces, grammar not validated); finite `base_score` in [0, 10]. Scores are
  never calculated and vector/score/version consistency is never claimed.
- **EPSS**: finite `score` and `percentile` in [0, 1] and a required `score_date`.
  Zero is a valid value; an absent observation is not zero.
- **Exploitation**: `status` is `reported` or `unknown`, optional `observation_date`.
  There is deliberately no negative status. Absence of observations, or `unknown`,
  never means "not exploited".

Multiple observations, including contradictory ones from the same or different
publishers, are retained as separate items in input order. Nothing chooses a winner,
overwrites, merges publisher identities or derives operational action, exposure,
applicability or priority from any score or catalogue presence. Only an exactly
identical repeated observation is rejected (as an error, not silently dropped).

## Wire format

Synthetic example (pretty-printed here; canonical output is a single line):

```json
{
  "cve_ids": ["CVE-2099-0001"],
  "cvss": [
    {
      "base_score": 9.8,
      "cve_id": "CVE-2099-0001",
      "evidence": [{"end": 140, "snapshot_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "start": 100}],
      "publisher_id": "synthetic-scorer-a",
      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "version": "3.1"
    }
  ],
  "description": "Synthetic overflow in an invented component.",
  "epss": [],
  "evidence": [{"end": 16, "snapshot_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "start": 0}],
  "exploitation": [
    {
      "evidence": [{"end": 24, "snapshot_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "start": 8}],
      "publisher_id": "synthetic-catalogue",
      "cve_id": "CVE-2099-0001",
      "status": "unknown"
    }
  ],
  "observed_at": "2099-01-05T08:00:00Z",
  "publisher_id": "synthetic-cna",
  "published_at": "2099-01-02T00:00:00Z",
  "record_id": "SYN-ADV-2099-0001",
  "revision": "r1",
  "schema_version": 1,
  "status": "published"
}
```

### Canonical serialization

`serialize_advisory_record` emits UTF-8 JSON with sorted keys, `,`/`:` separators,
no ASCII escaping and no non-finite numbers. Absent optional fields are omitted;
empty observation groups are emitted as `[]` (meaning "none carried", not a negative
finding). Output is independent of input key order and whitespace. Before returning,
nested model instances are revalidated and the bytes are re-parsed and re-encoded.
Invalid fields, including injected unknown fields, introduced behind validation
(for example via `model_copy(update=...)` or `model_construct`) raise
`AdvisoryFormatError("ADVISORY_RECORD_NOT_SERIALIZABLE")` instead of producing output.

### Timezone contract

Wire timestamps must match `YYYY-MM-DDTHH:MM:SS[.f{1,6}](Z|±HH:MM)`; naive values,
space separators, lowercase `z`, more than microsecond precision, leap seconds and
compact offsets are rejected. Every instant is normalized to UTC; the original offset
is **not** preserved. Output uses `Z`, with fractional seconds only when non-zero
(six digits). Instants that cannot be represented in UTC are rejected. Dates are
`YYYY-MM-DD` and must be real calendar dates. Direct construction requires aware
`datetime` / exact `date` instances (strings are accepted only on the JSON wire).

### Number contract

Numbers are IEEE-754 binary64. Lexical form is not preserved: `7.50` and `7.5` both
become `7.5`, an integer `7` in a float field becomes `7.0`, and `-0.0` normalizes to
`0.0`. Output uses Python's shortest round-trip representation, so serialize → parse
is exact for every accepted value. A float literal must have the same exact decimal
value as Python's shortest representation of the resulting binary64 value; otherwise
`ADVISORY_PAYLOAD_NUMBER_PRECISION` rejects it. This conservative lexical rule rejects
underflow and excessive decimal precision before either can cross score bounds.
It does not claim arbitrary-precision arithmetic or preserve original number spelling.
Float literals longer than 32 characters and
integer literals longer than 19 digits are rejected rather than rounded. Booleans,
numeric strings, `NaN`, `Infinity` and overflowing literals (`1e400`) are rejected.
Offsets must be JSON integers (`1.0` is rejected).

## Parsing, limits and errors

`parse_advisory_record` performs, in order and before any model construction:

1. type check (`bytes` only) and size check (≤ 262144 bytes; never truncated);
2. strict UTF-8 decoding;
3. a string-aware nesting scan (≤ 8 levels of objects/arrays; prevents recursion);
4. `json.loads` with duplicate-key rejection at every level, rejection of
   `NaN`/`Infinity` constants and of over-long or non-finite number literals;
5. single top-level object, no lone surrogate escapes, `schema_version` exactly the
   integer `1`;
6. strict Pydantic validation (unknown keys rejected at every level).

| Limit | Value |
| --- | --- |
| Input bytes | 262144 |
| Nesting depth | 8 |
| `cve_ids`, `evidence`, `cvss`, `epss`, `exploitation` | 64 each |
| Evidence per observation | 8 |
| `description` | 4096 code points |
| `publisher_id` / `revision` / `record_id` | 64 / 64 / 128 |
| CVSS vector | 512 |
| Offsets | 0 … 2**63-1 |

Because worst-case combinations of these limits could exceed the input limit,
`AdvisoryRecord` also rejects records whose canonical encoding exceeds 262144 bytes,
so every successfully constructed record can be serialized and parsed.

All parser failures raise `AdvisoryFormatError` (a `ValueError`) whose `str()`,
`args` and `code` are one fixed code: `ADVISORY_PAYLOAD_NOT_BYTES`,
`ADVISORY_PAYLOAD_TOO_LARGE`, `ADVISORY_PAYLOAD_INVALID_UTF8`,
`ADVISORY_PAYLOAD_TOO_DEEP`, `ADVISORY_PAYLOAD_INVALID_JSON`,
`ADVISORY_PAYLOAD_DUPLICATE_KEY`, `ADVISORY_PAYLOAD_NONFINITE_NUMBER`,
`ADVISORY_PAYLOAD_NUMBER_TOO_LONG`, `ADVISORY_PAYLOAD_NUMBER_PRECISION`,
`ADVISORY_PAYLOAD_INVALID_UNICODE`,
`ADVISORY_PAYLOAD_NOT_OBJECT`, `ADVISORY_SCHEMA_VERSION_UNSUPPORTED`,
`ADVISORY_RECORD_INVALID`. Errors are raised outside exception handlers, so no
`__cause__`/`__context__` chain carries raw input, keys or field values.

**Redaction scope.** The redaction guarantee applies to `parse_advisory_record` and
`serialize_advisory_record` errors only. Direct construction raises Pydantic
`ValidationError`; models set `hide_input_in_errors=True`, but the rendered error still
includes field locations (which may contain unknown key names) and is not a supported
redacted channel. Calling `AdvisoryRecord.model_validate_json` directly bypasses the
duplicate-key, depth and size checks; use `parse_advisory_record` for untrusted input.
Direct construction accepts model instances and tuples (lists are rejected in strict
mode) and enforces the same type, range, count and cross-field rules.

## Remaining work (not implemented here)

- Upstream adapters (CVE records, vendor/OS advisories, KEV, EPSS, OSV) with
  configured, external endpoint lists; acquisition, snapshot preservation and
  schema-version tracking for those sources.
- Database storage, migrations, revision/version heads, retraction and
  rejected-record lifecycle, feed-delay handling and CLI/MCP read surfaces.
- Verification that evidence spans exist in preserved snapshots and decode correctly.
- Affected product/range/configuration expressions, ecosystem-specific version
  ordering, operator inventory/SBOM matching with uncertainty, and the separation of
  presence, applicability, exposure, exploitation evidence and remediation policy.
- Interoperable JSON/STIX export with real schema and semantic tests.
- Full domain acceptance. The revision-bound verification receipt records which
  installed-wheel checks have actually executed.
