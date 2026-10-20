# KEV advisory projection

`osint-workbench advisory DOCUMENT_ID --publisher-id declared-publisher` reads one
stored visible KEV revision and prints a JSON receipt containing a canonical
AdvisoryRecord. Configure `OW_READER_DSN` and `OW_EVIDENCE_ROOT` privately. This
uses the exact reader role and a read-only evidence store; it does not collect,
write a domain record, load models or change the seven MCP reads.

The operator chooses the publisher label explicitly: 1–64 ASCII letters, digits,
underscores or hyphens, beginning with a letter/digit. The receipt binds that label
to the stored source_id. Neither the label nor the `cisa-kev/1` format proves
publisher identity or CISA authenticity. Review origin/terms separately before
source adoption. Arbitrary document text can contain sensitive information; this
operator read is not an anonymized consumer export or permission to publish it.

## Evidence and semantics

The command requires extractor `cisa-kev/1`, verifies raw and normalized CAS
objects against their digests, matches normalized bytes to the database body, and
reparses the raw catalogue using the acquisition parser. The selected record must
match the stored source-scoped external identity, title, complete normalized text
and absent publication instant. The receipt names the raw digest and stored
snapshot/document/source identities.

Advisory evidence references use `normalized_record_utf8_bytes`: the full preserved
normalized record, from byte zero to its UTF-8 byte length. They are not offsets
in the raw catalogue or code-point offsets used by document chunks. The raw bytes
remain independently linked and verified. Whole-record evidence locates the
attributed catalogue assertion; it does not verify its truth.

The envelope revision is the normalized text SHA-256. observed_at is the original
stored snapshot acquisition time. It is not projection time or last poll time;
unchanged-head replay can keep an older observation. The record's status is
unknown because KEV does not specify advisory publication/withdrawal status.
Exploitation status is reported, attributed to the selected publisher label under
the KEV mapping. No publication, modification or exploitation date is invented
from dateAdded/dateReleased. No CVSS/EPSS is invented. dueDate is preserved only
in the source evidence, not converted to a universal remediation deadline.

Historical visible revisions are admitted and return their own immutable evidence.
`current_catalogue_membership: not_established`, `source_freshness: not_evaluated`
and `applicability: not_evaluated` prevent the projection being mistaken for a
current exposure assessment. Catalogue absence does not retract old records.

The receipt is `{sha256, payload}`. Its digest hashes the UTF-8 JSON encoding of
payload with sorted keys, no ASCII escaping, and comma/colon separators without
whitespace. The projection version is `kev-advisory/1`. The digest binds bytes,
including caller attribution; it is not a signature or separate reviewer approval.

## Refusal and recovery

An incompatible description (over 4096 code points or containing control
characters) returns `KEV_PROJECTION_RECORD_INCOMPATIBLE`. Collection admission is
unchanged; the original valid KEV record remains available. Do not truncate or
rewrite accepted evidence to force projection. A future mapping change requires
a versioned contract and reviewed tests.

A mismatched extractor, source identity, external key or raw-to-normalized mapping
returns `KEV_PROJECTION_PROVENANCE_MISMATCH`. Corrupt or missing CAS evidence uses
the existing fixed evidence errors. Invalid publisher labels return
`INVALID_ADVISORY_PUBLISHER`. An absent, expired or retired document returns
`DOCUMENT_NOT_FOUND`; holds do not confer serving permission. Parser timeouts and
malformed catalogue refusals preserve the existing fixed API parser errors.
No raw source text, credentials or database configuration appears in diagnostics.

Read admission holds the lifecycle lock across the operation and checks expiry
again before returning. Cooperative evidence-store admission excludes GC while
objects are read. Input/parser/SQL/admission limits are retained; final JSON is
bounded to 270336 UTF-8 bytes. A large receipt fails, rather than truncating.
There is no whole-command deadline beyond the separate bounded operations.

Reconcile missing/corrupt evidence through the existing recovery process. Re-run a
read after a corrected configuration or separately reviewed recovery; do not
modify immutable history. There is no queued work, retry reset or uncertain
inference marker to clear. Binary rollback removes this read path without a
schema or checkpoint conversion. See [ADR-0058](adr/0058-kev-advisory-projection.md).

Full vulnerability persistence, retractions, upstream coverage, local inventory
matching and E31/E32 acceptance remain open. Installed/native tests establish
only their named synthetic execution and authority boundaries.
