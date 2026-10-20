# ADR-0058: Evidence-verified KEV advisory projection

Status: ACCEPTED for the bounded operator read. Date: 2026-10-20.
Exact revision acceptance belongs to installed/native CI evidence.

## Context and decision criteria

The KEV collector preserves immutable documents and raw catalogue bytes, while
AdvisoryRecord is an offline envelope whose references alone prove no evidence
exists. Operators need a typed, evidence-verified observation from those stored
records without introducing unqualified applicability, current membership or
publisher-authentication claims. Reader authority, lifecycle visibility, bounded
parsing and original evidence must remain intact.

## Alternatives and decision

- No change preserves two disconnected contracts and requires ad hoc conversion.
- Persist domain tables now: useful for broader domain queries, but introduces
  migration, grants, head/retraction, purge and checkpoint contracts before those
  workflows are designed.
- Project directly from document JSON: smaller, but an extractor label and a
  digest alone do not establish the record corresponds to the raw catalogue.
- **Selected:** an explicit read-only operator command revalidates reader authority,
  verifies CAS bytes and the database body, reparses the linked raw catalogue using
  the existing bounded isolated parser, and requires exact source-scoped external
  identity, title, normalized text and absent publication instant. It then returns
  a digest-bound projection receipt. No domain state is written.

The caller supplies an explicit bounded publisher label. The receipt binds it to
source_id and declares that it is not authenticated. A configured KEV-compatible
origin is not automatically CISA. Source IDs are not truncated into the envelope's
shorter label field. The envelope revision is the normalized text SHA-256;
observed_at is the stored snapshot acquisition instant, not the projection time or
latest successful poll. Unchanged-head replay retains that earlier observation.

The exploitation observation means the attributed KEV-format catalogue reports
exploitation. It does not establish local exposure. Its evidence is the complete
normalized-record UTF-8 byte span, with the coordinate space labelled explicitly;
these are not raw-catalogue offsets. Raw bytes are separately digest-bound and
reparsed. Advisory status stays unknown. Publication, modification and exploitation
dates remain absent: dateAdded is not an exploitation date and dateReleased is not
an individual advisory publication instant. dueDate/requiredAction remain in the
preserved source evidence, not a universal deadline or an executable instruction.

The description must satisfy the existing envelope's 4096-code-point/no-control
contract. A valid but incompatible KEV description refuses projection with a fixed
error; acquisition remains valid. No silent truncation, normalization or omitted
qualification is introduced. Missing CVSS/EPSS remain empty observations.

## Bounds, impact and rollback

One document is selected. CAS reads retain the 20 MiB per-object ceiling; the
reparser admits at most 10 MiB input, 10000 records and 16 MiB output, with its
existing resource limits and at most eight seconds of child execution. SQL/store
admission limits remain independent; this is not a whole-command deadline.
The returned JSON receipt is capped at 270336 UTF-8 bytes. No bulk domain query,
model/network dispatch, arbitrary selector or new MCP tool is introduced.

Database lifecycle admission is acquired before cooperative store admission and
held through verified reads, parsing and the final visibility check. The latter
also checks statement-time expiry. Holds preserve storage but do not expand read
visibility. Historical visible revisions may be projected; current catalogue
membership and source freshness are explicitly not established/evaluated. An
empty later catalogue does not withdraw an earlier observation.

Core schema 12, retrieval profile 5 and checkpoint format 2 stay unchanged. No
published migration, grants or stored evidence changes. A binary revert removes
the command; already returned receipts remain dated artifacts of their producing
revision and cannot be relabelled as verified under another projection contract.
The receipt digest establishes bytes, not a signature, independent review,
publisher authentication, source truth or target applicability. Domain persistence,
retractions, wider upstream formats, applicability and full E31/E32 stay open.

## Verification and traceability

R36/R37 and U19/C19 constrain attributed evidence and missing dates/scores.
SC1/SC2/SC3/SC4/SC5/SC6 cover bounded disclosure, honest evidence states, reader
authority, immutable provenance, revision-bound validation and bounded parsing. Focused regressions distinguish
Unicode byte coordinates, incompatible descriptions, invalid publisher labels,
reader/write-store admission, wrong extractor/raw record/external identity,
CAS/database corruption, historical revisions, retirement, held expiry and expiry
during projection. The installed CLI uses actual reader SQL, CAS and the isolated
parser. The existing native TLS KEV acquisition test continues into projection.
These are bounded E31/E32 refinements, not complete domain acceptance. Passing
runtime claims require revision-bound execution results, not this design record.
