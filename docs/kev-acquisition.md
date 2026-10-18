# Bounded KEV catalogue acquisition

`cisa-kev/1` is an explicitly selected format adapter through
[API acquisition](api-acquisition.md) and its opt-in service. It preserves source
assertions as evidence-backed documents; it does not populate the offline
advisory envelope, match local assets or establish legal obligations.

## Qualification and contract baseline

Reviewed on 2026-10-18: the publisher's
[schema](https://github.com/cisagov/kev-data/blob/6a392940c663b52271fa4e6aa7b39995b18c9a71/known_exploited_vulnerabilities_schema.json),
[licence](https://github.com/cisagov/kev-data/blob/6a392940c663b52271fa4e6aa7b39995b18c9a71/LICENSE)
and repository guidance at upstream commit
`6a392940c663b52271fa4e6aa7b39995b18c9a71`. The schema SHA-256 was
`0d5865c98694c5bfba2c78a26caf814f406b3fce8bfb81bef79e99c7f288b0e7`;
the licence SHA-256 was
`8dfcf2d0cba33bede386eb470daf2ac08caf6540fc2516baab10dd546f90938a`.
No upstream entries are copied into tests. The licence declares CC0 for this
database, excludes implied endorsement and leaves linked third-party material
under its own terms. The adapter does not fetch those links.

This qualification establishes an inspected format/licence baseline, not
cryptographic publisher authentication or perpetual compatibility. The configured
HTTPS origin remains operator authority. A compatible response from another
origin does not thereby become an authenticated CISA statement. Review source
provenance, current terms, request billing and intended downstream uses before
privately configuring a source. The adapter name selects syntax, not permission.

## Configuration and mapping

Use the existing private `ApiSource` object with `adapter: cisa-kev/1`, an explicit
HTTPS endpoint and `enabled: false` until operator adoption. No endpoint is
bundled or discovered. For an unauthenticated public source use
`auth: {"kind": "none"}`; checked credential references remain available for an
explicitly authorized mirror. Keep the existing rights/unmetered declarations.
Use a dedicated source ID, not a shared identity for unrelated catalogues.

The envelope requires `catalogVersion`, `dateReleased`, integer `count` and
`vulnerabilities`; `title` is optional, matching its presence in publisher data
despite its omission from the reviewed schema properties. Counts must exactly
match the array. Required entry fields follow the reviewed schema. Supported
optional fields are `notes`, `cwes`, `knownRansomwareCampaignUse` and
`forensicTriage`. Unknown fields reject the complete response pending review.
Optional fields remain absent when absent; no default assertion is invented.

| Input | Stored interpretation |
| --- | --- |
| `cveID` | Source-scoped external identity; uppercase ASCII CVE syntax, unique within this response |
| `vulnerabilityName` | Title prefixed with the CVE identity |
| Entire admitted record | Deterministic sorted JSON text, retaining exact string values and optional fields |
| `dateAdded`, `dueDate` | Valid ISO calendar dates retained as dates in text; `published_at` stays null |
| Catalogue metadata and all original bytes | Linked immutable raw object and per-run digest; not injected into every record's text identity |
| Ransomware/triage/action fields | Attributed source statements, never executable actions, local exposure findings or an independent compliance determination |

The publisher schema permits unconstrained strings and additional fields. This
profile deliberately narrows admission: no NUL in strings, nonempty strings (notes may be empty),
name at most 1900 characters, other entry strings at most 100000, at most 100
bounded ASCII CWE identifiers, ransomware `Known`/`Unknown`, triage `Yes`/`No`,
and no unknown keys. Catalogue version is at most 128 characters and optional
title at most 2000. Every accepted CVE/CWE is syntax checked, not registry checked.
Strict JSON duplicate-key/depth/UTF-8 rules and isolated parser limits also apply.

## Bounds, replay and failure

One response is terminal: no pagination parameter or provider-selected URL.
The body cap remains 10 MiB, parser output 16 MiB and document text 1000000
characters. The adapter permits at most 10000 entries; the generic page cap
remains 1000. These are ceilings, not tested sustained capacity promises. Deadline
or storage/SQL failure rolls back the entire response; durable unreferenced
objects may require reviewed orphan GC. Larger catalogues require a separately
reviewed design rather than silent truncation or splitting.

Existing source locking, due/backoff, credential custody and lifecycle suppression
apply. Raw response, accepted documents, outbox and success state use the existing
transaction boundary. Unchanged records reuse heads even when catalogue metadata
changes; revisions preserve prior immutable versions. Absence, including an empty
catalogue, never deletes or withdraws previous entries. There is no monotonic
catalogue-version enforcement: an explicitly observed older response can select
an older record representation, following existing collector replay semantics.

Changing the adapter changes the configuration identity and clears private
continuation/freshness before fetching. Unknown fields, malformed entries,
count mismatch or duplicate identities reject the whole catalogue with fixed
diagnostics; no partial record list is accepted. Reconcile drift against the
publisher contract, preserve accepted history, and change/version the adapter
through review. Do not drop unknown fields to obtain a successful tick.

`tests/test_kev.py` and native TLS/SQL acquisition cases cover mapping, bounds,
revisions, metadata-only changes, absence, malformed responses and adapter changes.
The guarded service harness additionally exercises synthetic KEV collection,
replay, schema refusal, worker and reader units. The [two-LTS service receipt](testing/kev-service-2026-10-18.json) records
passing execution at its named source and wheel. These fixtures do not prove operational provider access,
production catalogue capacity, local applicability or complete vulnerability
intelligence. See [ADR-0048](adr/0048-kev-catalogue-adapter.md).
