# ADR-0048: Add an explicit KEV catalogue format adapter

Status: Accepted

## Context and criteria

The bounded JSON-page profile cannot read a qualified upstream catalogue without
a transformation service. A first real format adapter must have an inspectable
publisher contract, reviewable reuse terms, inert links, immutable provenance,
bounded execution and replay tests. It must not imply local exposure or silently
import the prototype's source catalogue. The reviewed baseline and exact source
hashes are in the [KEV operator contract](../kev-acquisition.md).

## Alternatives

| Option | Consequence |
| --- | --- |
| Keep only the generic profile | No added code, but every upstream format needs another service |
| Start with a commercial intelligence SDK | Contract and subscription rights not verified; incompatible with current shared consumers |
| Infer every KEV entry into the normalized advisory envelope | Introduces domain persistence/date/observation semantics before their implementation and evidence exist |
| Explicit bounded KEV document mapping | Reuses transport, parser isolation, CAS, collector transactions and supervised units without broadening execution authority |
| Accept unknown properties automatically | Tolerates upstream drift but silently expands unreviewed field semantics and disclosure |

## Decision and consequences

Add `cisa-kev/1` to the private API configuration selector and fixed-module parser
dispatch. Never content-sniff a provider, choose a URL from response data or bundle
an operational endpoint. Preserve existing generic behavior and 1000-item limit;
KEV permits at most 10000 entries within unchanged byte/result/process deadlines.
This accommodates catalogues larger than a generic page without introducing
partial-snapshot ingestion or automatic chunked requests.

Validate the complete envelope, exact count, required/known optional fields,
date precision, identities and bounded values before admission. Reject unknown
fields even though the upstream schema allows additional properties. This
deliberately narrower compatibility contract makes drift visible; it is not a
claim of accepting every schema-valid upstream extension.

Map each entry to canonical JSON text and a CVE-prefixed title. Keep release
metadata only in the raw catalogue, so a metadata change does not churn every
document/outbox. Leave publication time unset: a date-added field is not a precise
publication instant. Preserve ransomware, forensic-triage and action fields as
source assertions. Do not follow notes, classify local applicability, infer
withdrawal from absence or claim that due dates bind this operator. Reuse
observed-current replay semantics; monotonic revision/rollback detection remains
open. Source authenticity still depends on privately configured provenance.

No new dependency, migration, SQL privilege, MCP tool, model dispatch or cloud
route. Rights declarations and existing consumers remain unchanged; the reviewed
database's CC0 terms do not clear third-party linked material. Other providers,
restricted rights domains, paid accounting and normalized advisory observations
remain unfinished work.

## Verification and rollback

Synthetic parser cases discriminate malformed/count/identity/schema drift, new
optional fields, invalid dates, unknown enums, duplicate JSON keys and size limits.
Installed TLS/SQL cases reconcile raw bytes, heads, immutable revisions and jobs,
metadata-only replay, empty-catalogue absence, atomic rejection, a 1001-entry
catalogue and reset of old generic continuation. The disconnected two-LTS service
fixture uses the real collector, worker and reader with KEV-format assertions;
it does not use operational provider content. U1/U4/U8/U10/U12 remain allocated;
E31/E32/E40 are not closed by document acquisition.

Stop the API timer/service and reconcile its control group before changing
configuration or reverting binaries. Disable the source or restore its previous
compatible profile deliberately; a previous binary refuses this new selector.
Accepted schema-11 data remains readable; no reverse migration is needed.
Preserve history and private checkpoints. Revoke mirror credentials independently
if used. No operational source is enabled by this change.
