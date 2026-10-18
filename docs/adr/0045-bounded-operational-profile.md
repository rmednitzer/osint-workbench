# ADR-0045: Bound the first supervised operational profile

Status: Accepted

## Context and decision criteria

The collector has disposable service acceptance, but collection alone does not
prove that accepted work is processed, observable or recoverable. The first
profile must remain useful without models or provider credentials. Optional
retrieval, enrichment, cloud and domain scope remains on the programme roadmap.
Useful pretrained quality, recovery tolerances and target-host capacity have
not been accepted. No default threshold can establish those decisions.

The audit also identified reachable MCP response-size failures, special-token
interpretation of source text and incomplete reader-grant checks. Adding
supervision without fixing these boundaries would preserve avoidable failures.

## Alternatives

| Option | Consequence |
| --- | --- |
| Keep only the collector timer | Accepted jobs need manual processing and failures lack a bounded readiness signal |
| Add a general dispatcher with generation and cloud credentials | Expands authority and chargeable effects before workflow/quality acceptance |
| Run every service under one OS account | Avoids evidence sharing work but collapses host identity boundaries |
| Periodically chmod the private store | Creates race-prone implicit disclosure of existing content |
| Automate checkpoints using the recovery owner | Gives a recurring task broad database authority; does not solve independent policy custody |
| Bounded chunk worker, separate read-only health, explicit storage sharing | Adds a testable path while keeping models, recovery authority and notifications independently controlled |

## Decision and interfaces

Add `work --max-jobs` as one bounded tick over `document.accepted`, preserving
lease/fence and per-job commit boundaries. Aggregate journals contain counts,
not job payloads or source identifiers. Failed jobs make the tick fail; other
independent jobs can still complete within its cap. Backend failure stops the
tick. Unsupported downstream kinds remain queued and visible.

Add `health` with mandatory operator-provided source-age, pending-job and
failed-job thresholds. Its fixed aggregate facts/reasons exclude source IDs,
timestamps, URLs and exception text. Unconfigured, stale, failed, malformed or
unavailable state fails readiness. An optional retrieval gate checks compatible
active-generation metadata, not model usefulness, corpus coverage or recall.
Health is a sample over separate transactions, not an atomic service invariant.
Units expose systemd failure state and journal output; notification destinations
and external monitoring require separate configuration.

Keep private evidence creation as the default. An explicitly selected numeric
read-group profile requires a pre-provisioned, owner-controlled store and checks
anchored directory/object ownership, group and modes, refusing POSIX ACLs that
could grant additional named-principal access. Creation requires the selected
group as effective primary group; new directories/files use 0750/0640 without
requesting setgid chmod under the collector sandbox. Never repair or disclose an existing
private tree implicitly. Worker and health accounts have no collector credentials
or writable evidence mount. The reader's SQL surface is an exact relation/column
allowlist, with no reachable alternate application role.

Page MCP results against the actual 65,536-byte UTF-8 serialization budget.
Preserve complete records, original evidence identities and explicit continuation
scope; fail an individually unrepresentable record instead of skipping it. A
briefing page retains the full product identity and explicitly labels its partial
projection. This changes pagination/output contracts, requiring client adaptation.
The seven read tools remain the entire MCP surface.

Tokenize trusted generator prefix/suffix separately from literal source-bearing
text and submit the exact validated token IDs for completion. Support only the
verified automatic-prefix envelope; reject unsupported tokenizer transformations
instead of guessing model-specific chat semantics. This prevents source spellings
from becoming tokenizer control IDs; it does not establish resistance to semantic
prompt injection, entailment or quality.

## Verification and traceability

R01/R05–R08/R14/R19/R21/R49/R50 allocate to E01/E07/E08/E13/E14/E45/E46.
Extend STPA with C103–C107. Test byte-budget continuation, literal special-token
negative controls, extra reader grants, bounded ticks, health denial states,
actual service account permissions and collection/worker/checkpoint/current-policy
restore across fresh processes. Native PostgreSQL, tokenizer and systemd outcomes
must be tied to the candidate source/artifact. Local syntax/unit passes cannot
substitute for these integrations.

## Impact and rollback

No database migration, dependency update, model adoption or provider dispatch.
Core 10, retrieval 4 and checkpoint format 2 remain unchanged. New units remain
disabled until explicit installation. No operational host is changed by this ADR.

Stop the new timers before code rollback. Accepted jobs remain durable; old code
must retain the matching database/evidence pair. Shared files remain disclosed to
their explicitly selected group after code rollback: revocation requires stopping
consumers and a separately reviewed custody change. Private restore initially
creates private evidence and requires deliberate provisioning before shared use.
MCP clients must adopt the documented pagination contract or pin a compatible
version. The generator identity now includes the tokenization policy version.
Existing enrichment jobs retain their old kind and remain unclaimed by the new
generator; explicit enqueue creates a distinct identity-bound job. Unsupported
tokenizer envelopes fail capability validation. Operator disposition is required
for old queued work; no job is silently reset or migrated.

## Remaining adoption gates

Representative source and assistant-client acceptance, licensed useful local
models, independent review authority, resource/load targets, sustained supervision,
independent current-policy custody and operator-approved recovery point/time
remain open. A composed logical recovery fixture does not prove automated backup,
off-host durability, full-host recovery or physical erasure.
