> Target specification. See STATUS.md for implemented and verified scope.

# Complete requirements and traceability register

Revision 2. R01-R58 are proposed mandatory requirements for their enabled supported profiles. Core-only installation is supported, but all planned profile implementations must be accounted for before full programme completion. No requirement is proved by this table. Implemented subsets have revision-bound evidence in [STATUS](../../STATUS.md) and the named receipts; full target acceptance remains open. Scenario-level NOT RUN markers describe incomplete full scenarios, not an absence of application testing.

Need/source: user request for the complete generalized setup, critical redesign rather than prototype copying, secure coding, STPA/ADRs, full integration testing and no private-data/source-URL disclosure. Owner: maintainer accepts scope/targets, implementer supplies evidence. SC identifiers are derived constraints in STPA, not external legal mandates. Verification environments and oracles are in the E01-E51 matrix; E01-E18 supersede earlier E01-E18 descriptions as amended for full profiles.

| ID | Required observable behaviour | Constraint | Allocation | Verification |
| --- | --- | --- | --- | --- |
| R01 | A clean Linux installation shall run the synthetic collection-to-MCP workflow without the original environment, a GPU, cloud account or operational source config. | SC6/C1 | ADR-0001/0007/0009 | E01,14 |
| R02 | The release shall contain zero operational source URLs or private source catalogues in source, history, fixtures and built artifacts. Empty config shall initiate no fetches. | SC1/C1,C2 | ADR-0001/0004 | E01,09,18 |
| R03 | Replaying or concurrently ingesting the same source/raw-byte version shall create one accepted snapshot per source version, retaining changed versions. | SC4/C6 | ADR-0002 | E02,06 |
| R04 | Each accepted document shall reference immutable raw and normalized hashes, extraction version and acquisition time; mismatch shall block verified evidence reads. | SC2,SC4/C6,C9 | ADR-0002/0006 | E03,06,13 |
| R05 | The database reader shall be unable to INSERT/UPDATE/DELETE/DDL or invoke mutating functions; app identities shall not own schemas or use superuser credentials. | SC3/C8 | ADR-0002/0003 | E08 |
| R06 | The MCP adapter shall negotiate with the selected real SDK client and expose only documented enabled-profile read tools with schema-valid bounded responses. | SC3/C8 | ADR-0003 | E07,08 |
| R07 | MCP execution shall have no collector/migration credentials, no writable evidence mount and no outbound acquisition route. No listener shall be enabled by default. | SC1,SC3/C8 | ADR-0003/0009 | E08,09,14 |
| R08 | All read inputs shall reject unknown/extra fields, invalid IDs, path selectors and unsupported tools; invalid requests shall not cause database or file mutation. | SC3/C8 | ADR-0003 | E07,08,12 |
| R09 | The fetch path shall reject disallowed schemes, credentials in URLs and non-public destinations at every hop, with pinned resolution and bounded wire/decoded bytes and total deadline. | SC3,SC6/C4,C7 | ADR-0004 | E09,10,12 |
| R10 | Search shall preserve deterministic lexical/exact matching and label vector/hybrid strategy, corpus generation and degradation explicitly. | SC2/C9,C10 | ADR-0005 | E04,11 |
| R11 | All interfaces shall distinguish acquisition, extraction, integrity and freshness; no ranking score or hash shall imply factual verification. | SC2/C9 | ADR-0006 | E03,05,11 |
| R12 | Unknown publication timestamps shall remain null/unknown and source-specific freshness shall derive from last successful acquisition under configured policy. | SC2/C5,C10 | ADR-0006 | E05,11 |
| R13 | A release shall have all mandatory E2E scenarios executed against installed artifacts and real disposable PostgreSQL; unexpected skips shall fail acceptance. | SC5/C12 | ADR-0007 | E01..18 |
| R14 | A fresh installation shall restore the accepted synthetic database/evidence backup pair and verify every referenced digest before resuming reads. | SC4/C11 | ADR-0002/0009 | E13 |
| R15 | Failed ingestion, indexing or cancellation shall preserve the previous accepted corpus and expose a bounded error with last attempt/success and non-execution status. | SC2,SC6/C7,C10 | ADR-0002/0006 | E05,06,10 |
| R16 | Every outgoing file shall be selected by a reviewed publication manifest; the exact commit and artifacts shall pass generic and private identifier/source scans. | SC1/C1,C2,C3 | ADR-0001/0008 | E16,18 |
| R17 | The supported workflow shall run through documented local commands independently of GitHub Actions or proprietary hosting, after acquiring locked dependencies. | SC6/C12 | ADR-0007/0009 | E01,14 |
| R18 | Release evidence shall identify commit/tree/lock/artifact digests, tool/platform versions, full pass/fail/skip counts and unresolved findings. Changed bytes shall invalidate approval. | SC5/C3,C12 | ADR-0008 | E16,18 |
| R19 | Logs, diagnostics and default MCP/export location metadata shall omit credentials, raw source URLs, personal identifiers, local paths, DSNs and raw exception traces. Requested document content remains an explicit data disclosure, not an anonymized view. | SC1/C2,C8 | ADR-0004/0008 | E08,16,18 |
| R20 | All SQL values shall be parameterized and identifiers shall come from fixed schema code; parser/subprocess behavior shall not execute supplied content. | SC3/C4,C8 | ADR-0002/0003 | E08,09,12 |
| R21 | The reference deployment shall run application processes without root, host namespace access, privileged mode, host-control sockets or broad host mounts. | SC3/C8 | ADR-0009 | E08,14 |
| R22 | A versioned export shall round-trip selected synthetic records and evidence with ID/hash relationships preserved; URLs shall require explicit disclosure selection. | SC1,SC4/C2,C6 | ADR-0002/0004 | E03,17,18 |
| R23 | Dependency locks, image digests, SBOM, license notices and scanner dispositions shall be reviewable; unresolved exploitable material findings shall block release. | SC5/C12 | ADR-0007/0008 | E14,16 |
| R24 | The fixture harness shall never use operational credentials or source URLs; test-only routing/inference/provider doubles shall not weaken installed production enforcement. | SC1,SC3/C1,C4 | ADR-0004/0007 | E01,09,14,18 |
| R25 | Each acquisition adapter shall use external source endpoints, bounded cursors/rates and explicit parse/no-news/error states; no source seeds occur on import. | SC1,SC6 | ADR-0004 | E19,E40 |
| R26 | Structured XML/ZIP and PDF text extraction shall bound entities, recursion, paths, member count/size, parser resource/time and network effects, preserving original bytes. | SC3,SC6 | ADR-0014 | E12,E20 |
| R27 | Every accepted claim/assertion shall name evidence version and coordinate system; original-text slicing shall reproduce its quoted span, including Unicode normalization/case changes. | SC2,SC4 | ADR-0006/0014 | E27 |
| R28 | Embedding-space identity shall bind model/tokenizer/template/pooling/normalization/dimension/metric/precision; incompatible queries/vectors shall be rejected before search. | SC2,SC4 | ADR-0005/0011 | E21,E23 |
| R29 | Snapshot/model/chunk/policy/deletion changes shall invalidate dependent indexes/caches/derived outputs; activation shall be generation-consistent and reversible. | SC2,SC4 | ADR-0005/0016 | E22,E39,E48 |
| R30 | Model/code artifacts shall be hash/license/revision identified; runtime network downloads/custom executable model code shall be disabled by default. | SC3,SC6 | ADR-0011 | E34 |
| R31 | Hybrid fusion/reranking shall respect authorized candidate IDs, deterministic ties, finite scores and explicit fallback; ANN recall shall be checked against exact search. | SC2,SC3 | ADR-0005 | E22,E24 |
| R32 | Graph assertions and alias merges shall preserve source/ontology/version, contradiction and reversal state; mention/exact quote shall not imply affects/entailment. | SC2,SC4 | ADR-0014 | E27,E28 |
| R33 | Enrichment/analyst jobs shall persist inputs/attempts/leases/fencing/checkpoints and accept only validated schema-bound effects; stale workers shall not commit. | SC3,SC4,SC6 | ADR-0010/0014 | E25,E26,E44 |
| R34 | Retries/cancellation shall expose non-execution, partial and unknown outcomes; no at-least-once workflow shall claim exactly-once model/provider effects. | SC4,SC6 | ADR-0010/0013 | E25,E26,E38 |
| R35 | Briefings shall cite supported evidence for consequential statements, preserve qualifications/dates/corpus cutoff and label partial/fallback output; unsupported claims shall abstain. | SC2 | ADR-0014/0015 | E29,E30 |
| R36 | Vulnerability outputs shall preserve source CVSS/version/range, KEV/EPSS evidence/date and distinguish facts from target applicability/exposure. | SC2 | ADR-0014 | E31,E32 |
| R37 | Remediation deadlines and urgency shall come from explicit configurable policy with rationale; catalogue presence/scores alone shall not establish deployment impact or universal deadlines. | SC2 | ADR-0014 | E31,E32 |
| R38 | Regulatory records shall distinguish binding/proposed/guidance/interpretation, jurisdiction/version and adoption/publication/force/application/transposition dates. | SC2 | ADR-0014 | E33,E40 |
| R39 | Partial or stale regulatory/procedure/family evidence and uncertain article/applicability mappings shall remain review-pending/unknown rather than promoted to compliance conclusions. | SC2 | ADR-0014 | E33,E40 |
| R40 | The local reference shall demonstrate actual generation, embedding and reranking with licensed pinned models; compatible endpoint capabilities shall be probed and recorded. | SC2,SC6 | ADR-0011 | E23,E34,E35 |
| R41 | Shared local model admission shall bound queues/resources, isolate ownership, handle OOM/crash/drain and confirm worker termination before resource release/replacement. | SC3,SC6 | ADR-0011 | E35,E36 |
| R42 | Quota/resource state failure shall deny work requiring a hard budget and preserve reads; advisory counters shall not be represented as enforced limits. | SC6,SC7 | ADR-0011/0013 | E36,E42 |
| R43 | Before remote dispatch, route selection shall validate data classification, sovereignty/jurisdiction, endpoint/model/capability and budget, and persist the decision. | SC1,SC3,SC7 | ADR-0012 | E37,E41 |
| R44 | A disabled/unapproved/failed local route shall not silently escalate to cloud or a broader provider/tool/data scope; fallback edges shall be explicit and bounded. | SC1,SC3 | ADR-0012 | E37,E38,E44 |
| R45 | Model discovery/alias drift shall not auto-promote active routes; selection/upgrade requires capability, quality, license, sovereignty and resource/cost dispositions. | SC2,SC7 | ADR-0012/0015 | E34,E41 |
| R46 | Accounting shall preserve operation/attempt IDs, reservations, native token categories and estimated/observed/billed cost with explicit dated pricebook/currency; unknown usage shall not be zero. | SC7 | ADR-0013 | E38,E42 |
| R47 | Batch submit/poll/cancel/retrieve/ingest shall reconcile duplicate/missing/late/partial results by durable IDs without replaying ambiguous chargeable operations blindly. | SC4,SC7 | ADR-0010/0013 | E43 |
| R48 | Workspace context shall have actor/sensitivity/provenance/retention and explicit inclusion; no private personal/fleet state is imported or appended automatically. | SC1,SC3 | ADR-0014 | E30,E39,E44 |
| R49 | Migrations/backups/restores shall preserve a consistent database/object/job/index/accounting checkpoint and validate actual scoped grants and representative query plans. | SC3,SC4 | ADR-0002 | E08,E13,E45 |
| R50 | Status/metrics shall expose enabled-profile freshness, queues, model/index state, unknown accounting and recovery with bounded labels and no private payload fields. | SC1,SC2,SC6 | ADR-0009 | E05,E10,E46 |
| R51 | Outbound report publishing shall be disabled unless configured, validate exact staged bundles/disclosure policy and reconcile immutable receipts without database/network authority conflation. | SC1,SC4 | ADR-0016 | E17,E18,E47 |
| R52 | Specialist adapters shall be generic schema-bound mechanics with synthetic fixtures, external source mappings and no personal/employer/watchlist defaults. | SC1 | ADR-0004 | E19,E40 |
| R53 | Quality acceptance shall use frozen independent/held-out cases and predeclared targets; model self-evaluation, schema success or a prototype baseline alone shall not establish quality. | SC2,SC5 | ADR-0015 | E24,E27,E29,E41 |
| R54 | Retention/deletion shall honour holds, propagate tombstones to derivatives/caches/jobs/restores and disclose backup/provider/published-copy deletion limits. | SC1,SC4 | ADR-0016 | E39,E48 |
| R55 | Local-only operation shall produce zero provider egress; an external MCP client or optional provider shall be documented as a separate disclosure boundary. | SC1,SC3 | ADR-0009/0012 | E37,E44 |
| R56 | An explicit remote MCP profile shall use TLS and maintained authorization components, validate issuer/audience/expiry/scopes and bind each read/session to the authenticated allowed workspace. | SC1,SC3 | ADR-0017 | E49,E50 |
| R57 | Remote transport shall reject unauthenticated/wrong-audience/wrong-scope/cross-session reads, unsafe origins and token passthrough; disabling it shall close listener/session authority without affecting stdio reads. | SC1,SC3,SC6 | ADR-0017 | E49,E50 |
| R58 | Stdio and remote clients shall satisfy the same application schemas/semantics with a documented tested client/protocol/version matrix; unsupported capabilities shall fail explicitly. | SC2,SC5 | ADR-0017 | E07,E51 |

## Conflicts, assumptions and change impact

Optional cloud support and sovereignty are resolved by separate adapter availability and route authorization; compatibility never implies approval. Offline CI cannot establish real-provider operation, so contract-tested/live-verified are distinct evidence levels. Generic source adapters cannot ship the private source catalogue. Core simplicity cannot be used to silently exclude ML/enrichment/domain/cloud profiles. Complete capability scope does not justify copying irrelevant host-control privileges.

Inferred: a single-operator Linux reference with optional isolated workspaces is the initial deployment context; multi-tenant service operation is not claimed. Exact runtime/model/provider selections and quality/resource thresholds must be frozen at M0/M2 with evidence. No assumption of model truth, calibrated confidence, source completeness, compatible model weights or stable API aliases is accepted.

Every new adapter impacts R02/R09/R25/R26/R52; model changes R27-R35/R40-R45/R53; provider changes R43-R47/R55; domain changes R36-R39; lifecycle changes R14/R29/R49/R54. Reconcile hazards, ADRs, data contracts, privacy policy and tests before activation. Missing required evidence blocks the corresponding claim/profile acceptance; it is not represented as a pass.
