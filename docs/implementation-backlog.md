# Remaining implementation and acceptance work

The goal remains a self-hostable, source-configurable workbench that can acquire,
preserve, enrich and retrieve evidence, produce qualified cited intelligence and
expose it through scoped MCP reads. Local inference must be useful and measured;
cloud support must be optional, policy-controlled and accountable. A new install
must reproduce the documented supported profile without private prototype files.
This is integration engineering, not a claim of original model research.

This ledger records unfinished work after bounded local inference/retrieval,
recovery/lifecycle and governed cloud reservation/settlement increments.
STATUS.md describes current code; the named CI receipt establishes tested scope.
The 51 full acceptance scenarios remain the release programme. More regression
tests do not automatically close a complete scenario or make the project ready
for operational use. The prototype is a source of feature intent, never a
correctness oracle or a source of public fixtures/configuration.

The [dated prototype comparison](prototype-lessons.md) records useful mechanisms,
bounded source/catalog findings and discriminating acceptance cases. Its delivery
order refines this ledger without claiming profile completion or importing the
private implementation. In particular, domain observations must distinguish state
content from occurrence/current authority, and publication receipts must bind the
accepted product generation.

The [2026-10-19 alignment review](testing/roadmap-alignment-2026-10-19.md)
accounts for every requirement and full scenario. Its bounded code/test mapping
does not close the workstreams below. The initial
[ASVS control selection](security/control-evidence.md) is partial; broader
applicability and lifecycle assessment remain open.

## Delivery order and closure evidence

| Workstream | Concrete outstanding implementation | Evidence required to close the workstream |
| --- | --- | --- |
| Recovery and lifecycle | Full all-copy erasure beyond transactional retired-record SQL purge and bounded orphan-object GC; shared-feed disentanglement; backup expiry; independent policy custody/replication; legacy format adoption; larger-corpus/deployment recovery; extend current logical-key suppression/holds to future context/cache profiles | E13/E39/E45/E48: physical deletion/hold/shared-reference cases, supported old-pair migration, restored policy and failure/restart, explicit recovery point; transactional SQL deletion and logical suppression do not prove all-copy erasure |
| Acquisition and parsing | Broader source/deployment acceptance beyond the isolated installed RSS HTTP/timer fixture, including provider contracts beyond the bounded authenticated JSON-page and [KEV catalogue mapping](kev-acquisition.md) profiles ([ADR-0046](adr/0046-authenticated-api-acquisition.md)), restricted rights-domain isolation, OAuth beyond the bounded [client-credentials mode](oauth-acquisition.md), mTLS/private-key signing, documented search POSTs, paid-query accounting, operational API adoption beyond the bounded [two-LTS service evidence](testing/scheduled-api-hardening-2026-10-18.json) ([ADR-0047](adr/0047-scheduled-api-service.md)), Internet DNS/public-PKI and operational TLS beyond native configured-trust fixtures, provider-specific cursors/watermarks, redirect-response retry advice and shared-host rate/jitter policies beyond bounded per-source Retry-After scheduling; article/HTML/JSON-LD/XML/ZIP/PDF, explicitly isolated JavaScript rendering and generic specialist adapters; explicit partial/schema-drift outcomes; broader adversarial HTTP/DNS/redirect coverage | E05/E09/E10/E12/E19/E20/E40: synthetic hostile inputs through the installed actual transport/parser path, bounded resources and preserved raw versions; no operational endpoint catalogue |
| Retrieval at scale | Resumable backfill, incremental scheduling, cache identities/invalidation, scoped filtering and optional ANN with an exact oracle; index readiness/rollback across upgrades | E21–E24/E39/E45: restart during backfill, compatible atomic activation, filtered candidate isolation, measured exact-vs-ANN recall and frozen relevance cases |
| Useful local models and resource operations | Validate the explicitly pinned experimental encoder and select adopted licensed pretrained encoder/reranker/generator artifacts; capability/upgrade probes, complete stream/incomplete/refusal contracts where supported; measured memory/queue admission, OOM/drain/shutdown and a declared acceleration profile | E23/E24/E34–E36/E41: actual held-out CPU inference and declared GPU hardware evidence, independent expected outputs, no implicit downloads/custom model code, old worker ownership resolved before replacement |
| Enrichment, graph and context | Durable prerequisite/checkpoint workflows beyond the current bounded workers; source-aware entity aliases and reversible merges; contradictions; explicit workspace notes/decisions/deadlines with sensitivity, provenance and retirement | E25–E28/E30/E39/E44: killed/retried workers, alias reversal, contradiction preservation, late-result rejection and retired context absent from future retrieval/model packets |
| Briefings and semantic quality | Topic/importance selection, source-family independence, diversity/MMR, deeper supported analysis and explicit omissions; extend the frozen public English/German diagnostic with independently labelled, separately controlled held-out cases and answerability policy before adoption | E24/E27/E29/E30/E41: independently labelled citation support/refutation, relevance, abstention, omission/recall and source diversity; synthetic constant-model execution or LLM self-grading alone cannot pass |
| Vulnerability intelligence | Upstream adapters and domain persistence beyond the offline observation envelope and bounded KEV document mapping: generic CVE/vendor/OS advisory, EPSS and OSV/dependency records; broader persisted observation integration beyond the [read-only KEV projection](kev-advisory-projection.md); revisions/retractions; local package/SBOM applicability with ecosystem-specific range semantics; explicit prioritization policy | E31/E32/E40: known positive/negative/unknown applicability cases, conflicting/revised upstream facts, source/time/score lineage; catalogue presence never automatically means exposure |
| Regulatory intelligence | Versioned instruments/articles/annexes, consolidations/corrigenda, procedures, publication families and jurisdictions; distinct legal status and date types; qualified evidence dossiers and uncertain mappings | E20/E33/E40: synthetic multilingual instruments and transitions, changed dates/text, partial sources and national/EU differences; no automated compliance conclusion |
| Governed cloud routes | Native OpenAI/Anthropic adapters, streaming and further declared-compatible capabilities beyond the bounded chat-completions route (ADR-0042); a separate dispatcher identity; classified release packets, capability/data/sovereignty policy, explicit fallback graph and route audit; external credentials/configuration | E37/E38/E41/E44: actual adapter-to-fixture-server tests, denied/unconfigured routes with zero dispatch, no silent escalation, bounded streams and honest incomplete/refusal outcomes; real provider smoke evidence is a separate explicitly enabled activity |
| Usage, budgets and batch operations | Invoice/usage import and automatic provider reconciliation beyond the bounded reservation ledger and evidence-bound operator settlement (ADR-0042, ADR-0043); correction workflow for settlements; native token categories (cached, reasoning), dated price/currency records, unknown outcome accounting; batch submit/poll/cancel/retrieve/import with reconciliation | E38/E42/E43/E45: concurrent reservation limits, crashes and ambiguous remote acceptance, duplicate/missing/late results, no invented zero usage or blind chargeable replay |
| Remote MCP and authorization | Maintained authenticated HTTP transport, issuer/audience/scope/origin checks, principal/workspace/session binding, expiry/revocation and explicit disable behaviour; profile-aware read tools for implemented domains | E08/E49–E51: real independent clients, positive and negative authorization, cross-session attacks and matching authorized stdio/HTTP semantics; no default unauthenticated listener |
| Consumer export and publication | Versioned selected-field export with explicit URL/content disclosure; validated staged outbound bundles and separately scoped immutable publication receipts | E17/E18/E47: consumer schema round trip, disclosure canaries, receipt reconciliation and unknown publishing outcome; private checkpoints are not this feature |
| Deployment, observability and reliability | Complete operational adoption beyond collector/chunk/health service templates and explicit group-readable storage: provider process authorities, supported downstream consumers, monitoring/notification routing, sustained workload/capacity and target-host failure/recovery | E08/E14/E15/E45/E46: revision-bound installed service/permission-negative tests, mixed workloads, unavailable dependencies and representative recovered queries; operator health/recovery targets; no private host/service inventories |
| Secure development and release assurance | Extend the initial six-control ASVS 5.0.0 selection to full applicability and lifecycle evidence; complete type/static analysis, dependency/license/SBOM dispositions, build provenance, reviewed repository/release protection and scoped vulnerability response | E13/E14/E16/E18/E44/E45: revision/artifact-bound evidence, all required checks run without unexpected skips, actual enforcement observed; adopted references are not formal conformance |

Within these groups, establish deletion/recovery and permission boundaries before
adding effects that depend on them. Acquisition hardening, deterministic domain
contracts and held-out quality design can proceed independently. Any additional remote dispatch path must retain the already implemented
release-policy and durable-accounting prerequisites. Public publishing
must wait for selected-field disclosure controls. Do not drop local, cloud, domain
or optional profiles merely to simplify completion claims.

## Open audit findings and their next evidence

The [dated audit dispositions](testing/audit-remediation-2026-10-18.md) retain the
individual implementation findings and severities. Priority follow-up includes:

- The misleading mention contract is replaced by explicit proposal-label bindings
  in [ADR-0051](adr/0051-honest-assertion-label-bindings.md). Label-specific spans,
  entity resolution and independently verified semantic support remain future work.
- Separate reviewer SQL authority is implemented in [ADR-0053](adr/0053-reviewer-database-authority.md).
  Human independence, workspace authorization and operational adoption remain open.
- Retain native acceptance for byte-budget MCP pagination, literal source-token
  isolation and exact reader-grant validation added by
  [ADR-0045](adr/0045-bounded-operational-profile.md); verify intended assistant
  clients and adopted tokenizer capabilities separately.
- Retrieval profile 5 narrows writer UPDATE to status/error and the active generation.
  [Index encoder custody](adr/0056-index-encoder-custody.md) binds new operations
  to owned configuration; build, activation and read paths check registered metadata.
  Historical vectors still need requalification where producer custody is uncertain;
  matching metadata is not per-call production evidence.
  Enrichment enqueue now reports
  terminal preservation and atomic stored status; broader job producer retry/reset
  contracts remain to be reviewed.
- Retain revision-bound service acceptance when feed identity or its harness
  changes; the core-10 two-LTS receipt covers its named wheel, while historical
  receipts do not validate a newer oracle automatically.

These are unfinished engineering and verification tasks, not claims that an
exploit or operational incident occurred. New evidence must discriminate the
claimed failure and preserve existing lifecycle/permission boundaries.

## Next bounded changes after local API integration

1. Qualify reviewer credential custody and human review procedures in an adopted
   deployment. [The SQL boundary](reviewer-authority.md) does not establish human
   independence or per-workspace authorization. Apply core 12/profile 5 and
   requalify legacy reviews before relying on their cited products.
2. Preserve the exact retrieval writer column grants through future index,
   activation, purge and recovery changes; broader producer separation remains open.
3. Explicit enrichment and [chunk operation receipts](workflows.md#explicit-chunk-recovery-and-receipts)
   cover their bounded producers. Broader workflow/DAG scheduling and automatic
   backfill remain open. Preserve intentional operation identity, terminal history
   and uncertain local/API/cloud admission; acquisition counts never prove downstream completion.
4. The [frozen diagnostic](local-quality.md) supports encoder and stand-alone
   reranker execution; independent useful-model/cascade quality remains open.
   Qualify selected useful local models and actual API server deployments, including
   disabled forwarding, licence/provenance, chat templates, context/resource limits,
   controlled held-out support/abstention/relevance and acceleration evidence.

The [local API profile](local-inference-api.md) closes the missing explicit chat
transport integration only. Embedding/reranking APIs, vendor-specific streaming,
DNS/service discovery, actual Ollama/vLLM adoption and cross-host resource control
remain open. Its operator qualification is not machine proof of local execution
or sovereignty. Full workstream/scenario acceptance above remains open.

## Privacy and acceptance limits still open

Every future commit, package, fixture, model manifest, release receipt and log
needs publication review against the private identifiers kept outside Git.
Source URLs, hostnames, operational prompts/configuration and private inventories
must remain external. Pattern scans cannot prove arbitrary document content is
anonymous. An external MCP client is a separate disclosure boundary.

Pre-existing public Git author metadata is unchanged; clean new commits and file
scans do not erase historical metadata. History remediation is a separate deliberate
repository change, not something this implementation performs implicitly.

The current native tests use authored synthetic model weights. Useful pretrained
semantic quality, GPU behaviour, actual provider operation, remote MCP compatibility,
full-host recovery and the complete acceptance programme remain unverified. A
workstream closes only when its implementation and specified evidence both exist.
