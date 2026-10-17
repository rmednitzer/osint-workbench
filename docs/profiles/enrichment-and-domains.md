# Enrichment, graph, briefings and domain profiles

## Durable enrichment and analyst workflows

Deterministic parsing precedes model extraction. Jobs declare inputs, output schema, policy, prompt/model version, resource limits, dedup key, prerequisites, lease/fencing token and postconditions. Proposals are validated before accepted-state writes. Model calls can abstain, fail or yield partial output; repairing malformed JSON requires a bounded explicitly tracked attempt and cannot quietly change the factual result. Record operation identity through every attempt.

Bounded analysts can read registered evidence/search/domain tools and propose typed enrichment outputs. They cannot execute code, change source/provider policies, see secrets or obtain host/fleet authority. Workflow definitions are reviewable code/config, not arbitrary downloaded plugins. Model tool arguments receive the same validation as external API input. Durable state records phase/checkpoint/cancel state; outputs from an expired worker are fenced out. Worker retry is at-least-once with idempotent acceptance; remote model calls may have unknown cost/outcome.

Prompt injection can appear in visible text, metadata, retrieved chunks and model output. Treat it as untrusted throughout; sanitization/RAG does not eliminate it [S9]. The enforceable guarantee is bounded authority and validated effects, not model obedience. Use adversarial cases, output schemas, source-span checks and no arbitrary follow-up actions. Uncertainty and abstention remain visible.

## Graph and claim lifecycle

Represent assertions in PostgreSQL with subject/predicate/object, ontology version, original publisher, snapshot/chunk/span, extractor kind/version, model/prompt identity, observation/effective time, acceptance rationale and lifecycle. Use mentions, affects, supersedes, ownership, deadline and other relations only under explicit schemas and evidence rules. Structured advisory membership is not equivalent to software applicability or exploitation. Quotation matching establishes textual support location, not semantic entailment or source truth.

Entities have source-qualified IDs, aliases and reversible merge events. Do not merge homonyms, organizations/products or different-language names solely on fuzzy similarity. Preserve contradictions, negation, disputed assertions and superseded versions; graph expansion cannot hide rejected/quarantined facts. Compute derived edges from recorded inputs/rules with invalidation when evidence changes. Model-suggested links require explicit proposal status and independent validation.

## Briefings, source diversity and context

Briefing selection is configuration-driven: topics, materiality, time window, source families, duplicate/syndication policy and diversity controls. No personal interest/source/job watchlist is supplied. Keep publication/retrieval/event/effective dates distinct. Build summaries from selected evidence, preserve relevant qualifications and link each consequential statement to evidence. A citation existing in a corpus does not establish that it supports a statement. Contradictions must be represented or the claim omitted/marked unresolved.

MMR/diversity uses documented features and family assumptions. Different URLs or model agreement do not prove publisher independence. Quality evaluation includes missing high-priority events, over-filtering, repeated syndicated stories, citation precision and unsupported operational advice. A model failure may produce an explicitly labelled deterministic digest; it must not present it as completed deep analysis. Reports name corpus cutoff, run/model/prompt identity and partial/degraded state.

Optional research workspaces include threads, decisions, deadlines and timeline events with actor, sensitivity, source and retention. This is explicit application content, not a connector to personal memories, fleet state or unrestricted files. Retired/tombstoned context must disappear from active retrieval, caches and future model packets. A manual note is not an authoritative external source. Deadline changes retain provenance/review and do not silently delete the previous record.

## Vulnerability profile

Implement configurable structured acquisition for CVE records, authoritative vendor/OS advisories, KEV/EPSS and OSV/dependency data; endpoints and source lists remain external. Preserve raw snapshots and schema versions, CVSS version/vector/source, affected product/range/configuration expressions, EPSS score/date and KEV evidence/date. Treat retractions, rejected CVEs, revised descriptions, feed delays and conflicting vendor data explicitly.

Match optional operator-supplied package/SBOM/inventory records locally with product identity/version/platform prerequisites and uncertainty. A CVE in the catalogue does not establish target exposure; CPE/string matches can be ambiguous, and version ordering is ecosystem-specific. Separate vulnerability presence, applicability, exposure, active exploitation evidence and configured remediation policy. No universal patch deadline or exploitation claim derives solely from CVSS/EPSS/priority. Policy output includes rationale and unknown fields. Export interoperable JSON/STIX only with actual schema/semantic tests; do not claim STIX support because identifiers look correct.

## Regulatory profile

Implement versioned instruments, article/recital/annex text, source snapshots, structured XML/FORMEX, bounded PDF text where needed, consolidations, corrigenda, publication families, procedures/transitions and evidence dossiers. Model adoption/publication/entry-into-force/application/transposition/implementation dates separately and preserve uncertain mappings. Maintain jurisdiction and instrument mappings as user-supplied profile data; provide synthetic examples covering EU and national changes without shipping the existing watchlist or acquisition URLs.

Separate binding legal text, official guidance, proposals, source observations, interpretations and entity-specific applicability. No automatic compliance determination. National obligations cannot be inferred from an EU instrument alone. Partial/inaccessible sources, outdated consolidations, wrong article mappings, language variants, repeals, pending review and conflicting effective dates remain explicit. Reconciliation must not promote stale corroboration after text/normalization version changes. Procedure state is not the same as enacted law.

## Specialist source adapters and publication

Generalize defence/industry, vendor blog and employment-source mechanics with per-adapter parsers/schema, pagination/rate controls and fixtures. Do not bundle actual employers, private taxonomies, destinations or existing URLs. Source authority classifications are configurable assertions with rationale, not truth inferred from domain spelling. Handle changes in upstream layouts with an explicit parse-failed state rather than silent no-news success.

Local products use versioned JSONL/manifests and readable reports. An optional outbound Git publisher holds only its selected destination credential, receives a validated staged bundle, excludes private fields/content under an explicit disclosure profile and records immutable publication receipts. Database reconciliation validates receipt identity and is separately scoped from network publishing. No automatic external push is enabled by default; deletion/revocation limits for previously published products are documented.
