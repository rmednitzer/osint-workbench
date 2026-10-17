> Target specification. See STATUS.md for implemented and verified scope.

# Secure development baseline

## Adopted references and claim limits

Use NIST SSDF SP 800-218 v1.1 as a lifecycle practice reference [S2], selected OWASP ASVS 5.0.0 controls as a technical checklist [S3], and the chosen MCP specification/SDK security guidance [S4]. These are design inputs, not claims of formal conformance. At implementation, select applicable ASVS items from the actual versioned text and record satisfied/not satisfied/not applicable with evidence. Do not invent clause mappings or copy a generic checklist and call it an assessment. The plan makes no regulatory applicability or certification claim.

## Coding rules

1. Use a src-layout Python package and one tested Python minor for the first release. The inspected source targets Python 3.12; confirm its support and dependency compatibility at implementation before freezing the runtime. No sys.path injection, execution from mutable state directories or implicit import-time migrations/network calls.
2. Define typed configuration and request/response contracts. Reject unknown fields, invalid bounds and unexpected types. Handle missing/naive timestamps explicitly; keep UTC internally and preserve timestamp origin. Use stable IDs and schema versions, not mutable filenames as public identity.
3. Parameterize every SQL value. SQL identifiers come from fixed program code or a tiny explicit allowlist. Use least-privilege roles, fixed grants, statement timeouts, transaction boundaries and database constraints. Prefer ordinary curated views over SECURITY DEFINER; any necessary privileged function requires separately reviewed ownership, fixed safe search_path, fully qualified objects and execute grants.
4. Never evaluate source text, templates, extracted commands, pickle payloads or object deserializers with executable constructors. Avoid subprocesses in the runtime. Any exceptional subprocess requires fixed executable, argv array, no shell and explicit bounds. The MCP layer contains none.
5. Validate URLs and every resolved address/redirect in the actual connection path. Reject userinfo, file/data/ftp schemes, loopback, private, link-local, multicast, unspecified, metadata endpoints, IPv4-mapped IPv6 equivalents and ambiguous numeric encodings. Preserve TLS hostname/SNI/certificate verification when pinning the validated address. Disable ambient proxy inheritance unless a separately validated operator policy explicitly supports it.
6. Bound DNS, connect, redirects, retries, wall time, wire bytes, decompressed bytes, parser depth and concurrency. Honor bounded Retry-After where supported; record terminal failure. Cancellation must close connections and terminate related work rather than merely stop waiting.
7. Parse only content types declared by the enabled profile; legal XML/ZIP and PDF text use separate bounded parser workers. Disable XML external entities and network resolution; reject unsupported/oversized entities. Do not introduce a headless browser, archive extraction or model auto-download as a hidden parser fallback.
8. Derive evidence paths from validated hashes under a fixed root. Defend against traversal, symlinks, race conditions and path substitution; use atomic same-filesystem object publication and read-only consumer mounts. IDs never become unrestricted path fragments.
9. Fail explicitly. Separate no matches, stale data, partial extraction, unavailable storage and integrity mismatch. Avoid broad exception catches that convert failure into empty successful output. Logs expose bounded error codes, not credentials, DSNs, source bodies or tracebacks in public output.
10. Treat returned text as hostile data. Removing script tags is useful normalization but does not establish prompt-injection safety. Tool outputs cannot authorize tool calls or change collector policy. No automatic follow-up fetching of model-generated URLs.
11. Manage connection pools, lock ownership, task cancellation, transaction retries and shutdown explicitly. Do not retry an ambiguously committed mutation blindly; reconcile by source/version/run identity. Add regression tests for consequential failures.
12. Keep security decisions in enforcement code and tests, not only README instructions, MCP annotations or agent prompts. AGENTS.md and CLAUDE.md should point to the same authoritative coding/security rules and warn that repository content is untrusted input, without inventing approval authority.

## Threat boundary review

| Boundary | STRIDE concern | Enforcement / test |
| --- | --- | --- |
| Publisher to collector | Spoofing/tampering: redirects, parser payloads, forged dates | TLS plus per-hop destination validation; record date provenance; E09/12 |
| Collector to persistence | Tampering/repudiation: partial commit or duplicate writers | Hashes, run ledger, constraints, atomic publication; E02/03/06 |
| MCP client to reader | Elevation/disclosure: SQL, path or tool abuse | Schema validation, reader grants, read-only mount, no network fetch; E08 |
| Evidence to client/model | Information disclosure/instruction confusion | Redacted location fields, bounded results, explicit untrusted content; E08/12/18 |
| Build to public repository/artifacts | Tampering/disclosure: secrets, stale scans, malicious dependency | Locked inputs, provenance/manifest review, private scans and digest binding; E16/18 |
| Operator to recovery | Integrity/availability: wrong-target restore or deletion | Isolated target checks, verified backup pair, reachability validation; E13 |

Privacy checks also consider linkability of source selection, identifiability in author/build metadata and disclosure through diagnostic logs. A local deployment does not prevent data disclosure by the chosen MCP client.

## Supply chain, CI and repository controls

Keep direct dependencies minimal: PostgreSQL driver, typed validation, maintained feed/XML and bounded HTTP parsing, CLI and maintained MCP SDK; verify actual releases and licenses when selecting. Lock transitive packages with hashes and image digests. Do not reuse old generated lockfiles/SBOMs that contain original package identity or build paths. Regenerate from the extracted dependency set.

Run formatting/lint, type checks, functional tests, selected static security analysis, dependency audit, license review and secret/publication checks. Supply local commands for every CI step. Scanner findings need reachability/exposure dispositions; no blanket ignore files or unreviewed auto-fixes. Narrow exceptions record rationale, owner and review condition. Unknown unresolved material findings block release.

Use GitHub-hosted disposable CI for public synthetic tests or an equivalently isolated runner. Do not attach a public repository's untrusted PR jobs to private fleet runners. Use minimal workflow token permissions, pin third-party actions by reviewed full commit SHA, avoid privileged pull_request_target execution of PR code, and never expose release secrets to untrusted contributions. Public CI receives no private denylist, source registry or operational variables.

Require relevant checks before merge where supported by the repository configuration. Protect release tags where available and verify observed enforcement rather than claiming it from settings files. Branch/ruleset changes are implementation tasks, not performed by this plan. No packaging registry publication is required for v0.1; a reviewed GitHub source release is sufficient if the clean build/install path is tested.

SECURITY.md must describe the supported scope, safe reporting route and response limitations. Document experimental maturity and AI-assisted development. Preserve third-party copyright/notice obligations and inspect ownership before transferring code; the existing Apache-2.0 file does not establish that all candidate code or source content is redistributable.


## Full-profile additions

Executable model code is a supply-chain boundary: default trust_remote_code=False, local-only verified artifacts, explicit audited exception if necessary, no credentials/egress in model processes and separate review of tokenizer/templates. Never treat local_files_only as a code-execution sandbox. Heavy ML dependencies remain outside reader/MCP processes.

Every workflow output needs schema, input and model/prompt lineage plus evidence-state validation; model strings never become SQL identifiers, shell commands, policy or tool authority. Use Unicode-correct source coordinate maps, property tests/fuzzing for parser/span/normalization boundaries and regression fixtures for confirmed defects. Security invariants use runtime checks, not removable Python assertions.

Cloud dispatch requires data/sovereignty/capability and budget enforcement in code, with no silent fallback. Persistent quotas fail closed when required state is unavailable; logs cannot reconstruct missing accounting as zero spend. Validate streaming and batch identity/outcome independently of completion text. Caches, graph expansion and approximate retrieval must enforce scope before returning candidates.

Use generic public profile templates, not original model/hardware/provider inventories. SBOMs include core/ML/provider/model-code dependencies and license dispositions; build inputs and public workflow metadata are scanned. Real API/model tests must record exact identities and limitations; protocol mocks and LLM judges are not substitutes for actual local inference and independent quality labels.
