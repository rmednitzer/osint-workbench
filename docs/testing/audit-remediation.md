# Audit remediation scope and evidence

The 2026-10-17 review of source `52610dcda2dc16c0cc79fa6a547d309cc2235cb8`
identified an evidence-store backend-loss race and overloaded feed-parser input,
plus bounded transport, packet and retry problems. This increment's goal is to
preserve recoverable evidence under that fault and make the observed input/error
boundaries explicit. It does not close the full implementation roadmap.

## Candidate acceptance

- Native disposable PostgreSQL termination after GC's reference read and at the
  final unlink boundary must not permit accepted metadata with missing bytes.
  GC process kills before/after unlink must release filesystem admission; later
  writers recreate byte-identical objects and stale-journal resume is refused.
- Store admission must cover commit, failed commit cleanup, cached 304 reuse and
  isolated restore, with anchored descriptors and independent thread/process
  ownership. Required order: DB admission, FS admission, fresh state.
- Actual parser children must reject path-shaped response data instead of loading
  readable local feeds. Explicit ASCII URL configuration fails before transport
  for unsupported Unicode/control characters; no resource identity is rewritten.
- Validate every DNS answer before selecting up to eight numeric connection
  attempts. Preserve resolver order, share one absolute deadline and allocate
  bounded connect time among attempts. TLS/certificate failures are not a reason
  to switch targets; original Host/SNI remain bound to the origin.
- Complete UTF-8 encoder packets, including maximum-length astral text, must pass
  bounded packet parsing before model integrity/session admission. Oversize,
  malformed, duplicate and truncated inputs have fixed errors.
- Per-source early database failures must preserve independent-source progress;
  transient lifecycle/store contention retries within the existing fenced job
  budget. Integrity/provenance failures remain terminal.
- Designated isolated workflow builds must enforce the complete exact, hashed
  Hatchling build closure in `build-constraints.txt`. Wrong or missing transitive
  hashes must prevent a build. This is not a claim that every possible external
  PEP 517 frontend or development bootstrap applies those command-line controls.

All 630 installed-wheel tests passed with no skips, including 58 additional audit
cases. The [revision-bound receipt](verification-evidence.json) identifies source
`064be8bb629a61e50ed9d4708a52a7b13675cb28` and [run 39063644045](https://github.com/rmednitzer/osint-workbench/actions/runs/39063644045). The
[separate service receipt](collector-deployment.json) covers the same wheel.
Local/component checks alone are not the native release evidence; any failed
attempts and exact code/artifact identities remain recorded.

## Audit dispositions still open

The initial commit's author contact identifier remains in Git metadata. No address
is repeated here. Removing it requires coordinated history rewriting and revised
provenance; that was not authorized by this implementation increment. Current
source/artifact and introduced-history scans do not erase existing clones.

Repository branch protection/rulesets remain a separate policy decision. No
access restriction was changed. Type checking, selected SAST, licence disposition
and a current dependency advisory result remain unfinished assurance work. A
failed advisory lookup is not a clean scan.

The shared temporary inference-lock default, large-model hashing/admission
budgets, adopted multi-logit scoring semantics, multilingual quote/context policy,
serving beyond the reference corpus bounds and review/head linearization need
their own requirements and acceptance decisions. They are not silently fixed by
changing semantics in this patch. Purge replay keeps its full current-state
admission/anti-resurrection checks; historical outcome-query availability beyond
the bounded profile remains open and is now explicit in the operator procedure.
