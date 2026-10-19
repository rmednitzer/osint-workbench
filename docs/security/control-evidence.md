# Secure-development control evidence

This register is the initial bounded technical selection for the current
single-operator CLI and stdio profiles. It does not assess an ASVS level, every
applicable control, the complete roadmap or a production deployment. A control's
presence here is an allocation and evidence inventory, not a conformance result.
The [alignment review](../testing/roadmap-alignment-2026-10-19.md) identifies the
review baseline; candidate test results must be read from their exact CI revision.

## Reference identity and assessment vocabulary

The selected source is OWASP ASVS **5.0.0**, English JSON at the upstream
`v5.0.0` tag, linked in [S3](../references.md#s3). The retrieved file's SHA-256 is
`bcdbec214d70abcfad9284a31d4f9e5134305831d628aad3aa85d7e26626cb35`.
The identifiers below were checked against that file. Summaries are deliberately
short; the versioned source defines the actual requirements.

- **Partial:** implemented controls and discriminating tests exist for named
  paths; broader applicability, deployment or verification remains unresolved.
- **Not assessed:** no claim is made from a reference, scanner result or nearby
  test. This applies to controls outside this initial selection.
- **Not applicable:** requires a documented feature/boundary rationale. No
  blanket browser, authentication or remote-profile exclusion is made here.

No selected control is marked completely satisfied in this review.

## Selected ASVS controls

Paths in the implementation column are under `src/osint_workbench/`.

| ASVS 5.0.0 | Bounded allocation | Implementation and discriminating tests | Assessment and remaining scope |
| --- | --- | --- | --- |
| V1.2.4 | Parameterized database operations | `database.py`, `jobs.py`, `cloud.py`, `record_purge.py`; [collector SQL denials](../../tests/test_collector_role.py), [reader grants](../../tests/test_reader_authority.py), [accounting concurrency](../../tests/test_cloud_settlement.py) | Partial. Bound values and fixed internal SQL fragments are reviewed; these tests do not prove every query, query plan, extension or future adapter safe. Broad writer authority remains a separate open issue. |
| V1.2.5 | Fixed runtime subprocess arguments | `collection.py`, `api_acquisition.py`, `local_encoder.py`, `local_reranker.py`; [hostile acquisition inputs](../../tests/test_acquisition_audit.py), [encoder packets](../../tests/test_encoder_packet.py), [child lifetime](../../tests/test_inference_child_lifetime.py) | Partial. No source-selected shell/program path; bounded parser/model children are not complete filesystem/network sandboxes. Native runtime and operator-selected artifact trust remain dependencies. |
| V1.3.6 | Constrain outbound acquisition | `fetch.py`, `api_http.py`, `oauth.py`; [DNS limits](../../tests/test_dns_policy.py), [address fallback](../../tests/test_address_fallback.py), [TLS](../../tests/test_tls_transport.py), [API transport](../../tests/test_api_transport.py), [OAuth](../../tests/test_oauth.py) | Partial. Actual configured paths enforce public-address pinning, TLS identity and redirect policy. Representative Internet/public-PKI/provider behavior and future browser/proxy paths remain unaccepted. |
| V1.5.1 | Reject unsafe XML feed parsing | `feed_parser.py`; [entity and malformed-feed cases](../../tests/test_core.py), [native acquisition](../../tests/test_acquisition_audit.py) | Partial. Applicable to the bounded RSS/Atom parser; generic legal XML, archives and PDF are unimplemented and require separate controls. Resource limits do not establish hostile native-parser containment. |
| V1.5.2 | Decode data into bounded declared types | `api_parser.py`, `contracts.py`, `recovery.py`; [strict API envelopes](../../tests/test_api_parser.py), [core contracts](../../tests/test_core.py), [recovery refusal](../../tests/test_recovery.py) | Partial. Source/wire/checkpoint data cannot select executable object constructors. This is not assurance of all native model formats or third-party transitive deserializers. |
| V2.2.2 | Enforce validation inside trusted application paths | `mcp_server.py`, `api_acquisition.py`, `cli.py`; [actual MCP protocol errors](../../tests/test_mcp_protocol.py), [API admission](../../tests/test_api_acquisition.py), [operator file admission](../../tests/test_operator_input.py) | Partial. Unknown tools/fields and unsafe bounded inputs are refused before effects in tested paths. Remote authentication, principal/workspace isolation and independent review identity remain unimplemented. |

## Project coding rules and STPA allocation

The twelve [coding rules](secure-development.md#coding-rules) remain the local
implementation contract. Acquisition and credential tests allocate SC1/SC3/SC6;
immutable evidence, fencing, lifecycle and recovery tests allocate SC2/SC4/SC8;
installed-wheel, publication and exact-set signing checks allocate SC5; explicit
cloud policy/reservations/settlement allocate SC7. The detailed controller,
feedback, unsafe-action and residual allocations remain in
[STPA](../assurance/stpa.md). This register does not create new hazard IDs or
reinterpret a test count as hazard closure.

Operator text/source-file admission was a concrete gap: named pipes blocked
before validation and text import read without a byte cap. The successor uses
the existing guarded regular-file reader with fixed call-site limits. Actual CLI
negative cases cover FIFO/device/directory/symlink/missing/oversized/malformed
inputs; growth and exact-byte/Unicode cases preserve the valid boundary.
Regular-file I/O still has no physical deadline, and parent custody remains an
operator assumption.

## Lifecycle, supply chain and unresolved assurance

NIST SSDF SP 800-218 **v1.1** remains the adopted lifecycle reference [S2](../references.md#s2).
Requirements/ADRs/STPA, intentional review, locked inputs, installed tests,
protected merges, source/artifact scans, provenance and vulnerability reporting
provide project evidence. This is not an SSDF practice-by-practice assessment,
independent organizational assurance or proof of effective vulnerability-response
staffing. Those broader assessments remain open.

The current type gate covers four named modules; Ruff security rules cover
application Python, with narrowly documented exceptions. Scripts, SQL, native
code, model quality and dependencies need their separate checks. Zero open
hosted alerts is an observation, not proof of security. Python/native-file
inventories and supplementary notices retain incomplete native/OS/model
composition and unresolved redistribution outcomes.

Before a broader profile or release claim, the maintainer must select its
applicable controls, identify evidence and residuals, and perform the missing
verification. In particular: independent review authority, quote-label support,
narrower retrieval-writer grants, complete static/type coverage, restricted
content and query-disclosure controls, remote MCP authorization, representative
model/provider behavior, deployment isolation and full recovery remain open.
No certification, regulatory applicability or legal redistribution clearance is
established here.
