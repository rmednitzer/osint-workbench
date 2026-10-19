# ADR-0039: Adopt MCP SDK v2 with explicit read and telemetry boundaries

Status: ACCEPTED; runtime qualification partly superseded by ADR-0050. Date: 2026-10-18.

## Context and decision criteria

The dependency dashboard identifies a stable MCP major update. The previous
lock selected 1.30.0, not 1.3.0, but its `<2` constraint excluded the maintained
v2 API. A successful resolution alone cannot establish protocol, authority,
privacy or native-runtime compatibility. This review also covers the entire
Python lock, hashed build closure and external CI/native dependency pins.

Criteria are supported stable releases, the existing Ubuntu/CPython matrix,
seven bounded read tools, explicit validation, sanitized failures, no implicit
telemetry disclosure and revision-bound installed/native evidence.

| Alternative | Consequences |
| --- | --- |
| Retain v1 | Avoids migration but leaves the stable major update unresolved |
| Change only the bound and lock | Removed handlers, renamed fields and changed protocol behavior remain unverified |
| Replace the adapter with automatic high-level tool inference | Introduces an unnecessary schema and exception-contract change |
| Migrate the explicit low-level adapter and test both protocol eras | Preserves application control over schemas, dispatch and errors; selected |

## Decision and verification

Select MCP 2.3.0 and require `>=2.3,<3`; exact dependency bytes remain locked.
Use constructor-registered low-level handlers, typed request/result envelopes
and snake_case SDK attributes. Preserve the existing wire tool schemas and
annotations, application JSON Schema checks, fixed dispatch table, reader-only
database identity, 64 KiB result bound and sanitized tool-error codes. An omitted
argument object becomes an empty object; malformed arguments must never reach
the read service. No tools gain acquisition, write, model or administrative
authority. The transport remains stdio.

Exercise real SDK clients in modern and legacy modes over stdio, including
database-backed reads, argument refusal and shutdown. Modern discovery and the
legacy initialization handshake have different protocol mechanics; an SDK
round trip does not establish compatibility with an actual assistant product.
Remote HTTP authentication and authorization remain unimplemented.

SDK v2 installs OpenTelemetry middleware even on the low-level server. The API
alone has no exporter, but embedding the adapter in an instrumented process
could activate tracing. Remove only the SDK tracing middleware using its
[documented opt-out](https://py.sdk.modelcontextprotocol.io/run/opentelemetry/).
Do not configure a global provider or disable unrelated middleware. The
provisional underscored class import is an explicit maintenance dependency;
import drift must fail startup rather than silently restoring tracing. Test
the resulting request path and preservation of other middleware. This does not
prevent a client or embedding process from independently recording data.

Review upstream stable releases across the full resolved closure, including
new SDK dependencies, rather than only versions allowed by the old caps.
`httpcore` and `httpcore2` are separate distributions; adopting the latter
transitively does not authorize replacing the collector's explicitly tested
transport. Keep CPython 3.12–3.14 support; adding 3.15 requires its own wheel,
native and runtime acceptance. Refresh licence/native evidence from inspected
locked wheels, retaining unresolved composition and redistribution outcomes.
The hashed build closure is reviewed independently of Renovate exclusions.

The native test server uses the latest stable llama.cpp release, v0.7.0, instead
of the newer unreleased source commit previously pinned. The immutable source
and archive digest, synthetic GGUF execution and complete native matrix must
establish that transition. Stable selection is not a claim that every commit is
newer than the previous pin. CI actions, uv and service/tool images retain exact
identities and are updated only when a newer supported stable identity exists.

The dashboard remains a recurring maintenance issue. Resolve its listed updates
through the reviewed PR; do not close it or weaken major-update approval,
release-age policy, hashed builds, privacy checks or protected merge gates.

## Impact, limitations and rollback

Blast radius is the public adapter, dependency resolution and disposable test/
evidence pipeline. There are no schema migrations or operational fleet changes.
Tests use synthetic data and models without cloud requests or pretrained
downloads. Registry currency and clean vulnerability results are dated evidence,
not a security or licence guarantee. OS packages, complete native component
lineage, model assets and operational deployment remain separate scope.

Roll back through a protected PR restoring the adapter, tests, complete lock,
external pins and their matching licence/native policies together. Rebuild and
verify every required profile; an old receipt does not validate the rollback.
Public provenance remains immutable historical evidence.

Primary references: [SDK migration](https://py.sdk.modelcontextprotocol.io/whats-new/),
[SDK release files](https://pypi.org/project/mcp/2.3.0/) and
[upstream native releases](https://github.com/ggml-org/llama.cpp/releases).

## Runtime qualification successor (2026-10-19)

[ADR-0050](0050-required-lts-and-optional-python-profiles.md) supersedes the
three-profile merge/signing requirement with two native LTS profiles and separate
optional interpreter diagnostics. Earlier runtime fixes and source-bound evidence
remain valid for their named revisions. Package bounds remain `>=3.12,<3.15`.
