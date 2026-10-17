# ADR-0030: Verify transport trust boundaries with native synthetic peers

Status: ACCEPTED for transport verification. Date: 2026-10-17.

## Context and decision drivers

The public HTTP acquisition profile pins a validated address at connection time
while retaining the configured HTTP origin for TLS identity and request routing.
One absolute monotonic deadline spans resolution, connection, TLS and HTTP I/O.
The disconnected service fixture establishes one synthetic HTTP path, not TLS,
public DNS or certificate trust. Successful in-memory HTTP framing cannot prove
certificate rejection, hostname/SNI preservation or actual native handshake/read
timeouts. Code inspection alone cannot establish those runtime effects.

The next evidence increment must exercise the existing production path with
independent native socket/TLS peers. It must not add a private-address exception,
permissive TLS mode, system trust-store mutation or implicit external request.
Fixtures remain synthetic and runtime support limitations remain visible.

## Alternatives, including no change

- Keep HTTP-only fixtures and static inspection. This preserves existing results
  but leaves consequential native TLS/DNS boundaries unexecuted.
- Mock TLS success or disable certificate/hostname verification. This tests
  control flow while removing the property under assessment; reject it as trust
  evidence.
- Use a live public service and DNS. This depends on an external identity and
  network, exposes source-selection metadata and cannot deterministically create
  wrong-host, untrusted-chain, mixed-answer or stalled-handshake cases.
- Use ephemeral test certificates and native local peers, with explicit fixture
  trust/routing injection at the test boundary. Choose this bounded approach
  while retaining production certificate and address-policy enforcement.

## Decision and trust mechanics

Create a private temporary test CA and leaf certificates using the installed
OpenSSL tooling. Positive TLS cases add the intended fixture CA only through
the test's context construction, retaining `CERT_REQUIRED` and hostname checking.
Do not install that CA into machine trust or expose a production flag for it.
Negative cases retain wrong-host or untrusted-chain conditions and must fail
before an HTTP request is accepted. Test certificates and private keys remain
ephemeral test files, not repository artifacts or operational credentials.

The test transport routes only to disposable local listeners. State explicitly
which DNS/backend/context boundary is injected: local routing is not public
Internet DNS, reachability or deployment evidence. Within that boundary, exercise
native TLS cryptography, the real `_Stream.start_tls`, httpcore connection/request
handling and deadline checks. Assert the original URL hostname at SNI and HTTP
Host while the TCP destination is the validated/routed address. A correct chain
without a matching hostname is insufficient.

Python's [TLS documentation](https://docs.python.org/3.12/library/ssl.html)
describes certificate validation, hostname checking and `server_hostname` as
separate required configuration concerns. HTTPCore's
[network-backend contract](https://www.encode.io/httpcore/network-backends/)
passes the TLS context and server hostname through `start_tls`; its
[connection-pool contract](https://www.encode.io/httpcore/connection-pools/)
defines the separate backend/context injection points. Actual installed-package
behaviour and negative native tests, rather than those interfaces alone,
establish the candidate's observed enforcement.

DNS-policy cases independently exercise blocked address classes, IPv4-mapped
private addresses, empty/malformed responses and mixed public/private answers.
The full answer set must pass before connection; choosing a public first answer
must not conceal a prohibited later answer. Verify that connection uses the
validated address rather than resolving the original hostname again. Recheck
each redirect's destination and refuse HTTPS downgrade. Preserve the same
absolute deadline across redirect connections and TLS upgrades; a new phase
must not receive a fresh complete budget.

## Failure behaviour and acceptance oracles

Use distinct positive and negative peers so a connection refusal cannot stand
in for successful certificate/hostname rejection. Observe server-side handshake,
SNI/request state or socket admission as appropriate. Bound fixture listener,
thread/process and subprocess lifetime; stop owned resources on failure. No test
may retry indefinitely or depend on a live operational endpoint.

Native negative peers exposed a baseline error-mapping defect: the exception
handler named `httpcore.HTTPError`, which does not exist in the installed library,
so a transport failure could be replaced by an unrelated attribute error. Map the
documented transport exception families to the existing bounded public failure;
do not describe the old error-path behaviour as verified TLS handling. The URL
check also treated explicit port zero as a default because it used truthiness.
Distinguish an omitted port from zero and reject zero under the existing 80/443
policy. This closes an input-policy inconsistency; it does not establish a prior
private-network exploitation path.

## Resolver IPC decision

A native partial-frame counterexample exposed a second deadline boundary: the
old parent waited for pipe readability and then called blocking `recv`. A child
that made only part of a framed message readable held a nominal 0.5 s deadline
for approximately 1.6 s in the controlled experiment. Readability does not mean
that the complete message is available, so the old sequence did not establish
the claimed whole-receive bound. This is a reproducible fault-injection case,
not evidence that an operational DNS publisher exercised it.

Compare the implementation choices:

- Keep `poll` followed by blocking receive. This retains the observed gap even
  if the declared message length is bounded; reject it.
- Read framed data through nonblocking OS descriptors and deadline-controlled
  readiness. This can enforce the bound but adds platform-specific descriptor
  and framing logic to maintain.
- Replace the pipe with an atomic Unix datagram/sequence-packet channel. This
  avoids partial-frame blocking but requires Unix sockets and another platform
  assumption; some supported execution environments deny AF_UNIX.
- Keep the private standard multiprocessing pipe, move bounded `recv_bytes`
  into one owned receiver thread and wait through a queue using the remaining
  absolute budget. Choose this portable API construction without claiming
  unexecuted platform compatibility.

The child serializes JSON through `send_bytes`; the parent decodes only bounded
JSON, never a received pickle. Limits are 64 answers, 4096 packet bytes and
64 characters per address. Reject the entire excessive or malformed result with
`DNS_LIMIT` or the appropriate bounded validation failure; do not truncate away
a prohibited answer to make the remainder admissible. The queue wait controls
complete reception, not merely arrival of a framing prefix.

The resolver owns one short-lived child and receiver thread. Finally cleanup
terminates and joins the child, escalates to kill when necessary, joins the
receiver and closes its endpoints. If ownership termination cannot be observed,
report a distinct cleanup failure rather than success. A daemon receiver is a
last-resort interpreter-exit safeguard, not evidence that a surviving thread is
harmless or that cleanup succeeded. Normal completion still requires observed
thread/process termination.

Process creation and bounded cleanup add overhead outside the remaining-message
wait. Cleanup allows up to 1 s for the initial child join, another 1 s after kill
if required, and 1 s for the receiver join. Process startup is not independently
hard-bounded by the queue timeout; the external process supervisor remains an
aggregate containment boundary. A
Python-level result cap is not a bound on libc/NSS's allocation or processing of
the raw `getaddrinfo` result. The OS resolver, NSS implementation and absence of
unowned descendants retaining IPC handles remain trust assumptions. The selected
native tests establish the tested runtime only, not all platforms using these
APIs.

Malformed names, certificate failures, blocked destinations, TLS stalls and body
stalls must return bounded public errors without URL, certificate paths, private
keys, resolver exception strings or raw peer content. A native deadline test must
observe actual waiting/I/O and elapsed bounds, not merely assert a timeout option
was passed. A DNS subprocess test must distinguish missing answers, blocked data
and deadline failure; fake answers alone do not establish subprocess termination.

Test status must distinguish local transport unit cases from PostgreSQL-backed
application integration and the manually executed service fixture. No new model,
cloud, database migration, credential or MCP tool follows from this decision.
If a test exposes a reachable production defect, add a narrowly scoped fix with
a failing-before/passing-after regression and preserve the authority contract.
The TLS negatives and explicit-zero-port regression allocate the two corrections
above; native candidate execution remains the evidence for their closure.

## Consequences, limits and reversibility

The suite needs native TLS/OpenSSL and socket support. Unavailable prerequisites
are visible missing execution, not successful negative tests. Certificate and IP
classification behaviour can depend on the pinned runtime/dependency versions;
bind results to their actual candidate revision and wheel. A trusted OS/network
stack, fixture harness and dependency implementation remain assumptions.

These cases do not establish Internet resolver correctness, universal PKI trust,
revocation/OCSP policy, hostile kernel resistance, network egress confinement,
operational TLS configuration, external-source quality or complete HTTP/TLS
conformance. The synthetic HTTP service receipt remains distinct and must not be
relabelled as a deployed TLS receipt. Further platform/runtime profiles need
their own tests. No full acquisition or programme acceptance is closed here.

Blast radius is the repository and disposable test state. Removing the fixture
tests or reverting their harness does not require operational rollback, trust
store cleanup or a schema change. A candidate cannot inherit transport assurance
after changing runtime, transport or certificate policy without verifying the
relevant boundaries again. Production verification remains enabled throughout;
rollback is never permission to disable trust checks to make a test green.

## Verification evidence

Bind the exact selected test inventory, installed wheel and runtime to the native
CI receipt. Required evidence includes successful trusted hostname/SNI/Host
handling, rejected untrusted/wrong-host peers without accepted HTTP, blocked
mixed/mapped-private DNS results, connection-time pinning, redirected policy and
native handshake/read deadline enforcement. Report each fixture's injection
boundary and any unexecuted case explicitly. This ADR allocates and bounds that
evidence; a candidate's receipt establishes which cases actually passed.
