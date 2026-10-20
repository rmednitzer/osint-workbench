# Disposable Compose core acceptance

This opt-in profile tests a synthetic core installation in Docker Compose. It is
not a production stack, source collector, browser, model deployment or remote MCP
server. Nothing runs during import, ordinary pytest or installation. See
[ADR-0061](adr/0061-isolated-compose-core-acceptance.md) for decisions and limits.

## Preconditions and approved effects

Use a Linux amd64 host with an operator-controlled local Docker Engine and Compose.
The test creates a fresh uniquely named image, internal network and disposable
volumes, then removes its owned resources. It never adopts an existing database or
evidence directory. The Docker administrator and host root remain trusted.
Existing host services, firewall/account configuration and inference workloads are
outside the test. Do not grant a container the Docker socket or host namespaces.

The runtime image is pinned Python 3.12.14 on Debian trixie; the database is the
existing pinned PostgreSQL 18/pgvector image. This is an additional exact container
profile, not a replacement for native Ubuntu LTS qualification. Rootless engines,
user-namespace remapping, Docker Desktop, remote daemons, other architectures and
Swarm are unqualified. The runner refuses ambient Docker/Compose override variables
and requires a local Unix-socket context; inspect that context before running.

Stage these reviewed public inputs outside the checkout:

- A built `osint_workbench-0.1.0.dev1-py3-none-any.whl` and its independently reviewed
  SHA-256, preferably from the exact-main signed evidence.
- A core-only hash-locked export from the same `uv.lock` (`--no-dev`, no extras,
  `--no-emit-project`), plus its selected dependency wheels.
- Both exact base images below, explicitly acquired before acceptance.

```sh
docker pull --platform linux/amd64 python:3.12.14-slim-trixie@sha256:44ff437bba879d4941b710a369a8f19266aea34b29002807f0c487fabc9eec9b
docker pull --platform linux/amd64 pgvector/pgvector:pg18@sha256:2358fcba361ed2233a5ed81b5fe4ca779ccb304120ce531a3bf51c0ed7e2bc11
uv export --locked --no-dev --no-emit-project --output-file /private/test-inputs/core-requirements.txt > /dev/null
```

Dependency acquisition is an explicit preparation step. Use the pinned Python base
and pip's `--only-binary=:all: --require-hashes` with the core export to populate the
wheelhouse. Bind only the public requirements file read-only and a new output
directory into that preparation container; do not mount host credentials, a source
registry or the whole private staging directory. Preparation may contact public
package registries. The application build itself uses `--network=none`,
`--no-index` and hashes; runtime acceptance has no live acquisition or cloud route.
Do not substitute an editable checkout or synchronize the verification environment.

Upstream images and packages remain foreign supply-chain dependencies. Local
runtime custody and portable OCI inputs support mirroring and exit; they do not
establish EU-controlled upstream builds, complete native/OS notices or legal
redistribution clearance. The upstream Python recipe source and MIT licence were
reviewed at its immutable source revision named in ADR-0061. No image is published
by this harness.

## Execute the bounded test

Run from the matching reviewed checkout, using an explicit new private work path
outside it. Replace every uppercase argument below deliberately. A previously
used path is refused; retain its private diagnostics before choosing another path.

```sh
python3 scripts/test_compose_core.py \
  --acknowledge-disposable-containers \
  --workdir NEW_EXTERNAL_PRIVATE_DIRECTORY \
  --wheel REVIEWED_WHEEL_FILE \
  --wheel-sha256 REVIEWED_WHEEL_SHA256 \
  --core-lock CORE_REQUIREMENTS_FILE \
  --wheelhouse LOCKED_WHEELHOUSE_DIRECTORY \
  --source-revision REVIEWED_SOURCE_COMMIT
```

Docker authority stays with the host runner. Runtime writer, worker, reader,
lifecycle and recovery containers use distinct Unix identities and credentials.
Writer and worker SQL logins both inherit existing `ow_writer` authority; they are
not newly constrained database roles. The provisioning login temporarily has the
fixture database's administrative authority and is not mounted into consumers.
Non-root PostgreSQL runs as its inspected numeric image identity.

A short-lived, network-disabled bootstrap initializes only fresh owned volumes.
The writer creates explicitly group-readable evidence; worker and reader have
read-only mounts. Compose file-based secrets are bind mounts, so declared secret
UID/GID/mode must not be mistaken for enforcement. Only each role's credential file
is mounted, read-only; files stay behind a private host directory. Tests verify
access through the actual consuming UID and the absence of foreign credentials.
The launcher adapts fixed role credentials to the CLI's existing DSN environment
contract. It adds no generic shell, arbitrary SQL, model or URL interface.

Resource limits, read-only application roots, dropped runtime capabilities,
no-new-privileges, no published ports and internal networking are checked against
Docker's effective container/network configuration. Bootstrap's explicitly scoped
ownership capabilities do not belong to runtime consumers. Memory and CPU bounds
are test limits, not production sizing or an SLO.

## Acceptance and recovery evidence

The runner must establish:

1. Two synthetic text imports, actual chunk-worker results and verified lexical
   document/evidence reads, with no collection or provider request.
2. Exactly seven stdio MCP tools through a real client and installed CLI, including
   invalid-selector refusal and reader authority checks. An empty cited digest is
   a fixture product, not accepted semantic intelligence.
3. Reader/worker evidence write denial and role-only credential custody.
4. Database restart plus fresh application processes preserving accepted identities,
   chunks and job state.
5. A private checkpoint followed by a later lifecycle retirement and separately
   captured current policy. Invalid digests or rolled-back policy must refuse
   before accepting restored rows or creating the new CAS root.
6. Restore into a distinct empty migrated database and absent object root. Restored
   sources remain disabled and jobs quarantined. A separate explicit bootstrap
   copies verified restored bytes into a fresh shared synthetic tree before the
   independent restored reader verifies surviving content and retired refusal.
7. Ownership-checked removal of test resources, leaving unrelated containers and
   volumes untouched.

The receipt binds source revision, wheel/core-lock hashes, immutable base images,
local image ID and exact profile-file hashes. It records the tested scope and
cleanup outcome. Keep full host diagnostics and any checkpoint/policy or credential
files private. A public successor receipt must remove host identity, paths,
inventory and operational output; a source scanner is only a backstop.

## Failure and rollback

A failed step is not acceptance. Inspect the fixed phase/error and private work
files, reconcile remaining resources using their exact project/run ownership, and
preserve evidence before retrying with a new work path. Never run a daemon-wide
prune or delete a similarly named unrelated volume. If ownership is missing or
conflicting, cleanup must refuse that resource for operator reconciliation.

The runner owns its disposable project and performs guarded teardown. Removing
those owned resources rolls back test execution; no host account, firewall,
existing database, evidence tree or published migration is changed. Public base
image caches may remain and can be shared by other work; do not remove them as
unrelated cleanup. Quiesce the test before changing its files or credentials.

This does not establish live source/API acceptance, model usefulness, remote MCP,
monitoring/notification delivery, sustained capacity, backup scheduling, independent
policy custody, full-host recovery or physical all-copy deletion. Continue the
[operational adoption gates](operational-profile.md) separately.

Primary container contracts: [Compose services](https://docs.docker.com/reference/compose-file/services/),
[internal networks](https://docs.docker.com/reference/compose-file/networks/), and
[file-backed secrets](https://docs.docker.com/compose/how-tos/use-secrets/).
