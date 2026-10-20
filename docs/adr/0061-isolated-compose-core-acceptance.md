# ADR-0061: Opt-in isolated Compose core acceptance

Status: ACCEPTED for a disposable synthetic test profile. Date: 2026-10-20.
Execution evidence belongs to the exact source, wheel and image receipt.

## Context and decision drivers

Native foundation checks and the systemd reference do not establish application
container behavior. The project had no application Dockerfile or Compose profile.
A first target-host test must distinguish functional mechanics from operational
adoption, and must not reuse an existing database, evidence tree, credential,
network, inference service or source catalogue.

The acceptance boundary is synthetic text import, durable chunk processing,
lexical/evidence reads, seven stdio MCP tools, authority denial, restart and isolated
checkpoint/current-policy recovery. Collection, retrieval/inference, cloud routes,
GPU scheduling, dashboards and sustained operation remain separate profiles.

## Alternatives

- No change: leaves container execution unavailable as evidence.
- Wrap the whole native test suite in a privileged container: broadens authority,
  hides process/host assumptions and does not define runtime role separation.
- Use an existing host database or inference deployment: couples test failures and
  credentials to operational state; rejected.
- **Selected:** an explicit disposable Compose project with pinned images, staged
  offline installation inputs, distinct runtime identities and guarded teardown.

## Build and trust boundaries

The runtime base is the reviewed Linux amd64 Python 3.12.14 slim-trixie manifest
`sha256:44ff437bba879d4941b710a369a8f19266aea34b29002807f0c487fabc9eec9b`.
Its upstream recipe identifies docker-library/python revision
`688a0b86bb44289df16a363e9f41d90514c1a5f9`, Python source digest verification
and build-time signature checking. This repository consumes the immutable image;
it does not claim to have reproduced that upstream build. The upstream recipe
licence is MIT. That is not complete Python, Debian or image redistribution clearance.

PostgreSQL uses the existing digest-pinned PostgreSQL 18/pgvector image. Build
preparation explicitly obtains public images and locked dependency wheels. The
application build installs its separately hash-verified wheel and core-only,
hash-locked dependencies without package-network access. No apt upgrade, mutable
image tag, editable source installation or runtime dependency download is required.
A receipt binds the source, artifact, requirement export, input wheels, image ID
and profile scripts. Capturing inputs is not proof of byte-reproducible upstream
images or complete OS/native/model SBOM coverage.

The base uses Debian and upstream CPython rather than either distro-maintained
Ubuntu interpreter. This is a distinct, exact container test profile. Required
native Ubuntu 24.04/3.12 and 26.04/3.14 qualification remains unchanged; other
container architectures and runtimes are unqualified. Docker/registry and Python
supply-chain dependencies remain foreign upstreams. Local execution and portable
OCI inputs support operator custody, mirroring and exit, not an EU-controlled
supply-chain or sovereignty-conformance claim. No private test data is uploaded.

## Runtime, authority and effects

A uniquely named project and run nonce own every test container, network and
volume. The harness refuses resource collisions and adopted/shared volumes. It creates
its fresh labelled volumes explicitly before Compose uses them; `external: true`
in the Compose file assigns lifecycle ownership to the harness, not to an existing
installation.
Runtime containers use an internal network with no published host ports, host
network/PID namespace, Docker socket, device/GPU mapping or privileged mode.
Application roots are read-only, temporary storage and memory/CPU/PIDs are bounded,
and runtime capabilities are dropped with no-new-privileges enabled.

Writer, worker, reader, lifecycle and recovery identities have distinct Unix and
SQL credentials. Writer and worker retain the existing `ow_writer` database
capability; a new login is not narrower SQL authority. Synthetic import uses writer
authority and does not establish collector-role or HTTP acquisition acceptance.
Writer-owned shared evidence uses the explicitly selected primary read GID;
worker and reader mounts are read-only. Only each role's credential is mounted.
Compose file-secret ownership declarations are not relied upon: real consuming UID
access and missing cross-role credentials are tested. The Docker administrator
and host root remain trusted and can inspect all container secrets and data.

Bootstrap is a narrowly scoped provisioning effect on fresh project-owned empty
volumes, not a root application runtime or a permission-repair command. Recovery
creates private content. Any later shared access to restored synthetic evidence
requires an explicit fixed-path, verified fresh-copy custody transition; no existing
operational tree is adopted or recursively repaired implicitly.

## Acceptance, failure and rollback

Actual installed CLI and MCP processes must establish import, chunk identities,
evidence integrity, reader SQL/filesystem denials and exactly seven stdio tools.
Restart PostgreSQL and create new application processes before checking durable
state. Capture a checkpoint, make a later lifecycle decision, retain the current
policy separately and restore into a distinct empty database and absent CAS root.
Validate policy refusal/suppression, disabled restored sources and representative
surviving reads. A successful database healthcheck alone is not acceptance.

Cleanup must verify exact project/run ownership before removing only its containers,
network and marked disposable volumes. A failure preserves a fixed error and
private diagnostic context; it must not remove other projects, prune the daemon,
reset existing jobs or widen permissions. Compare preexisting container identities
and running state after the host exercise. Public receipts exclude host names,
paths, inventories, credentials, checkpoint/policy bytes and operational output.

Stop and remove the owned disposable project to roll back execution. No application
migration, existing data, host account, firewall or service configuration is changed.
Revert profile files through a protected PR if needed. This profile is not a
production Compose distribution, live collection acceptance, pretrained quality,
full-host recovery, physical erasure or sustained-capacity qualification.
