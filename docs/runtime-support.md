# Python and Ubuntu support

The package permits standard, GIL-enabled CPython 3.12–3.14 on Linux. Required
release qualification covers the two native Ubuntu LTS profiles below; 3.13
has optional compatibility coverage. Python
3.12 remains the minimum language and Ruff target. Do not infer support for
free-threaded builds, other interpreters, GPU stacks or additional architectures
from a universal Python wheel or an available dependency wheel.

## Native Ubuntu installation

Python 3.14 is not the application's minimum and is not required on Ubuntu 24.04.
Use each LTS release's distribution-maintained system interpreter: Python 3.12 on
24.04 and Python 3.14 on 26.04. The Ubuntu `python3` package catalogues were
rechecked on 2026-10-19. Supporting 3.14 is necessary to accept the default 26.04
interpreter; requiring 3.14 everywhere would unnecessarily replace the 24.04
runtime. Keep the package bound `>=3.12,<3.15` and the 3.12 language target.

For the root-owned reference installation, provision the distribution's
`python3` and `python3-venv` packages, then create the isolated environment with
that interpreter:

```sh
sudo apt-get install python3 python3-venv
sudo /usr/bin/python3 -m venv /opt/osint-workbench/venv
/opt/osint-workbench/venv/bin/python -c 'import sys; print(sys.version); print(sys.base_prefix)'
```

Install the reviewed locked dependencies and application wheel into this venv
under the [deployment procedure](deployment.md#scope-and-authority). Do not alter
`/usr/bin/python3`, use interpreter alternatives to replace it, or install Python
packages into the system environment. This is native Linux execution in a venv;
no container or separate managed interpreter is required for the reference service.
The two required CI profiles below verify native LTS compatibility; they do not impose Python 3.14
on 24.04. Optional native inference dependencies still need their declared
artifacts and acceptance; creating a venv does not install the complete stack.

## Required verification profiles

| Runner | Python | Purpose |
| --- | --- | --- |
| Ubuntu 24.04 x86-64 | CPython 3.12 | Older LTS default and minimum runtime |
| Ubuntu 26.04 x86-64 | CPython 3.14 | Newer LTS default and preferred runtime on that LTS |

Foundation CI builds and installs the wheel, verifies the core without optional
inference dependencies, and executes the full native CPU/database suite in every
profile. Each profile has its own PostgreSQL 18/pgvector service and native server
build. PostgreSQL remains an explicitly provisioned dependency; the host's default
database version is not the application contract. Tests generate synthetic ONNX/GGUF
weights; no pretrained inference weights or provider requests are used. Explicit
native source preparation downloads the pinned source archive, which includes
upstream vocabulary/test fixtures. The stable required `installed-artifact` check succeeds only
when both required LTS profiles succeed; skipped, cancelled or failed required work is
not accepted. See [the workflow](../.github/workflows/ci.yml) and its same-commit
[reusable verifier](../.github/workflows/installed-profile.yml).

These are verification profiles, not an assertion that every revision passed.
Use the exact source revision and completed job results as evidence. The
[deployment diagnostic](../.github/workflows/public-encoder-diagnostic.yml)
separately exercises the actual collector service and sandbox on both Ubuntu
releases using `/usr/bin/python3`. It remains an explicit disposable-runner
operation, with the limits in [deployment](deployment.md). Ordinary test-suite
unit parsing does not establish systemd confinement or timer behavior.

Do not replace the OS Python or install into its externally managed environment.
Use a dedicated virtual environment. Service environments must use a reviewed
base interpreter under `/usr` or `/opt`, readable with `ProtectHome=yes`; a
home-directory-managed interpreter is unsuitable for this reference unit.
The foundation matrix uses uv-selected patch releases; the manual service profile
uses the distribution-maintained system interpreter. A distro version string alone
does not establish absence of vendor security backports. Neither profile replaces
the OS Python. The core collector sandbox is not an inference-worker deployment template.

## Optional interpreter diagnostics

The [separate compatibility workflow](../.github/workflows/python-compatibility.yml)
runs the full 24.04/3.13 installed/native procedure weekly or by explicit dispatch.
It shares the reusable verifier with the required LTS jobs, but uses distinct
`compatibility-evidence` artifacts. Its failure remains visible and does not block
merges or signing; no `continue-on-error` converts it into success. The signer
requires exactly the two same-run LTS sets and rejects optional substitutes.

Dispatch `profile=3.13`, `3.15-dependencies` or `both`. The weekly schedule selects
only 3.13; GitHub scheduling is best effort. The 3.15 probe only attempts the
existing hashed runtime/retrieval dependency wheels under standard CPython 3.15.
The report records the exact interpreter version and release level selected by
the pinned tool; a prerelease is not final-release evidence. It installs no
application, performs no source builds, changes no production
lock/bounds and does not ignore `Requires-Python`. A successful dependency probe
is not application acceptance; unavailable wheels or incompatible locked packages
are genuine failed probe results. Neither diagnostic has signing permissions.
A new workflow must be present on the default branch before its dispatch is
available. See [ADR-0050](adr/0050-required-lts-and-optional-python-profiles.md).

## Compatibility boundaries

Timestamp admission validates RFC 3339 clock and offset components before
calling the interpreter's ISO parser. Interpreter normalization must not broaden
the input contract: `24:00:00`, leap seconds and out-of-range offset components
remain rejected. Valid fractions, explicit offsets and UTC normalization retain
their tested meaning.

TLS verification retains native certificate-chain and hostname checks. The
synthetic test CA explicitly declares CA constraints and signing usage, with
subject/authority key identifiers. Fix fixture certificates instead of disabling
strict verification to make a new interpreter pass. Address admission, DNS
process isolation, absolute deadlines, resource limits, numerical model execution,
MCP and retained-state migrations are exercised across the runtime matrix.

Optional CPU retrieval dependencies must resolve to reviewed compatible artifacts.
Their availability is not pretrained model-quality or performance evidence.
Python 3.15 requires a separate compatibility decision; a new upstream release
does not silently extend this support range. See [ADR-0035](adr/0035-python-ubuntu-runtime-support.md).

## Maintenance and rollback

Update runtime bounds and `uv.lock` together. Preserve the hashed build closure
and verify installed artifacts on all required profiles. Review native source and
action/tool updates independently; do not change native revision and checksum
separately. The advisory workflow queries locked runtime dependencies for all three
declared interpreter versions so platform markers do not hide a profile.

Rollback uses a reviewed compatible wheel and its lock in a staged environment.
Stop affected processes before switching environments. This change adds no SQL
migration and authorizes no OS upgrade or operational deployment. A package
rollback must still respect current schema and policy semantics; preserve the
original source-bound receipts rather than relabeling them.

The audit baseline `d01f80ac88da50c9f826b1a15cb18c75bd1db75f` completed
[foundation CI](https://github.com/rmednitzer/osint-workbench/actions/runs/39133727926)
with all required profiles successful. This is installed/native suite evidence,
not a systemd-service receipt. The separate
[core-10 two-LTS service receipt](testing/documentation-service-2026-10-18.json)
records both protected distro interpreters at source `ebdbf666e0f4001dca59ce8760386aae80408d61`.
Its fixture and wheel scope remains separate from foundation CI and operational
acceptance; earlier service receipts retain their older source and wheel.

The [operational service successor](testing/operational-service-2026-10-18.json)
adds actual worker/health account, custody, failure/recovery and accelerated timer
acceptance on both LTS defaults at `d4a1e64be1e399eb052db13f35ddcf0fc5234b81`.
It uses the protected system interpreters and core dependencies, with no pretrained
model or provider dispatch. Its exact installed wheel is recorded; it does not
replace the required two-LTS installed/native application suite.

The [2026-10-19 dependency successor](testing/lock-maintenance-service-2026-10-19.json)
records both actual service and independent credential-isolation passes in run
`39218774672` at `237660c057a5512221f2216430e6b2bf6bd2650b`. The protected
system interpreters report 3.12.3 on 24.04 and 3.14.4 on 26.04. Its wheel,
updated dependency lock and harness hashes are bound separately from full
foundation CI. These native service passes preserve the 3.12 minimum; they do
not require replacing the interpreter on either LTS release.
