# Python and Ubuntu support

The package supports standard, GIL-enabled CPython 3.12–3.14 on Linux. Python
3.12 remains the minimum language and Ruff target. Do not infer support for
free-threaded builds, other interpreters, GPU stacks or additional architectures
from a universal Python wheel or an available dependency wheel.

## Required verification profiles

| Runner | Python | Purpose |
| --- | --- | --- |
| Ubuntu 24.04 x86-64 | CPython 3.12 | Older LTS default and minimum runtime |
| Ubuntu 24.04 x86-64 | CPython 3.13 | Intermediate declared-runtime compatibility |
| Ubuntu 26.04 x86-64 | CPython 3.14 | Newer LTS default and preferred runtime on that LTS |

Foundation CI builds and installs the wheel, verifies the core without optional
inference dependencies, and executes the full native CPU/database suite in every
profile. Each profile has its own PostgreSQL 18/pgvector service and native server
build. PostgreSQL remains an explicitly provisioned dependency; the host's default
database version is not the application contract. Tests generate synthetic ONNX/GGUF
weights; no pretrained inference weights or provider requests are used. Explicit
native source preparation downloads the pinned source archive, which includes
upstream vocabulary/test fixtures. The stable required `installed-artifact` check succeeds only
when the complete matrix succeeds; skipped, cancelled or failed matrix work is
not accepted. See [the workflow](../.github/workflows/ci.yml).

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
replace the three-profile installed/native application suite.
