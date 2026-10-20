#!/usr/bin/env bash
# Run from the repository root. Only public dependency/configuration files enter
# the container; no Git metadata, environment credentials or operational data.
set -euo pipefail

check_dir=$(mktemp -d /tmp/ow-renovate-check.XXXXXX)
trap 'rm -rf -- "$check_dir"' EXIT
mkdir -p "$check_dir/repo/.github/workflows"
cp renovate.json pyproject.toml uv.lock "$check_dir/repo/"
cp .github/renovate.Dockerfile "$check_dir/repo/.github/"
cp .github/workflows/*.yml "$check_dir/repo/.github/workflows/"

docker build --tag ow-renovate-validator --file .github/renovate.Dockerfile .github

check_config() {
    local entrypoint=$1
    shift
    docker run --rm --network none --read-only --cap-drop ALL \
        --security-opt no-new-privileges --user "$(id -u):$(id -g)" \
        --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777 \
        --env RENOVATE_CACHE_DIR=/tmp/renovate-cache --env LOG_FORMAT=json \
        --volume "$check_dir/repo:/app:ro" --workdir /app \
        --entrypoint "$entrypoint" ow-renovate-validator "$@"
}

check_config renovate-config-validator --strict --no-global /app/renovate.json

# The standalone validator does not resolve extends. The local platform reads
# renovate.json as repository config and stops before lookup, updates or PRs.
# This pinned experimental exit flag is essential: the default CLI exits zero
# even when a repository stops with a configuration error.
local_args=(--platform=local --dry-run=extract --exit-code-for-errors \
    --base-dir=/tmp/renovate --cache-dir=/tmp/renovate-cache)
if ! check_config renovate "${local_args[@]}" > "$check_dir/valid.log" 2>&1; then
    cat "$check_dir/valid.log"
    exit 1
fi
python3 - "$check_dir/valid.log" <<'PY'
import json
import pathlib
import sys

records = [json.loads(line) for line in pathlib.Path(sys.argv[1]).read_text().splitlines()]
extractions = [r for r in records if r.get("msg") == "Dependency extraction complete"]
if len(extractions) != 1:
    raise SystemExit("Expected one completed repository dependency extraction")
managers = extractions[0]["stats"]["managers"]
for name in ("pep621", "github-actions", "dockerfile", "custom.regex"):
    if managers.get(name, {}).get("depCount", 0) < 1:
        raise SystemExit("Expected dependency extraction from manager: " + name)
if managers["custom.regex"]["depCount"] != 2:
    raise SystemExit("Expected both pinned disposable Compose images")
print("All four configured dependency managers extracted real dependencies")
PY

# A real negative control: an unknown built-in preset must produce the pinned
# configuration-error exit code, not a generic Docker/infrastructure failure.
python3 -c 'import json,sys; json.dump({"extends": [":pinDigests"]}, open(sys.argv[1], "w"))' \
    "$check_dir/repo/renovate.json"
set +e
check_config renovate "${local_args[@]}" > "$check_dir/invalid.log" 2>&1
invalid_status=$?
set -e
if [ "$invalid_status" -ne 5 ]; then
    cat "$check_dir/invalid.log"
    echo "Unknown preset did not produce the expected configuration-error exit (5)" >&2
    exit 1
fi
python3 - "$check_dir/invalid.log" <<'PY'
import pathlib
import sys

message = "Cannot find preset's package (:pinDigests)"
if message not in pathlib.Path(sys.argv[1]).read_text():
    raise SystemExit("Unknown preset failed for an unexpected reason")
print("Unknown preset rejected with the expected configuration error")
PY
