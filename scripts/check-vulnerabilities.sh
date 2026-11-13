#!/usr/bin/env bash
set -euo pipefail
architecture=${1:?usage: check-vulnerabilities.sh ARCHITECTURE}
lock="artifacts/locks/${architecture}.json"
builder=$(python3 scripts/artifacts.py base-reference "${lock}" builder)
# build-image.sh already verified the publisher signature and pulled this pin.
# Query tooling is ephemeral and never enters the runtime image.
podman run --rm --pull=never --platform "linux/${architecture}" \
    --volume "${PWD}:/work:Z" --workdir /work --entrypoint bash "${builder}" \
    -c 'set -e; microdnf install -y dnf dnf-plugins-core; python3 scripts/scan-gate.py security-results --architecture "$1" --lock "artifacts/locks/$1.json"' \
    -- "${architecture}"
