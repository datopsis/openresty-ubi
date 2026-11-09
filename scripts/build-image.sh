#!/usr/bin/env bash
set -euo pipefail

architecture=${1:?usage: build-image.sh ARCHITECTURE IMAGE}
image=${2:?usage: build-image.sh ARCHITECTURE IMAGE}
runtime=${CONTAINER_RUNTIME:-podman}
python=${PYTHON:-python3}
bundle=${ARTIFACT_BUNDLE:-.artifact-bundle/${architecture}}
lock=artifacts/locks/${architecture}.json

case "${architecture}" in
    amd64) machine=x86_64 ;;
    arm64) machine=aarch64 ;;
    *) echo "unsupported architecture: ${architecture}" >&2; exit 2 ;;
esac

test "$("${runtime}" info --format '{{.Host.Arch}}')" = "${architecture}"
test "$(uname -m)" = "${machine}"
"${python}" scripts/artifacts.py validate-lock "${lock}" \
    --inputs artifacts/lock-inputs.json
bash scripts/verify-rpm-bundle.sh "${lock}" "${bundle}"

builder=$("${python}" scripts/artifacts.py base-reference "${lock}" builder)
runtime_base=$("${python}" scripts/artifacts.py base-reference "${lock}" runtime)
if test "${PULL_BASES:-1}" = 1; then
    "${python}" scripts/verify-bases.py --architecture "${architecture}" --keys "${bundle}/keys"
    "${runtime}" pull --platform "linux/${architecture}" "${builder}"
    "${runtime}" pull --platform "linux/${architecture}" "${runtime_base}"
fi
"${runtime}" image exists "${builder}"
"${runtime}" image exists "${runtime_base}"

lock_sha256=$(sha256sum "${lock}" | cut -d' ' -f1)
"${runtime}" build \
    --file Containerfile \
    --format docker \
    --network none \
    --pull=never \
    --build-context "artifact_bundle=${bundle}" \
    --build-arg "ARTIFACT_LOCK_SHA256=${lock_sha256}" \
    --build-arg "UBI_MINIMAL_IMAGE=${builder}" \
    --build-arg "UBI_MICRO_IMAGE=${runtime_base}" \
    --tag "${image}" \
    .
