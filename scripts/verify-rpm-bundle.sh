#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 LOCK BUNDLE [--include-sources]" >&2
    exit 2
}

[[ $# -eq 2 || $# -eq 3 ]] || usage
lock=$1
bundle=$2
include_sources=${3:-}
[[ -z "${include_sources}" || "${include_sources}" == "--include-sources" ]] || usage

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
verify_args=(verify-bundle --lock "${lock}" --bundle "${bundle}")
if [[ "${include_sources}" == "--include-sources" ]]; then
    verify_args+=(--include-sources)
fi
"${PYTHON:-python3}" "${script_dir}/artifacts.py" "${verify_args[@]}"

rpmdb=$(mktemp -d)
cleanup() {
    rm -rf -- "${rpmdb}"
}
trap cleanup EXIT

while IFS=$'\t' read -r filename fingerprint sha256; do
    [[ "${filename}" == "filename" ]] && continue
    gpg --batch --show-keys --with-colons "${bundle}/keys/${filename}" \
        | awk -F: -v expected="${fingerprint}" \
            '$1 == "fpr" && $10 == expected { found = 1 } END { exit !found }' || {
        echo "signing key fingerprint mismatch: ${filename}" >&2
        exit 1
    }
    echo "${sha256}  ${bundle}/keys/${filename}" | sha256sum --check --status
    rpm --define "_dbpath ${rpmdb}" --import "${bundle}/keys/${filename}"
done < "${bundle}/key-manifest.tsv"

while IFS=$'\t' read -r filename name epoch version release architecture source_rpm fingerprint sha256; do
    [[ "${filename}" == "filename" ]] && continue
    package="${bundle}/rpms/${filename}"
    echo "${sha256}  ${package}" | sha256sum --check --status
    rpm_signature=$(rpm -qp --queryformat \
        $'%{RSAHEADER:pgpsig}\n%{DSAHEADER:pgpsig}\n%{SIGPGP:pgpsig}\n%{SIGGPG:pgpsig}\n' \
        "${package}" 2>/dev/null)
    grep -Eqi "key ID [[:xdigit:]]*${fingerprint: -8}" <<< "${rpm_signature}" || {
        echo "RPM signer does not match the lock: ${filename}" >&2
        exit 1
    }
    signature_result=$(rpm --define "_dbpath ${rpmdb}" --checksig "${package}")
    grep -Eq ': digests signatures OK$' <<< "${signature_result}" || {
        echo "RPM signature verification failed: ${filename}" >&2
        exit 1
    }
    actual=$(rpm -qp --queryformat $'%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}' \
        "${package}" 2>/dev/null)
    expected="${name}"$'\t'"${epoch}"$'\t'"${version}"$'\t'"${release}"$'\t'"${architecture}"$'\t'"${source_rpm}"
    [[ "${actual}" == "${expected}" ]] || {
        echo "RPM metadata does not match the lock: ${filename}" >&2
        exit 1
    }
done < "${bundle}/rpm-manifest.tsv"

echo "verified locked RPM bundle: ${bundle}"
