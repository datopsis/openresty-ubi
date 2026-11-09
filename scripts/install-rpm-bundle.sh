#!/usr/bin/env bash
set -euo pipefail

bundle=${1:?usage: install-rpm-bundle.sh BUNDLE ROOT}
root=${2:?usage: install-rpm-bundle.sh BUNDLE ROOT}

test -f "${bundle}/key-manifest.tsv"
test -f "${bundle}/rpm-manifest.tsv"
test -d "${bundle}/keys"
test -d "${bundle}/rpms"
test ! -e "${root}"
test -z "$(find "${bundle}" -type l -print -quit)"
test "$(find "${bundle}" -mindepth 1 -maxdepth 1 -type f | wc -l)" -eq 3
test "$(find "${bundle}" -mindepth 1 -maxdepth 1 -type d | wc -l)" -eq 2
test -z "$(find "${bundle}/keys" "${bundle}/rpms" -mindepth 1 ! -type f -print -quit)"

rpmdb=$(mktemp -d)
expected_packages=$(mktemp)
actual_packages=$(mktemp)
cleanup() {
    rm -rf -- "${rpmdb}" "${expected_packages}" "${actual_packages}"
}
trap cleanup EXIT

expected_key_count=0
while IFS=$'\t' read -r filename fingerprint sha256; do
    test "${filename}" != filename || continue
    test -f "${bundle}/keys/${filename}"
    printf '%s  %s\n' "${sha256}" "${bundle}/keys/${filename}" \
        | sha256sum --check --status
    rpm --define "_dbpath ${rpmdb}" --import "${bundle}/keys/${filename}"
    expected_key_count=$((expected_key_count + 1))
done < "${bundle}/key-manifest.tsv"
test "$(find "${bundle}/keys" -maxdepth 1 -type f | wc -l)" -eq "${expected_key_count}"

expected_rpm_count=0
while IFS=$'\t' read -r filename name epoch version release architecture source_rpm fingerprint sha256; do
    test "${filename}" != filename || continue
    package=${bundle}/rpms/${filename}
    test -f "${package}"
    printf '%s  %s\n' "${sha256}" "${package}" | sha256sum --check --status
    rpm_signature=$(rpm -qp --queryformat \
        $'%{RSAHEADER:pgpsig}\n%{DSAHEADER:pgpsig}\n%{SIGPGP:pgpsig}\n%{SIGGPG:pgpsig}\n' \
        "${package}" 2>/dev/null)
    grep -Eqi "key ID [[:xdigit:]]*${fingerprint: -8}" <<< "${rpm_signature}"
    signature_result=$(rpm --define "_dbpath ${rpmdb}" --checksig "${package}")
    grep -Eq ': digests signatures OK$' <<< "${signature_result}"
    actual=$(rpm -qp --queryformat $'%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}' \
        "${package}" 2>/dev/null)
    expected="${name}"$'\t'"${epoch}"$'\t'"${version}"$'\t'"${release}"$'\t'"${architecture}"$'\t'"${source_rpm}"
    test "${actual}" = "${expected}"
    printf '%s\t%s\t%s\t%s\t%s\n' \
        "${name}" "${epoch}" "${version}" "${release}" "${architecture}" \
        >> "${expected_packages}"
    expected_rpm_count=$((expected_rpm_count + 1))
done < "${bundle}/rpm-manifest.tsv"
test "$(find "${bundle}/rpms" -maxdepth 1 -type f -name '*.rpm' | wc -l)" \
    -eq "${expected_rpm_count}"
test "$(find "${bundle}/rpms" -maxdepth 1 -type f ! -name '*.rpm' | wc -l)" -eq 0

mkdir -p "${root}"
rpm --root "${root}" --initdb
rpm --root "${root}" --import "${bundle}"/keys/*
rpm --root "${root}" --install "${bundle}"/rpms/*.rpm

rpm --root "${root}" --query --all \
    --queryformat $'%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n' \
    | awk -F $'\t' '$1 != "gpg-pubkey"' > "${actual_packages}"
sort -o "${expected_packages}" "${expected_packages}"
sort -o "${actual_packages}" "${actual_packages}"
test "$(sha256sum "${expected_packages}" | cut -d' ' -f1)" = \
    "$(sha256sum "${actual_packages}" | cut -d' ' -f1)"

# Retain the verified package identity without retaining RPM tooling or inputs.
install -d -m 0755 "${root}/usr/share/openresty-ubi"
install -m 0444 "${bundle}/rpm-manifest.tsv" \
    "${root}/usr/share/openresty-ubi/rpm-manifest.tsv"

# Verification keys are build inputs, not runtime trust anchors.
rpm --root "${root}" --erase --allmatches gpg-pubkey
