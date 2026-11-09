#!/usr/bin/env bash
set -Eeuo pipefail
trap 'printf "resolver failed at line %s: %s\n" "${LINENO}" "${BASH_COMMAND}" >&2' ERR

architecture=${1:?usage: resolve-lock.sh ARCHITECTURE INPUT_DIR OUTPUT_DIR}
input_dir=${2:?usage: resolve-lock.sh ARCHITECTURE INPUT_DIR OUTPUT_DIR}
output_dir=${3:?usage: resolve-lock.sh ARCHITECTURE INPUT_DIR OUTPUT_DIR}
input_dir=$(realpath "${input_dir}")
output_dir=$(realpath -m "${output_dir}")

case "${architecture}" in
    amd64) rpm_architecture=x86_64 ;;
    arm64) rpm_architecture=aarch64 ;;
    *) printf 'unsupported architecture: %s\n' "${architecture}" >&2; exit 1 ;;
esac

test -d "${input_dir}/rpms"
test -d "${input_dir}/keys"
test -f "${input_dir}/key-manifest.tsv"
test -f "${input_dir}/rpm-seed-manifest.tsv"
test ! -e "${output_dir}"
mkdir -p "${output_dir}/rpms" "${output_dir}/srpms"

# Resolution is an explicitly invoked, networked update operation. Ordinary
# builds consume the reviewed output lock and never run this script.
if command -v microdnf >/dev/null; then
    microdnf install -y dnf dnf-plugins-core gnupg2 >/dev/null
fi
repo_dir=$(mktemp -d)
trap 'rm -rf -- "${repo_dir}" "${resolve_root:-}"' EXIT
for component in baseos appstream codeready-builder; do
    cat >>"${repo_dir}/locked.repo" <<EOF
[ubi-9-${component}-rpms]
name=UBI ${component}
baseurl=https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/${rpm_architecture}/${component}/os/
enabled=1
gpgcheck=1
[ubi-9-${component}-source-rpms]
name=UBI ${component} sources
baseurl=https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/${rpm_architecture}/${component}/source/SRPMS/
enabled=0
gpgcheck=1
EOF
done
cat >>"${repo_dir}/locked.repo" <<EOF
[openresty-stable]
name=OpenResty
baseurl=https://openresty.org/package/rhel/9/${rpm_architecture}/
enabled=1
gpgcheck=1
gpgkey=file://${input_dir}/keys/pubkey2.gpg
EOF
dnf() { command dnf --setopt="reposdir=${repo_dir}" "$@"; }

expected_key_count=0
while IFS=$'\t' read -r filename fingerprint sha256; do
    test -f "${input_dir}/keys/${filename}"
    printf '%s  %s\n' "${sha256}" "${input_dir}/keys/${filename}" | sha256sum --check --status
    gpg --batch --show-keys --with-colons --with-fingerprint \
        "${input_dir}/keys/${filename}" \
        | awk -F: '$1 == "fpr" { print $10 }' \
        | grep --fixed-strings --line-regexp "${fingerprint}" >/dev/null
    expected_key_count=$((expected_key_count + 1))
done <"${input_dir}/key-manifest.tsv"
actual_key_count=$(find "${input_dir}/keys" -maxdepth 1 -type f | wc -l)
test "${actual_key_count}" -eq "${expected_key_count}"

expected_seed_count=0
while IFS=$'\t' read -r filename sha256; do
    test -f "${input_dir}/rpms/${filename}"
    printf '%s  %s\n' "${sha256}" "${input_dir}/rpms/${filename}" | sha256sum --check --status
    expected_seed_count=$((expected_seed_count + 1))
done <"${input_dir}/rpm-seed-manifest.tsv"
actual_seed_count=$(find "${input_dir}/rpms" -maxdepth 1 -type f -name '*.rpm' | wc -l)
test "${actual_seed_count}" -eq "${expected_seed_count}"

rpm --import "${input_dir}"/keys/*
rpm --checksig "${input_dir}"/rpms/*.rpm

resolve_root=$(mktemp -d)
mkdir -p "${resolve_root}"
rpm --root "${resolve_root}" --initdb
rpm --root "${resolve_root}" --import "${input_dir}"/keys/*
dnf install -y \
    --forcearch="${rpm_architecture}" \
    --downloadonly \
    --downloaddir="${output_dir}/rpms" \
    --installroot="${resolve_root}" \
    --releasever=9 \
    --setopt=localpkg_gpgcheck=1 \
    --setopt=install_weak_deps=0 \
    --setopt=keepcache=0 \
    "${input_dir}"/rpms/*.rpm \
    ca-certificates tzdata
cp "${input_dir}"/rpms/*.rpm "${output_dir}/rpms/"

query_format='%{repoid}|%{location}'
binary_inventory="${output_dir}/binary-inventory.tsv"
: >"${binary_inventory}"

find_url() {
    local spec=$1
    local mode=${2:-binary}
    local result result_count
    if test "${mode}" = source; then
        result=$(dnf repoquery --forcearch="${rpm_architecture}" --disablerepo='*' \
            --enablerepo='ubi-9-*-source-rpms' \
            --qf "${query_format}" "${spec}")
    else
        result=$(dnf repoquery --forcearch="${rpm_architecture}" \
            --qf "${query_format}" "${spec}")
    fi
    result_count=$(printf '%s\n' "${result}" | sed '/^$/d' | wc -l)
    if test "${result_count}" -ne 1; then
        printf 'repository lookup for %s (%s) returned %s matches:\n%s\n' \
            "${spec}" "${mode}" "${result_count}" "${result}" >&2
        return 1
    fi
    printf '%s\n' "${result}"
}

while IFS= read -r rpm_path; do
    metadata=$(rpm -qp --qf \
        '%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}|%{SOURCERPM}' \
        "${rpm_path}")
    IFS='|' read -r name epoch version release package_arch source_rpm \
        <<<"${metadata}"
    filename=$(basename "${rpm_path}")
    if [[ ${name} == openresty* ]]; then
        repository=openresty-stable
        url="https://openresty.org/package/rhel/9/${rpm_architecture}/${filename}"
    else
        spec="${name}-${epoch}:${version}-${release}.${package_arch}"
        query=$(find_url "${spec}")
        repository=${query%%|*}
        location=${query#*|}
        case "${repository}" in
            ubi-9-baseos-rpms) component=baseos ;;
            ubi-9-appstream-rpms) component=appstream ;;
            ubi-9-codeready-builder-rpms) component=codeready-builder ;;
            *) printf 'unexpected binary repository: %s\n' "${repository}" >&2; exit 1 ;;
        esac
        url="https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/${rpm_architecture}/${component}/os/${location}"
    fi
    signature=$(rpm -qp --qf \
        '%{SIGPGP:pgpsig}|%{SIGGPG:pgpsig}|%{RSAHEADER:pgpsig}|%{DSAHEADER:pgpsig}' \
        "${rpm_path}")
    key_id=$(sed -n 's/.*[Kk]ey ID \([0-9A-Fa-f]*\).*/\1/p' <<<"${signature}" | head -n1)
    test -n "${key_id}"
    size=$(stat -c '%s' "${rpm_path}")
    sha256=$(sha256sum "${rpm_path}" | cut -d' ' -f1)
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "${filename}" "${name}" "${epoch}" "${version}" "${release}" \
        "${package_arch}" "${source_rpm}" "${key_id}" "${repository}" \
        "${url}" "${size}" "${sha256}" >>"${binary_inventory}"
done < <(find "${output_dir}/rpms" -maxdepth 1 -type f -name '*.rpm' | sort)

cut -f7 "${binary_inventory}" | sort -u >"${output_dir}/source-names.txt"
source_inventory="${output_dir}/source-inventory.tsv"
: >"${source_inventory}"

while IFS= read -r source_rpm; do
    if [[ ${source_rpm} == openresty-* ]]; then
        # The upstream RPM repository provides binary packages, not source RPMs.
        continue
    else
        spec=${source_rpm%.rpm}
        query=$(find_url "${spec}" source)
        repository=${query%%|*}
        location=${query#*|}
        case "${repository}" in
            ubi-9-baseos-source-rpms) component=baseos ;;
            ubi-9-appstream-source-rpms) component=appstream ;;
            ubi-9-codeready-builder-source-rpms) component=codeready-builder ;;
            *) printf 'unexpected source repository: %s\n' "${repository}" >&2; exit 1 ;;
        esac
        url="https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/${rpm_architecture}/${component}/source/SRPMS/${location}"
    fi
    # `--retry` alone covers a transient error, not a transfer that connects
    # and then stalls. Without a speed floor a hung CDN connection blocks the
    # resolver indefinitely, which is how this was found. The floor turns a
    # stall into an error that `--retry` can act on.
    curl --fail --location --proto '=https' --retry 3 --retry-delay 2 \
        --connect-timeout 20 --speed-limit 1024 --speed-time 30 \
        --output "${output_dir}/srpms/${source_rpm}" "${url}"
    rpm --checksig "${output_dir}/srpms/${source_rpm}"
    size=$(stat -c '%s' "${output_dir}/srpms/${source_rpm}")
    sha256=$(sha256sum "${output_dir}/srpms/${source_rpm}" | cut -d' ' -f1)
    printf '%s\t%s\t%s\t%s\t%s\n' \
        "${source_rpm}" "${repository}" "${url}" "${size}" "${sha256}" \
        >>"${source_inventory}"
done <"${output_dir}/source-names.txt"

sort -o "${binary_inventory}" "${binary_inventory}"
sort -o "${source_inventory}" "${source_inventory}"
