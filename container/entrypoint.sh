#!/bin/sh
set -eu
fail() { printf 'openresty-ubi: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" -ne 0 ] || fail 'refusing UID 0; run as a non-root UID'
case "${1:-}" in
    -v|-V) exec /usr/bin/openresty "$@" ;;
    '') ;;
    *) fail 'configure with OPENRESTY_UBI_CONFIG; arbitrary startup arguments are not accepted' ;;
esac
config=${OPENRESTY_UBI_CONFIG:-}
if [ -z "$config" ]; then
    [ "${OPENRESTY_UBI_ALLOW_PLAINTEXT_DEMO:-0}" = 1 ] ||
        fail 'mount a configuration and set OPENRESTY_UBI_CONFIG; plaintext demo requires OPENRESTY_UBI_ALLOW_PLAINTEXT_DEMO=1'
    printf 'openresty-ubi: WARNING: explicit plaintext, unauthenticated demo enabled\n' >&2
    config=/etc/nginx/nginx.conf
fi
case "$config" in /*) ;; *) fail 'OPENRESTY_UBI_CONFIG must be an absolute path' ;; esac
[ -f "$config" ] && [ -s "$config" ] && [ -r "$config" ] || fail "missing, empty, or unreadable configuration: $config"
[ ! -w "$config" ] || fail "configuration must be read-only: $config"
[ -d /tmp ] && [ -w /tmp ] || fail 'required writable /tmp mount is missing'
umask 027
mkdir -p /tmp/openresty || fail 'cannot create runtime directory in /tmp'
/usr/bin/openresty -t -p /tmp/openresty/ -c "$config" -e stderr || fail "invalid configuration: $config"
exec /usr/bin/openresty -p /tmp/openresty/ -c "$config" -e stderr -g 'daemon off;'
