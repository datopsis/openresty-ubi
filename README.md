# OpenResty on Red Hat UBI 9

Security-oriented, rootless OpenResty **1.31.8.1**, embedding NGINX **1.31.8**
and LuaJIT, on digest-pinned UBI **9.8 Minimal/Micro**. Development increment;
no released image or supported platform. Repository code is Apache-2.0;
packaged components retain their own licenses (see THIRD_PARTY_NOTICES.md).

## Build and verify

On a native Linux amd64 or arm64 host with Podman, Python 3, RPM (including
rpmsign), Skopeo, and GnuPG:

```sh
ARCH=amd64 # use arm64 on an arm64 host
python3 scripts/artifacts.py acquire --lock "artifacts/locks/$ARCH.json" --output ".artifact-bundle/$ARCH"
bash scripts/verify-rpm-bundle.sh "artifacts/locks/$ARCH.json" ".artifact-bundle/$ARCH"
bash scripts/build-image.sh "$ARCH" localhost/openresty-ubi:test
IMAGE=localhost/openresty-ubi:test CONTAINER_RUNTIME=podman bash tests/smoke.sh
```

Acquisition downloads exactly the lock. Assembly uses the verified local RPM
closure with networking disabled and image pulls refused. Builds do not resolve
live repositories. The RPM database and `/usr/share/openresty-ubi/rpm-manifest.tsv`
remain for inventory/scanning; package-manager executables and signing keys do
not. UBI Micro supplies the final base; the locked RPM closure overlays it.
See [artifact provenance](docs/ARTIFACTS.md) for trust and refresh procedures.

## Run

Startup requires an explicit configuration. Mount a complete NGINX config at
`/etc/nginx/site.conf:ro` and set `OPENRESTY_UBI_CONFIG=/etc/nginx/site.conf`.
The file must exist, be non-empty, readable, and not writable by the runtime
identity. Syntax validation runs before exec; errors name the failing path.
The only writable application path is `/tmp` (PID, request buffering, temporary
files). Mount it `rw,noexec,nosuid,nodev`. Logs go to standard streams.

For a local demonstration only, explicitly accept plaintext and anonymous
access using this opt-out:

```sh
podman run --rm --read-only --read-only-tmpfs=false \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777 \
  --cap-drop ALL --security-opt no-new-privileges \
  -p 127.0.0.1:8080:8080 \
  -e OPENRESTY_UBI_ALLOW_PLAINTEXT_DEMO=1 localhost/openresty-ubi:test
```

Request `/` for static content, `/healthz` for HTTP liveness, and `/lua` for a
real LuaJIT/CJSON/PCRE2 response. Without an explicit config or the demo opt-out,
startup fails. No credentials or TLS material ship with the image. UID is
`999:0`; arbitrary non-root UIDs in group 0 are tested. Root is rejected.
Docker uses the same flags except `--read-only-tmpfs=false` (Podman-specific).

Operator configurations must use unprivileged listeners, `/tmp` for all write
paths, stdout/stderr logging, and runtime-mounted trust/keys. Authentication,
TLS termination, Lua code, outbound authorization, and network exposure are
operator responsibilities. The demo has no authentication and must not be
exposed as a production application. Custom config is an explicit replacement
of the demo policy; the entrypoint validates syntax, not arbitrary Lua's safety.
The template enables upstream TLS verification and disables session tickets.

The entrypoint execs NGINX as PID 1. SIGQUIT provides graceful shutdown;
allow at least 15 seconds. The image healthcheck validates configuration only;
monitor `/healthz` separately for HTTP liveness. No dynamic package installation
or OPM download occurs at startup.

## Development and CI

```sh
python3 -m venv .venv
.venv/bin/pip install --require-hashes --only-binary=:all: -r .github/requirements/pre-commit.txt
.venv/bin/pre-commit run --all-files
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

CI runs lint and native amd64/arm64 builds, real Podman and Docker runtime
checks, signature/tampering negatives, an SPDX SBOM, and Trivy/Grype scans.
`scripts/scan-gate.py` **fails** on either scanner's fixed High/Critical
findings. It also fails on missing/malformed reports. Complete JSON reports
retain unfixed findings and are uploaded even when the gate fails. Unit tests
prove the gate rejects synthetic fixed findings from each scanner independently.
A green status does not replace reading those reports or upstream advisories.

`.github/workflows/update-locks.yml` generates candidate locks and provenance
logs on relevant PR changes or manual dispatch, with `contents: read`. It does
not commit, open PRs, publish, or approve anything. No workflow publishes on tags.
The Python requirements include filelock 4.2.9, virtualenv 21.14.13, and all
transitive dependencies with hashes; regeneration is documented in the `.in`.

## Layout and limits

- `Containerfile`, `container/`: runtime, entrypoint, demo configuration/content.
- `artifacts/`: reviewed inputs and per-architecture RPM locks.
- `scripts/`: acquisition, verification, offline build, lock refresh, scan gate.
- `tests/`: lock/gate negatives and real restricted runtime checks.
- `.github/`: pinned CI tools and read-only workflows.
- `docs/`: provenance, versions, advisory assessment, and remaining roadmap.

Read [ROADMAP](docs/ROADMAP.md), [VERSION](docs/VERSION.md), and
[SECURITY](SECURITY.md). No FIPS validation, STIG certification, or general
platform-support claim is made. Local namespace restrictions may prevent
container tests; native CI evidence must then be checked before accepting work.
