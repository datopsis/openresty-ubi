# Project guidance

This repository builds a security-oriented OpenResty (NGINX + LuaJIT) web
platform on Red Hat UBI 9, following datopsis/nginx-ubi's layout and verified
RPM-bundle assembly. Preserve these non-negotiable properties:

- Digest-pinned UBI 9 builder and final runtime; no package manager in runtime.
- Starts and stays non-root, numeric UID and group 0, no entrypoint privilege
  transition; all default listeners use unprivileged ports.
- Works with a read-only root, explicitly declared writable mounts, all Linux
  capabilities dropped, and no-new-privileges.
- Every build input is pinned and verified: base manifest digests, RPM NEVRA
  and SHA-256 per architecture, and digests for any upstream artifacts.
  Verify publisher signatures where provided. Say explicitly when only digest
  integrity is available; never equate a checksum with publisher identity.
- No credentials, private keys, or default passwords in images or examples.
  Unsafe upstream defaults fail closed with a documented explicit opt-out.
- No FIPS, STIG, certification, or platform-support claims without evidence.
- Both Trivy and Grype enforce SECURITY.md's owner-approved UBI installability
  rule for High/Critical findings on both native architectures. Unfixed and
  deferred findings remain visible. Never weaken a check to pass.
- Complete hash-pinned CI requirements include their `.in` input and transitive
  dependencies. Actions use full commit SHAs. Lock refresh proposes artifacts
  for review with read-only permissions; it never commits or opens PRs.

## Scope and evidence

Read README.md for build/test commands, docs/ROADMAP.md for ordered remaining
work, and docs/VERSION.md for version rules. This increment is development
only: no release workflow, publishing, signing, or tag creation. A tag must
not trigger publishing. container-hardening is a draft reference only: no
workflow calls, pinned dependency, conformance score, or release-eligible gate.

Image changes require real HTTP and Lua requests, version-to-lock checks,
non-root process checks, actual kernel capability/mount evidence, read-only
root, missing/invalid configuration rejection, and native amd64/arm64 CI.
Use Podman primarily; Docker results are compatibility evidence only.
Do not infer Kubernetes, OpenShift, SELinux, RHEL host, or FIPS qualification
from Ubuntu GitHub runners. OpenResty's bundled OpenSSL is not Red Hat's
validated crypto boundary. Compare embedded NGINX against nginx.org advisories,
not Red Hat package versions. Preserve upstream notices and package inventory.

Mount application configuration, trust, and keys read-only. Application Lua
is trusted executable code, not a sandbox; the image cannot secure arbitrary
operator Lua. Keep certificates and private keys out of source and logs.
Generated bundles, SBOMs, reports, scanner caches, and private material are
not committed. Never manufacture owner reviews or sign-offs.

## Git conventions

Use feature branches and concise Conventional Commit subjects. No force-push,
merge without owner action, or AI/Co-Authored-By trailers. Do not change repo
or organization settings, secrets, permissions, or branch protection. Report
external governance prerequisites without attempting destructive probes.
