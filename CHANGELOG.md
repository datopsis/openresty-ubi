# Changelog

## [Unreleased]

### Added

- Rootless OpenResty 1.31.8.1 (NGINX 1.31.8 + LuaJIT) on pinned UBI 9.8.
- Signed, SHA-256/NEVRA-verified RPM bundles for amd64 and arm64; offline assembly.
- Explicit configuration guard, plaintext demo opt-out, read-only-root runtime.
- Real HTTP/Lua and restricted-process tests; native CI, SPDX SBOMs and blocking
  fixed High/Critical Trivy/Grype gates retaining unfixed findings.
- Read-only lock-candidate workflow and complete hash-pinned CI requirements.
- Provenance, licensing, advisory assessment and ordered qualification roadmap.
