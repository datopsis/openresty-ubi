# Ordered remaining work

This increment establishes development builds and runtime/security evidence,
not a supported release. No human approval is implied by these descriptions.

1. **Review and integrate the first increment.** Review native amd64/arm64
   Podman and Docker HTTP/Lua tests, complete Trivy/Grype findings, licenses,
   signing-key provenance, and all lock changes. Owner review remains pending.
2. **Deeper product and platform qualification.** Exercise mounted TLS and mTLS,
   upstream certificate rejection, reverse proxying, WebSockets, load balancing,
   Lua cosockets/FFI, reloads and long-lived request shutdown, failure recovery,
   resource limits, and controlled-network transfer. Record exact RHEL/Podman,
   SELinux, Docker, Kubernetes and OpenShift restricted-policy environments.
   Ubuntu CI does not establish those support boundaries.
3. **SCAP and control evidence.** Define a local threat/control model, pin
   scanner content and tailoring, produce native per-architecture filesystem
   evidence, and distinguish image controls from host/operator controls.
   Include source/secrets analysis, malware evidence, component accountability,
   and complete license/source redistribution review. Do not claim STIG/FIPS.
   The container-hardening criteria are a draft reading reference only; this
   repository has no dependency on its workflows or conformance gates.
4. **Release signing and publishing design.** With owner authorization, define
   immutable image identifiers, GHCR publication, keyless signatures, provenance,
   SBOM attestations, and independent verification. Identify owner-controlled
   branch protection, review, environments, and registry permissions. No settings
   changes or release-capable workflow belong to the initial increment.
5. **Final candidate qualification and first release.** Refresh base/RPM locks,
   reassess embedded NGINX and bundled library advisories, rerun all evidence
   against the exact candidate digest and native architectures, obtain genuine
   owner/security/license reviews, then publish only through the reviewed process.

Evidence belongs to its commit, image digest, architecture, configuration,
platform, and scanner databases. Changes invalidate affected candidate evidence.
No source-only release or tag is created for this increment.
