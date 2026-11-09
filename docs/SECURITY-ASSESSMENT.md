# Initial upstream assessment

Assessment date: 2026-11-09 UTC. Development evidence, not release approval.

The [OpenResty 1.31.8.1 announcement](https://openresty.org/en/ann-1031008001.html)
identifies embedded **NGINX 1.31.8**, LuaJIT v2.1-20261023, OpenSSL 3.5.9 and
PCRE2 10.49. Runtime tests verify the NGINX numeric version through an actual
Lua response (`ngx.config.nginx_version`), the OpenResty command-line version,
and execution of LuaJIT, CJSON and PCRE2 on each native architecture.

The [NGINX advisory index](https://nginx.org/en/security_advisories.html) was
checked directly. NGINX 1.31.8 lies beyond all vulnerable ranges listed on that
date. In particular, the latest five advisories (CVE-2026-15176, -93479, -95101,
-97629 and -97205) have mainline fixes in 1.31.7; the preceding HTTP/3 overflow
CVE-2026-90439 is fixed in 1.31.6. This is a version-range assessment, not proof
that undisclosed vulnerabilities do not exist. Recheck when inputs change.

Do not match this binary as Red Hat's nginx module stream: OpenResty builds
and patches its own embedded NGINX and ships its own OpenSSL/PCRE2/zlib.
Retain both scanners' raw findings and inspect their package identities and
match details. No Red Hat false-positive suppression is shipped. Scanner
coverage gaps or a clean RPM-level scan do not supersede upstream assessment.

The full Trivy and Grype reports and SPDX SBOM are CI artifacts per architecture.
The gate rejects fixed High/Critical findings from either and preserves unfixed
findings. See the PR/run for actual scan outcomes; this document does not claim
that a scanner ran when no runtime image has yet been produced locally.

Local container build/runtime execution was blocked by Podman's namespace error
`cannot clone: Operation not permitted`. Local signature, integrity, lock and
gate tests are independent of that restriction. Native GitHub runs provide
container evidence; no SELinux/OpenShift/FIPS/STIG claim follows from them.

Native runtime and scanner outcomes, including the four unfixed High CVEs and
the embedded-component SBOM coverage gap, are recorded in
[evaluation evidence](evals/2026-11-09-runtime.md). No owner acceptance is implied.
