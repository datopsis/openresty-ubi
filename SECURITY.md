# Security policy

No supported image has been released. Development revisions have no security
support SLA. Do not infer support or compliance from a successful CI run.

Report suspected vulnerabilities privately through the repository's Security
advisory reporting channel if enabled. If unavailable, ask the owner for a
private channel without posting vulnerability details or secrets publicly.
This increment does not enable repository features or change permissions.
Include the commit/image digest, architecture, runtime, configuration, and a
sanitized reproduction. Never include credentials or private keys.

For upstream handling use [OpenResty](https://openresty.org/en/community.html),
[NGINX security](https://nginx.org/en/security_advisories.html), or
[Red Hat Product Security](https://access.redhat.com/security/team/contact).

The owner decision of 2026-11-12 defines a fixable UBI RPM finding as one whose
vendor-fixed version (or newer) is available from the UBI repositories used to
resolve this image's locked inputs. Both Trivy and Grype block High/Critical
findings with an installable fix. `artifacts/ubi.repo` is the shared, reviewed
repository configuration for lock resolution and the availability gate. The
image itself still builds offline from its verified locks.

On each native architecture, the gate queries fresh metadata for every enabled
UBI repository inside the digest-pinned builder. RPM compares epoch, version
and release. A successful complete query showing only older versions defers the
finding; publication of an equal or newer version makes the next scan block.
This is a repository availability rule, not a CVE/package allow-list. A
repository-advertised fix blocks even if a later download or dependency solve
would fail; the gate never uses those failures as a reason to defer.

Query errors, timeouts, missing/empty repositories or packages, malformed or
ambiguous versions, scanner/lock mismatches, and malformed reports fail closed.
Non-RPM findings and RPMs outside the locked UBI package set retain the existing
blocking behavior. No successful availability query means no deferral. Findings
without vendor fixes remain visible in the complete reports.

Every scan uploads the full reports, query inventory, gate decisions and job
summary, including vendor-fixed versions for deferred findings. Native CI also
runs every six hours. On scheduled or manually dispatched default-branch runs,
a separate job maintains one **UBI vulnerability fix availability** issue and
comments when state changes, including deferred-to-blocked publication and
missing evidence. It closes the issue when no deferred/blocking findings remain
and reopens the same issue if needed. PR jobs cannot write issues. Only the
tracking job requests `issues: write`; repository settings and secrets are not
changed. GitHub scheduling may be delayed; this is not an immediate alert SLA.
No ignore list is shipped. Assess OpenResty's embedded NGINX,
OpenSSL, LuaJIT, PCRE2 and zlib using the actual publisher/version; Red Hat
advisories alone do not describe these upstream builds. UBI packages may carry
Red Hat backports. Report mismatches with evidence; never suppress findings
merely to pass. See docs/SECURITY-ASSESSMENT.md for the initial assessment.

The image does not sandbox application Lua. Operators own application review,
authentication, TLS, network restrictions, secret delivery, runtime flags,
resource limits, logging and timely replacement of vulnerable deployments.
