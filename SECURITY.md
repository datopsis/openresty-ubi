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

Both scanners block fixed High/Critical findings, retaining unfixed findings
for review. No ignore list is shipped. Assess OpenResty's embedded NGINX,
OpenSSL, LuaJIT, PCRE2 and zlib using the actual publisher/version; Red Hat
advisories alone do not describe these upstream builds. UBI packages may carry
Red Hat backports. Report mismatches with evidence; never suppress findings
merely to pass. See docs/SECURITY-ASSESSMENT.md for the initial assessment.

The image does not sandbox application Lua. Operators own application review,
authentication, TLS, network restrictions, secret delivery, runtime flags,
resource limits, logging and timely replacement of vulnerable deployments.
