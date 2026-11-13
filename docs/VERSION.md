# Versions

Current upstream input: OpenResty 1.31.8.1 (`0:1.31.8.1-1.el9`), embedding
NGINX 1.31.8. Base line: UBI 9.9; exact manifest digests and package versions
live in artifacts/. These are dependency selections, not a container release.

Future container tags follow the nearest sibling's upstream-derived format:
`v<openresty-version>-ubi9-r<YYYYMMDD>.<daily-sequence>`. Preserve all four
OpenResty version components. This is not Semantic Versioning. The UTC date
and sequence identify a new immutable downstream release, including rebuilds
for UBI or packaging fixes. Never backdate, reuse, or move tags; never publish
`latest`. Deployments should pin image digests.

Git commits identify repository revisions. Documentation, tests, policy, and
CI-only changes create no release or version. Record notable changes under
Unreleased in CHANGELOG.md. The initial increment creates no tag or release,
and has no release/publish workflow.
