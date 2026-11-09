# Third-party notices

Repository packaging code is Apache-2.0 (LICENSE). This does not relicense the
image's third-party software. Verification tools and downloaded packages are
not committed. This file and the packaging LICENSE are also retained in the
runtime image under `/usr/share/licenses/openresty-ubi/`.

OpenResty's RPM license header says BSD. The platform combines NGINX (BSD-2-Clause),
OpenResty modules (principally BSD), LuaJIT (MIT), and bundled Lua libraries with
their individual notices. Preserve `/usr/local/openresty/COPYRIGHT` and all
package-supplied notices. OpenResty is a registered trademark; this project is
not a vendor support or certification claim.

OpenResty additionally supplies OpenSSL 3.5.9 (Apache-2.0; RPM header retains the
legacy label `OpenSSL`), PCRE2 10.49 (BSD-style), and zlib 1.3.2 (zlib/Boost
according to the RPM). UBI packages include GPL/LGPL and other licenses; their
notices remain installed. The lock records each binary's source RPM identity
and the available UBI source RPM URLs/digests. OpenResty's binary repository
exposes no SRPMS directory at the corresponding EL9 URL; do not invent source
RPM hashes or claim source-RPM verification for these four packages. Source
and packaging are available through the upstream OpenResty projects; complete
redistribution/accountability review remains a pre-release roadmap item.

No observed license prevents this development increment. A combined image is
not solely Apache-2.0, and its OCI license label is not a complete inventory.
Release publishing is out of scope; source offers and notice completeness must
be reviewed before any distribution of a supported release.
