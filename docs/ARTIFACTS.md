# Input provenance and lock refresh

The layout and RPM-bundle tooling derive from datopsis/nginx-ubi, reviewed along
with postgresql-ubi, lakekeeper-ubi, seaweedfs-ubi and clickhouse-ubi. Their
Apache-2.0 packaging conventions are retained. The draft container-hardening
criteria were read; no dependency or compliance claim is introduced.

## Selected inputs (2026-11-09 UTC)

OpenResty 1.31.8.1-1.el9 is downloaded from the official HTTPS RHEL 9 RPM
repository for x86_64 and aarch64. Its dependencies include signed upstream
OpenSSL 3.5.9, PCRE2 10.49, zlib 1.3.2 and a complete signed UBI RPM closure.
Every binary has its NEVRA, source RPM header, publisher key fingerprint, size,
URL and SHA-256 recorded in the architecture lock. Both bundles are verified
again before build; the installer verifies hashes, signatures, metadata,
exact inventory and installed package set without networking.

The installation page still names the older D5EDEB74 key and pubkey.gpg.
The actual 1.31.8.1 RPMs are signed by **8094BE9C9F4696A1**. The publisher's
[package directory](https://openresty.org/package/) provides
[pubkey2.gpg](https://openresty.org/package/pubkey2.gpg), whose full fingerprint
is **4B35DCD2EA45C4E0783135BC8094BE9C9F4696A1**, and whose SHA-256 is
`bdfed8da78e610325bdff9a5191f98ee2fd9ad41b6075d248c76c347df27ccfe`.
The old key was tested and rejected (NOKEY); the new publisher-hosted key
verifies the packages. Trust bootstrap is the separately fetched publisher
HTTPS key; there is no independent out-of-band identity attestation. Key
rotation requires explicit fingerprint and checksum review, never auto-accept.
Red Hat keys are separately pinned from security.access.redhat.com.

UBI 9.8 current manifest lists were retrieved with `skopeo inspect --raw`:

| Base | Manifest-list digest |
| --- | --- |
| ubi-minimal | `sha256:f26ef64172ea61f5ac5ba4be8c5c738bf8760b22b3e5148ce7b40f7308ab32db` |
| ubi-micro | `sha256:d3499a0896e2d6a1642f922615831bc5c2fd513bbb34f3446cabba530d9d54a2` |

Both list linux/amd64 and linux/arm64 (also ppc64le and s390x, which this project
does not qualify). Base manifests are digest-verified; each selected architecture manifest is
also verified against Red Hat's simple-signing signature at its public sigstore,
using the pinned Red Hat release keys and checking the signed digest and
repository identity. RPM publisher signatures are verified. No unsigned upstream
tarball is used as a build input. The first local locks were resolved with DNF
4.14 on Debian because namespace creation prevents running a UBI resolver here;
CI's native UBI update workflow independently produced candidates with identical
inputs on both architectures (only generated_at differed), in
[run 42608968026](https://github.com/datopsis/openresty-ubi/actions/runs/42608968026).

## Refresh

Edit reviewed seeds, keys, versions and base digests in `artifacts/lock-inputs.json`.
Never substitute a latest version during an ordinary build. Confirm manifest
platforms and current NGINX advisories. Then run the read-only update workflow,
or on a native host:

```sh
ARCH=amd64
python3 scripts/fetch-lock-inputs.py --inputs artifacts/lock-inputs.json --architecture "$ARCH" --output ".artifact-inputs/$ARCH"
BUILDER=$(python3 -c 'import json; print(json.load(open("artifacts/lock-inputs.json"))["base_images"]["builder"])')
podman run --rm -v "$PWD:/work:Z" -w /work --entrypoint bash "$BUILDER" \
  scripts/resolve-lock.sh "$ARCH" ".artifact-inputs/$ARCH" ".artifact-resolver/$ARCH"
python3 scripts/render-lock.py --inputs artifacts/lock-inputs.json --architecture "$ARCH" \
  --binary-inventory ".artifact-resolver/$ARCH/binary-inventory.tsv" \
  --source-inventory ".artifact-resolver/$ARCH/source-inventory.tsv" \
  --output ".artifact-resolver/$ARCH.json"
```

Resolution is deliberately networked and installs resolver tools; it proposes
inputs, not a runtime image. Review the candidate diff, signatures, source and
license metadata, then replace committed locks through an ordinary reviewed PR.
Refresh both architectures and rerun image tests/scans. Candidates are never
automatically committed. Owner review fields are intentionally not fabricated.
