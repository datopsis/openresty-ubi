#!/usr/bin/env python3
"""Fetch only the reviewed key and OpenResty RPM seeds for a lock update."""

from __future__ import annotations

import argparse
import hashlib
import shutil
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

from artifacts import LockError, validate_inputs, validate_url


class ApprovedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        validate_url(newurl, "redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url: str, destination: Path, expected_sha256: str) -> None:
    opener = urllib.request.build_opener(ApprovedRedirectHandler())
    request = urllib.request.Request(url, headers={"User-Agent": "openresty-ubi-lock-updater/1"})
    digest = hashlib.sha256()
    with opener.open(request, timeout=30) as response, destination.open("wb") as output:
        validate_url(response.geturl(), "final response")
        for block in iter(lambda: response.read(1024 * 1024), b""):
            digest.update(block)
            output.write(block)
    if digest.hexdigest() != expected_sha256:
        raise LockError(f"SHA-256 mismatch for {destination.name}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", required=True, type=Path)
    parser.add_argument("--architecture", required=True, choices=("amd64", "arm64"))
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    inputs = validate_inputs(arguments.inputs)
    if arguments.output.exists():
        raise LockError(f"refusing to overwrite existing directory: {arguments.output}")
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{arguments.output.name}-", dir=arguments.output.parent))
    try:
        (temporary / "keys").mkdir()
        (temporary / "rpms").mkdir()
        key_rows = []
        for key in inputs["signing_keys"]:
            filename = Path(urllib.parse.urlsplit(key["url"]).path).name
            download(key["url"], temporary / "keys" / filename, key["sha256"])
            key_rows.append("\t".join((filename, key["fingerprint"], key["sha256"])))
        seed = inputs["architectures"][arguments.architecture]["openresty_rpm"]
        filename = Path(urllib.parse.urlsplit(seed["url"]).path).name
        download(seed["url"], temporary / "rpms" / filename, seed["sha256"])
        (temporary / "key-manifest.tsv").write_text(
            "\n".join(sorted(key_rows)) + "\n", encoding="utf-8", newline="\n"
        )
        (temporary / "rpm-seed-manifest.tsv").write_text(
            f"{filename}\t{seed['sha256']}\n", encoding="utf-8", newline="\n"
        )
        temporary.replace(arguments.output)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
