#!/usr/bin/env python3
"""Exercise fail-closed verification against a real acquired RPM bundle."""

from __future__ import annotations

import argparse
import copy
import errno
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import artifacts  # noqa: E402


def reject(command: list[str], label: str) -> None:
    result = subprocess.run(
        command,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode == 0:
        raise RuntimeError(f"verification unexpectedly accepted {label}")
    print(f"rejected {label}")


def clone_bundle(source: Path, destination: Path) -> None:
    def link_or_copy(source_path: str, destination_path: str) -> str:
        try:
            os.link(source_path, destination_path)
            return destination_path
        except OSError as exc:
            if exc.errno != errno.EXDEV:
                raise
            return shutil.copy2(source_path, destination_path)

    shutil.copytree(source, destination, copy_function=link_or_copy)
    for filename in ("LOCK-SHA256", "key-manifest.tsv", "rpm-manifest.tsv"):
        path = destination / filename
        contents = path.read_bytes()
        path.unlink()
        path.write_bytes(contents)


def detach(path: Path) -> None:
    contents = path.read_bytes()
    path.unlink()
    path.write_bytes(contents)


def write_contract(lock: dict, lock_path: Path, bundle: Path) -> None:
    lock_path.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
    manifests = artifacts.manifest_contents(lock, artifacts.sha256_file(lock_path), False)
    for filename, contents in manifests.items():
        path = bundle / filename
        if path.exists():
            path.unlink()
        path.write_text(contents, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--bundle", required=True, type=Path)
    arguments = parser.parse_args()

    repository = Path(__file__).resolve().parents[1]
    verifier = repository / "scripts" / "verify-rpm-bundle.sh"
    original_lock = artifacts.validate_lock(arguments.lock)
    subprocess.run(
        ["bash", str(verifier), str(arguments.lock), str(arguments.bundle)],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    print("accepted the unchanged locked bundle")
    openresty = next(item for item in original_lock["packages"] if item["name"] == "openresty")
    first_package = original_lock["packages"][0]

    with tempfile.TemporaryDirectory(prefix="openresty-ubi-negative-") as temporary_name:
        temporary = Path(temporary_name)

        def variant(label: str) -> tuple[dict, Path, Path]:
            lock = copy.deepcopy(original_lock)
            lock_path = temporary / f"{label}.json"
            bundle = temporary / label
            clone_bundle(arguments.bundle, bundle)
            write_contract(lock, lock_path, bundle)
            return lock, lock_path, bundle

        lock, lock_path, bundle = variant("tampered")
        package = bundle / "rpms" / first_package["filename"]
        detach(package)
        with package.open("ab") as handle:
            handle.write(b"tampered")
        reject(["bash", str(verifier), str(lock_path), str(bundle)], "a tampered RPM")

        lock, lock_path, bundle = variant("missing")
        (bundle / "rpms" / first_package["filename"]).unlink()
        reject(["bash", str(verifier), str(lock_path), str(bundle)], "a missing RPM")

        lock, lock_path, bundle = variant("unexpected")
        (bundle / "rpms" / "unexpected.rpm").write_bytes(b"unexpected")
        reject(["bash", str(verifier), str(lock_path), str(bundle)], "an unexpected RPM")

        lock, lock_path, bundle = variant("wrong-version")
        locked_openresty = next(item for item in lock["packages"] if item["name"] == "openresty")
        lock["openresty_version"] = "1.30.3"
        lock["openresty_rpm_version"] = f"1.30.3-{locked_openresty['release']}"
        locked_openresty["version"] = "1.30.3"
        locked_openresty["nevra"] = (
            f"openresty-{locked_openresty['epoch']}:1.30.3-{locked_openresty['release']}."
            f"{locked_openresty['architecture']}"
        )
        write_contract(lock, lock_path, bundle)
        reject(["bash", str(verifier), str(lock_path), str(bundle)], "the wrong OpenResty version")

        lock, lock_path, bundle = variant("wrong-architecture")
        locked_openresty = next(item for item in lock["packages"] if item["name"] == "openresty")
        locked_openresty["architecture"] = "aarch64" if lock["architecture"] == "amd64" else "x86_64"
        write_contract(lock, lock_path, bundle)
        reject(["bash", str(verifier), str(lock_path), str(bundle)], "the wrong RPM architecture")

        lock, lock_path, bundle = variant("wrong-signer")
        locked_openresty = next(item for item in lock["packages"] if item["name"] == "openresty")
        locked_openresty["signing_key_fingerprint"] = next(
            item["fingerprint"]
            for item in lock["signing_keys"]
            if item["fingerprint"] != locked_openresty["signing_key_fingerprint"]
        )
        write_contract(lock, lock_path, bundle)
        reject(["bash", str(verifier), str(lock_path), str(bundle)], "a signer mismatch")

        lock, lock_path, bundle = variant("unsigned")
        locked_openresty = next(item for item in lock["packages"] if item["name"] == "openresty")
        package = bundle / "rpms" / openresty["filename"]
        detach(package)
        subprocess.run(["rpmsign", "--delsign", str(package)], check=True)
        locked_openresty["size"] = package.stat().st_size
        locked_openresty["sha256"] = artifacts.sha256_file(package)
        write_contract(lock, lock_path, bundle)
        reject(["bash", str(verifier), str(lock_path), str(bundle)], "an unsigned RPM")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
