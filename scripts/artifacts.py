#!/usr/bin/env python3
"""Validate reviewed inputs and architecture-specific artifact locks."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import ssl
import sys
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path


ALLOWED_HOSTS = {"cdn-ubi.redhat.com", "openresty.org", "security.access.redhat.com"}
ARCHES = {"amd64": "x86_64", "arm64": "aarch64"}
BASE_PREFIXES = {
    "builder": "registry.access.redhat.com/ubi9/ubi-minimal:",
    "runtime": "registry.access.redhat.com/ubi9/ubi-micro:",
}
UBI_BINARY_REPOSITORIES = {
    "ubi-9-appstream-rpms",
    "ubi-9-baseos-rpms",
    "ubi-9-codeready-builder-rpms",
}
UBI_SOURCE_REPOSITORIES = {
    "ubi-9-appstream-source-rpms",
    "ubi-9-baseos-source-rpms",
    "ubi-9-codeready-builder-source-rpms",
}
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
FINGERPRINT_RE = re.compile(r"^[A-F0-9]{40}$")
FILENAME_RE = re.compile(r"^[A-Za-z0-9+_.-]+$")


class LockError(ValueError):
    """An input or lock violated the fail-closed contract."""


def fail(message: str) -> None:
    raise LockError(message)


def read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read valid JSON from {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"{path} must contain one JSON object")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_keys(value: dict, fields: set[str], label: str) -> None:
    missing = fields - value.keys()
    extra = value.keys() - fields
    if missing:
        fail(f"{label} is missing fields: {', '.join(sorted(missing))}")
    if extra:
        fail(f"{label} has unexpected fields: {', '.join(sorted(extra))}")


def require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        fail(f"{label} must be a non-empty string")
    return value


def require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        fail(f"{label} must be a lowercase SHA-256 value")
    return value


def validate_url(value: object, label: str) -> str:
    url = require_string(value, f"{label} URL")
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in ALLOWED_HOSTS
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        fail(f"{label} has an unapproved URL: {url}")
    return url


def validate_alternate_url(value: object, label: str) -> str:
    url = require_string(value, f"{label} URL")
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        fail(f"{label} must use an HTTPS URL without credentials, query, or fragment")
    return url


def validate_base_reference(value: object, role: str) -> str:
    reference = require_string(value, f"base image {role}")
    if not reference.startswith(BASE_PREFIXES[role]) or "@sha256:" not in reference:
        fail(f"base image {role} is not an approved digest-pinned UBI image")
    if not DIGEST_RE.fullmatch(reference.rsplit("@", 1)[1]):
        fail(f"base image {role} has an invalid digest")
    return reference


def validate_keys(value: object) -> list[dict]:
    if not isinstance(value, list) or not value:
        fail("signing_keys must be a non-empty array")
    ids: set[str] = set()
    fingerprints: set[str] = set()
    filenames: set[str] = set()
    for item in value:
        if not isinstance(item, dict):
            fail("each signing key must be an object")
        fields = {"id", "filename", "url", "sha256", "fingerprint"}
        require_keys(item, fields, "signing key")
        identifier = require_string(item["id"], "signing key id")
        filename = require_string(item["filename"], "signing key filename")
        fingerprint = require_string(item["fingerprint"], "signing key fingerprint")
        if not FILENAME_RE.fullmatch(filename):
            fail(f"unsafe signing key filename: {filename}")
        if not FINGERPRINT_RE.fullmatch(fingerprint):
            fail(f"invalid signing key fingerprint: {fingerprint}")
        validate_url(item["url"], f"signing key {identifier}")
        require_sha256(item["sha256"], f"signing key {identifier}")
        if identifier in ids or fingerprint in fingerprints or filename in filenames:
            fail("signing key ids, fingerprints, and filenames must be unique")
        ids.add(identifier)
        fingerprints.add(fingerprint)
        filenames.add(filename)
    if "4B35DCD2EA45C4E0783135BC8094BE9C9F4696A1" not in fingerprints:
        fail("the approved full OpenResty signing fingerprint is missing")
    return value


def validate_inputs(path: Path) -> dict:
    value = read_json(path)
    fields = {
        "schema_version", "bundle_version", "nginx_version", "openresty_version",
        "openresty_rpm_version", "ubi_release", "base_images",
        "architectures", "signing_keys",
    }
    require_keys(value, fields, "lock inputs")
    if value["schema_version"] != 1 or value["bundle_version"] != 1:
        fail("only lock schema and bundle version 1 are supported")
    require_string(value["openresty_version"], "OpenResty version")
    require_string(value["openresty_rpm_version"], "OpenResty RPM version")
    if value["ubi_release"] != "9.9":
        fail("lock inputs must use the reviewed UBI release")
    if not isinstance(value["base_images"], dict):
        fail("base_images must be an object")
    require_keys(value["base_images"], set(BASE_PREFIXES), "base images")
    for role in BASE_PREFIXES:
        validate_base_reference(value["base_images"][role], role)
    if not isinstance(value["architectures"], dict) or set(value["architectures"]) != set(ARCHES):
        fail("lock inputs must define exactly amd64 and arm64")
    for architecture, rpm_architecture in ARCHES.items():
        entry = value["architectures"][architecture]
        if not isinstance(entry, dict):
            fail(f"architecture {architecture} must be an object")
        require_keys(entry, {"rpm_architecture", "openresty_rpm"}, f"architecture {architecture}")
        if entry["rpm_architecture"] != rpm_architecture:
            fail(f"architecture {architecture} has the wrong RPM architecture")
        seed = entry["openresty_rpm"]
        if not isinstance(seed, dict):
            fail(f"architecture {architecture} OpenResty RPM must be an object")
        require_keys(seed, {"url", "sha256"}, "OpenResty seed")
        url = validate_url(seed["url"], "OpenResty seed")
        require_sha256(seed["sha256"], "OpenResty seed")
        expected_suffix = f"openresty-{value['openresty_rpm_version']}.{rpm_architecture}.rpm"
        if not url.endswith(f"/{expected_suffix}"):
            fail(f"architecture {architecture} does not select the reviewed OpenResty RPM")
    input_keys = []
    for item in value["signing_keys"]:
        if not isinstance(item, dict):
            fail("each input signing key must be an object")
        require_keys(item, {"id", "url", "sha256", "fingerprint"}, "input signing key")
        rendered = dict(item)
        rendered["filename"] = Path(urllib.parse.urlsplit(validate_url(item["url"], "signing key")).path).name
        input_keys.append(rendered)
    validate_keys(input_keys)
    return value


def validate_lock(path: Path, inputs_path: Path | None = None) -> dict:
    value = read_json(path)
    fields = {
        "schema_version", "bundle_version", "architecture",
        "rpm_architecture", "generated_at", "nginx_version", "openresty_version",
        "openresty_rpm_version", "base_images", "signing_keys", "packages",
        "source_packages",
    }
    require_keys(value, fields, "artifact lock")
    if value["schema_version"] != 1 or value["bundle_version"] != 1:
        fail("only lock schema and bundle version 1 are supported")
    architecture = value["architecture"]
    if architecture not in ARCHES or value["rpm_architecture"] != ARCHES[architecture]:
        fail("lock architecture fields are inconsistent")
    if not isinstance(value["generated_at"], str) or not value["generated_at"].endswith("Z"):
        fail("generated_at must be a UTC date-time")
    if not isinstance(value["base_images"], dict):
        fail("base_images must be an object")
    require_keys(value["base_images"], set(BASE_PREFIXES), "base images")
    for role, base in value["base_images"].items():
        if not isinstance(base, dict):
            fail(f"base image {role} must be an object")
        require_keys(base, {"reference", "digest", "platform"}, f"base image {role}")
        reference = validate_base_reference(base["reference"], role)
        if base["digest"] != reference.rsplit("@", 1)[1]:
            fail(f"base image {role} digest is inconsistent")
        if base["platform"] != f"linux/{architecture}":
            fail(f"base image {role} platform is inconsistent")
    keys = validate_keys(value["signing_keys"])
    fingerprints = {item["fingerprint"] for item in keys}
    packages = value["packages"]
    if not isinstance(packages, list) or not packages:
        fail("packages must be a non-empty array")
    nevras: set[str] = set()
    filenames: set[str] = set()
    for package in packages:
        validate_package(package, architecture, value, fingerprints)
        if package["nevra"] in nevras or package["filename"] in filenames:
            fail("package NEVRAs and filenames must be unique")
        nevras.add(package["nevra"])
        filenames.add(package["filename"])
    if [item["nevra"] for item in packages] != sorted(nevras):
        fail("packages must be sorted by NEVRA")
    sources = value["source_packages"]
    if not isinstance(sources, list):
        fail("source_packages must be a non-empty array")
    source_files: set[str] = set()
    for source in sources:
        validate_source(source)
        if source["filename"] in source_files:
            fail("source package filenames must be unique")
        source_files.add(source["filename"])
    if [item["filename"] for item in sources] != sorted(source_files):
        fail("source_packages must be sorted by filename")
    missing = {item["source_rpm"] for item in packages if not item["name"].startswith("openresty")} - source_files
    if missing:
        fail(f"binary packages lack source records: {', '.join(sorted(missing))}")
    openresty = [item for item in packages if item["name"] == "openresty"]
    if len(openresty) != 1:
        fail("lock must contain exactly one OpenResty package")
    if inputs_path is not None:
        validate_lock_against_inputs(value, validate_inputs(inputs_path))
    return value


def validate_lock_against_inputs(lock: dict, inputs: dict) -> None:
    for field in ("schema_version", "bundle_version", "nginx_version", "openresty_version", "openresty_rpm_version"):
        if lock[field] != inputs[field]:
            fail(f"artifact lock {field} differs from reviewed inputs")
    for role, reference in inputs["base_images"].items():
        if lock["base_images"][role]["reference"] != reference:
            fail(f"artifact lock base image {role} differs from reviewed inputs")
    architecture = lock["architecture"]
    architecture_inputs = inputs["architectures"][architecture]
    if lock["rpm_architecture"] != architecture_inputs["rpm_architecture"]:
        fail("artifact lock RPM architecture differs from reviewed inputs")
    openresty = next(item for item in lock["packages"] if item["name"] == "openresty")
    seed = architecture_inputs["openresty_rpm"]
    if openresty["url"] != seed["url"] or openresty["sha256"] != seed["sha256"]:
        fail("artifact lock OpenResty package differs from reviewed inputs")
    expected_keys = {
        (item["id"], item["url"], item["sha256"], item["fingerprint"])
        for item in inputs["signing_keys"]
    }
    actual_keys = {
        (item["id"], item["url"], item["sha256"], item["fingerprint"])
        for item in lock["signing_keys"]
    }
    if actual_keys != expected_keys:
        fail("artifact lock signing keys differ from reviewed inputs")


def validate_package(package: object, architecture: str, lock: dict, fingerprints: set[str]) -> None:
    if not isinstance(package, dict):
        fail("each package must be an object")
    fields = {"name", "epoch", "version", "release", "architecture", "nevra", "filename", "url", "repository", "size", "sha256", "signing_key_fingerprint", "source_rpm"}
    require_keys(package, fields, "package")
    for field in ("name", "version", "release", "architecture", "nevra", "filename", "repository", "source_rpm"):
        require_string(package[field], f"package {field}")
    if not isinstance(package["epoch"], int) or package["epoch"] < 0:
        fail("package epoch must be a non-negative integer")
    if package["architecture"] not in {ARCHES[architecture], "noarch"}:
        fail(f"package {package['nevra']} has the wrong architecture")
    expected = f"{package['name']}-{package['epoch']}:{package['version']}-{package['release']}.{package['architecture']}"
    if package["nevra"] != expected:
        fail(f"package NEVRA is inconsistent: {package['nevra']}")
    if not FILENAME_RE.fullmatch(package["filename"]) or not package["filename"].endswith(".rpm"):
        fail(f"unsafe package filename: {package['filename']}")
    url = validate_url(package["url"], f"package {package['nevra']}")
    expected_filename = (
        f"{package['name']}-{package['version']}-{package['release']}."
        f"{package['architecture']}.rpm"
    )
    if package["filename"] != expected_filename or Path(urllib.parse.urlsplit(url).path).name != expected_filename:
        fail(f"package filename is inconsistent: {package['filename']}")
    if not isinstance(package["size"], int) or package["size"] < 1:
        fail(f"package {package['nevra']} has an invalid size")
    require_sha256(package["sha256"], f"package {package['nevra']}")
    if package["signing_key_fingerprint"] not in fingerprints:
        fail(f"package {package['nevra']} uses an unapproved signing key")
    if not package["source_rpm"].endswith(".src.rpm"):
        fail(f"package {package['nevra']} has an invalid source RPM")
    host = urllib.parse.urlsplit(url).hostname
    if package["name"] == "openresty":
        expected_rpm = f"{lock['openresty_version']}-{package['release']}"
        if package["epoch"] != 0 or expected_rpm != lock["openresty_rpm_version"]:
            fail("OpenResty package violates the selected version")
        if package["repository"] != "openresty-stable" or host != "openresty.org":
            fail("OpenResty package has an inconsistent source")
    elif package["name"].startswith("openresty-"):
        if package["repository"] != "openresty-stable" or host != "openresty.org":
            fail("OpenResty dependency has an inconsistent source")
    elif package["repository"] not in UBI_BINARY_REPOSITORIES or host != "cdn-ubi.redhat.com":
        fail(f"package {package['nevra']} has an inconsistent UBI source")


def validate_source(source: object) -> None:
    if not isinstance(source, dict):
        fail("each source package must be an object")
    fields = {"filename", "url", "repository", "size", "sha256"}
    require_keys(source, fields, "source package")
    filename = require_string(source["filename"], "source package filename")
    if not FILENAME_RE.fullmatch(filename) or not filename.endswith(".src.rpm"):
        fail(f"unsafe source package filename: {filename}")
    url = validate_url(source["url"], f"source package {filename}")
    if Path(urllib.parse.urlsplit(url).path).name != filename:
        fail(f"source package URL does not match its filename: {filename}")
    repository = require_string(source["repository"], "source package repository")
    if not isinstance(source["size"], int) or source["size"] < 1:
        fail(f"source package {filename} has an invalid size")
    require_sha256(source["sha256"], f"source package {filename}")
    host = urllib.parse.urlsplit(url).hostname
    if filename.startswith("openresty-"):
        if repository != "openresty-stable-source" or host != "openresty.org":
            fail(f"source package {filename} has an inconsistent OpenResty source")
    elif repository not in UBI_SOURCE_REPOSITORIES or host != "cdn-ubi.redhat.com":
            fail(f"source package {filename} has an inconsistent UBI source")


def bundle_artifacts(lock: dict, include_sources: bool = False) -> dict[str, dict]:
    artifacts = {
        f"keys/{item['filename']}": {
            "url": item["url"], "sha256": item["sha256"], "size": None,
        }
        for item in lock["signing_keys"]
    }
    artifacts.update({
        f"rpms/{item['filename']}": {
            "url": item["url"], "sha256": item["sha256"], "size": item["size"],
        }
        for item in lock["packages"]
    })
    if include_sources:
        artifacts.update({
            f"srpms/{item['filename']}": {
                "url": item["url"], "sha256": item["sha256"], "size": item["size"],
            }
            for item in lock["source_packages"]
        })
    return artifacts


def manifest_contents(lock: dict, lock_sha256: str, include_sources: bool) -> dict[str, str]:
    key_rows = ["filename\tfingerprint\tsha256"]
    key_rows.extend(
        f"{item['filename']}\t{item['fingerprint']}\t{item['sha256']}"
        for item in lock["signing_keys"]
    )
    rpm_rows = [
        "filename\tname\tepoch\tversion\trelease\tarchitecture\tsource_rpm\tfingerprint\tsha256"
    ]
    rpm_rows.extend(
        "\t".join(str(value) for value in (
            item["filename"], item["name"], item["epoch"], item["version"],
            item["release"], item["architecture"], item["source_rpm"],
            item["signing_key_fingerprint"], item["sha256"],
        ))
        for item in lock["packages"]
    )
    manifests = {
        "LOCK-SHA256": f"{lock_sha256}\n",
        "key-manifest.tsv": "\n".join(key_rows) + "\n",
        "rpm-manifest.tsv": "\n".join(rpm_rows) + "\n",
    }
    if include_sources:
        source_rows = ["filename\trepository\tsize\tsha256"]
        source_rows.extend(
            f"{item['filename']}\t{item['repository']}\t{item['size']}\t{item['sha256']}"
            for item in lock["source_packages"]
        )
        manifests["source-manifest.tsv"] = "\n".join(source_rows) + "\n"
    return manifests


def rpm_manifest(lock: dict) -> str:
    """Return the exact runtime RPM manifest embedded during assembly."""
    return manifest_contents(lock, "0" * 64, False)["rpm-manifest.tsv"]


def read_source_map(path: Path, expected: set[str]) -> tuple[dict[str, str], set[str]]:
    value = read_json(path)
    require_keys(value, {"schema_version", "artifacts"}, "alternate source map")
    if value["schema_version"] != 1 or not isinstance(value["artifacts"], dict):
        fail("alternate source map must use schema version 1 and an artifacts object")
    actual = set(value["artifacts"])
    if actual != expected:
        missing = expected - actual
        extra = actual - expected
        details = []
        if missing:
            details.append(f"missing {len(missing)} artifact(s)")
        if extra:
            details.append(f"containing {len(extra)} unexpected artifact(s)")
        fail("alternate source map does not exactly match the lock: " + " and ".join(details))
    urls = {
        logical_path: validate_alternate_url(value["artifacts"][logical_path], logical_path)
        for logical_path in sorted(expected)
    }
    hosts = {urllib.parse.urlsplit(url).hostname for url in urls.values()}
    return urls, {host for host in hosts if host}


class ApprovedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, hosts: set[str]):
        super().__init__()
        self.hosts = hosts

    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        parsed = urllib.parse.urlsplit(new_url)
        original = urllib.parse.urlsplit(request.full_url)
        if (
            parsed.scheme != "https"
            or parsed.hostname not in self.hosts
            or parsed.hostname != original.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            fail("download redirect left the original approved HTTPS host")
        return super().redirect_request(request, file_pointer, code, message, headers, new_url)


def download(url: str, destination: Path, hosts: set[str], context: ssl.SSLContext,
             token: str | None) -> None:
    headers = {"User-Agent": "openresty-ubi-artifact-acquirer/1"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    opener = urllib.request.build_opener(
        ApprovedRedirectHandler(hosts), urllib.request.HTTPSHandler(context=context)
    )
    request = urllib.request.Request(url, headers=headers)
    try:
        with opener.open(request, timeout=60) as response, destination.open("wb") as output:
            shutil.copyfileobj(response, output)
    except LockError:
        raise
    except Exception as exc:
        fail(f"download failed ({type(exc).__name__})")


def verify_file(path: Path, record: dict, logical_path: str) -> None:
    if not path.is_file():
        fail(f"bundle is missing {logical_path}")
    expected_size = record["size"]
    if expected_size is not None and path.stat().st_size != expected_size:
        fail(f"bundle artifact has the wrong size: {logical_path}")
    if sha256_file(path) != record["sha256"]:
        fail(f"bundle artifact has the wrong SHA-256: {logical_path}")


def verify_bundle(lock_path: Path, bundle: Path, include_sources: bool = False) -> None:
    lock = validate_lock(lock_path)
    artifacts = bundle_artifacts(lock, include_sources)
    manifests = manifest_contents(lock, sha256_file(lock_path), include_sources)
    expected_files = set(artifacts) | set(manifests)
    expected_directories = {
        Path(logical_path).parent.as_posix()
        for logical_path in artifacts
        if Path(logical_path).parent != Path(".")
    }
    if not bundle.is_dir():
        fail(f"bundle directory does not exist: {bundle}")
    actual_files: set[str] = set()
    for path in bundle.rglob("*"):
        relative = path.relative_to(bundle).as_posix()
        if path.is_symlink():
            fail(f"bundle contains a symbolic link: {relative}")
        if path.is_file():
            actual_files.add(relative)
        elif path.is_dir():
            if relative not in expected_directories:
                fail(f"bundle contains an unexpected directory: {relative}")
        else:
            fail(f"bundle contains a non-regular entry: {relative}")
    if actual_files != expected_files:
        missing = expected_files - actual_files
        extra = actual_files - expected_files
        details = []
        if missing:
            details.append(f"missing {len(missing)} file(s)")
        if extra:
            details.append(f"containing {len(extra)} unexpected file(s)")
        fail("bundle inventory is not exact: " + " and ".join(details))
    for logical_path, record in artifacts.items():
        verify_file(bundle / logical_path, record, logical_path)
    for filename, contents in manifests.items():
        try:
            actual = (bundle / filename).read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            fail(f"cannot read bundle manifest {filename}: {type(exc).__name__}")
        if actual != contents:
            fail(f"bundle manifest does not match the lock: {filename}")


def acquire_bundle(lock_path: Path, output: Path, include_sources: bool = False,
                   source_map: Path | None = None, token_env: str | None = None,
                   ca_bundle: Path | None = None) -> None:
    lock = validate_lock(lock_path)
    artifacts = bundle_artifacts(lock, include_sources)
    if output.exists():
        fail(f"output already exists: {output}")
    if token_env and source_map is None:
        fail("authenticated acquisition requires an alternate source map")
    token = None
    if token_env:
        token = os.environ.get(token_env)
        if not token:
            fail(f"credential environment variable is unset: {token_env}")
    if ca_bundle is not None and not ca_bundle.is_file():
        fail("CA bundle does not exist or is not a file")
    try:
        context = ssl.create_default_context(cafile=str(ca_bundle) if ca_bundle else None)
    except (OSError, ssl.SSLError):
        fail("cannot load the configured CA bundle")
    if source_map:
        urls, hosts = read_source_map(source_map, set(artifacts))
    else:
        urls = {path: record["url"] for path, record in artifacts.items()}
        hosts = set(ALLOWED_HOSTS)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        for logical_path, record in artifacts.items():
            destination = temporary / logical_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            download(urls[logical_path], destination, hosts, context, token)
            verify_file(destination, record, logical_path)
        for filename, contents in manifest_contents(
            lock, sha256_file(lock_path), include_sources
        ).items():
            (temporary / filename).write_text(contents, encoding="utf-8", newline="\n")
        verify_bundle(lock_path, temporary, include_sources)
        os.replace(temporary, output)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    inputs_parser = subparsers.add_parser("validate-inputs")
    inputs_parser.add_argument("path", type=Path)
    lock_parser = subparsers.add_parser("validate-lock")
    lock_parser.add_argument("path", type=Path)
    lock_parser.add_argument("--inputs", type=Path)
    acquire_parser = subparsers.add_parser("acquire")
    acquire_parser.add_argument("--lock", required=True, type=Path)
    acquire_parser.add_argument("--output", required=True, type=Path)
    acquire_parser.add_argument("--include-sources", action="store_true")
    acquire_parser.add_argument("--source-map", type=Path)
    acquire_parser.add_argument("--token-env")
    acquire_parser.add_argument("--ca-bundle", type=Path)
    verify_parser = subparsers.add_parser("verify-bundle")
    verify_parser.add_argument("--lock", required=True, type=Path)
    verify_parser.add_argument("--bundle", required=True, type=Path)
    verify_parser.add_argument("--include-sources", action="store_true")
    base_parser = subparsers.add_parser("base-reference")
    base_parser.add_argument("lock", type=Path)
    base_parser.add_argument("role", choices=sorted(BASE_PREFIXES))
    manifest_parser = subparsers.add_parser("rpm-manifest")
    manifest_parser.add_argument("lock", type=Path)
    arguments = parser.parse_args()
    try:
        if arguments.command == "validate-inputs":
            validate_inputs(arguments.path)
        elif arguments.command == "validate-lock":
            validate_lock(arguments.path, arguments.inputs)
        elif arguments.command == "acquire":
            acquire_bundle(
                arguments.lock, arguments.output, arguments.include_sources,
                arguments.source_map, arguments.token_env, arguments.ca_bundle,
            )
        elif arguments.command == "verify-bundle":
            verify_bundle(arguments.lock, arguments.bundle, arguments.include_sources)
        elif arguments.command == "base-reference":
            lock = validate_lock(arguments.lock)
            print(lock["base_images"][arguments.role]["reference"])
        else:
            print(rpm_manifest(validate_lock(arguments.lock)), end="")
    except LockError as exc:
        print(f"artifact lock validation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
