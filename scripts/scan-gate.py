#!/usr/bin/env python3
"""Block vendor-fixed High/Critical findings unless UBI publication is pending."""
import argparse
import configparser
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from artifacts import validate_lock


REPO_FILE = Path(__file__).resolve().parent.parent / 'artifacts/ubi.repo'
REPOS = {f'ubi-9-{component}-rpms' for component in ('baseos', 'appstream', 'codeready-builder')}
ARCHES = {'amd64': 'x86_64', 'arm64': 'aarch64'}
EVR = re.compile(r'(?:[0-9]+:)?[A-Za-z0-9][A-Za-z0-9._+~^]*-[A-Za-z0-9][A-Za-z0-9._+~^]*\Z')


def run(command, timeout=180):
    result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=timeout,
                            env={**os.environ, 'LC_ALL': 'C'})
    # DNF can return success after skipping an inaccessible repository.
    if result.stderr.strip():
        raise ValueError(f'query diagnostic: {result.stderr.strip()}')
    return result.stdout


def parse_evr(value):
    if not isinstance(value, str) or not EVR.fullmatch(value):
        raise ValueError(f'unparsable RPM epoch:version-release: {value!r}')
    return value if ':' in value else '0:' + value


def compare_evr(left, right):
    left, right = parse_evr(left), parse_evr(right)
    # Delegate RPM semantics to RPM >= 4.16 (the pinned UBI builder uses 4.16).
    # The strict EVR grammar excludes Lua quoting and RPM macro metacharacters.
    result = run(['rpm', '--eval', f'%{{lua:print(rpm.vercmp("{left}", "{right}"))}}'], timeout=10).strip()
    if result not in {'-1', '0', '1'}:
        raise ValueError('invalid RPM comparison result')
    return int(result)


def query_repositories(architecture, output):
    """One fresh, complete per-architecture snapshot; never use host repo files."""
    rpm_arch = ARCHES[architecture]
    config = configparser.ConfigParser(interpolation=None)
    if not config.read(REPO_FILE):
        raise ValueError('missing UBI repository file')
    enabled = {name for name in config.sections() if config.getboolean(name, 'enabled')}
    if enabled != REPOS:
        raise ValueError('missing/unexpected enabled UBI repository')
    for name in REPOS:
        if config.getboolean(name, 'skip_if_unavailable') or not config.getboolean(name, 'gpgcheck'):
            raise ValueError('UBI repository must fail closed and verify packages')
        if not config.get(name, 'baseurl').startswith('https://cdn-ubi.redhat.com/'):
            raise ValueError('unexpected UBI repository URL')
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        repos = root / 'repos'
        repos.mkdir()
        (repos / 'ubi.repo').write_bytes(REPO_FILE.read_bytes())
        command = ['dnf', '-q', '--noplugins', '--refresh', '--releasever=9',
                   f'--forcearch={rpm_arch}', f'--setopt=reposdir={repos}',
                   f'--setopt=cachedir={root / "cache"}', f'--setopt=persistdir={root / "persist"}',
                   f'--setopt=logdir={root / "log"}', '--setopt=*.skip_if_unavailable=0',
                   '--setopt=timeout=30', '--setopt=retries=1',
                   'repoquery', '--available', '--archlist=' + rpm_arch + ',noarch',
                   '--qf', '%{name}|%{epoch}|%{version}|%{release}|%{arch}|%{repoid}']
        raw = run(command)
    (output / 'ubi-repoquery.tsv').write_text(raw)
    packages = {}
    seen = set()
    for line in raw.splitlines():
        name, epoch, version, release, arch, repo = line.split('|')
        if repo not in REPOS or arch not in {rpm_arch, 'noarch'}:
            raise ValueError('unexpected repository or architecture in query result')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+_.-]*', name):
            raise ValueError('invalid package name in query result')
        evr = parse_evr(f'{epoch}:{version}-{release}')
        packages.setdefault((name, arch), []).append(evr)
        seen.add(repo)
    if seen != REPOS:
        raise ValueError('missing/empty UBI repository in query result')
    return packages


def findings(trivy, grype):
    if trivy.get('SchemaVersion') != 2 or not isinstance(trivy.get('Results'), list):
        raise ValueError('missing/invalid Trivy results')
    if not isinstance(grype.get('matches'), list) or not grype.get('descriptor', {}).get('version'):
        raise ValueError('missing/invalid Grype results')
    for result in trivy['Results']:
        for item in result.get('Vulnerabilities') or []:
            purl = item.get('PkgIdentifier', {}).get('PURL', '')
            yield dict(scanner='Trivy', cve=item['VulnerabilityID'], package=item['PkgName'],
                       severity=item['Severity'].upper(), installed=item.get('InstalledVersion', ''),
                       fixed=item.get('FixedVersion') or ('unspecified' if item.get('Status') == 'fixed' else ''),
                       rpm=result.get('Class') == 'os-pkgs' and result.get('Type') == 'redhat' and purl.startswith('pkg:rpm/'))
    for item in grype['matches']:
        vulnerability, artifact = item['vulnerability'], item['artifact']
        fix = vulnerability.get('fix', {})
        fixed = ','.join(fix.get('versions', []))
        if fix.get('state') == 'fixed' and not fixed:
            fixed = 'unspecified'
        yield dict(scanner='Grype', cve=vulnerability['id'], package=artifact['name'],
                   severity=vulnerability['severity'].upper(), installed=artifact.get('version', ''),
                   fixed=fixed, rpm=artifact.get('type') == 'rpm')


def classify(item, locked, available):
    if not item['fixed']:
        return 'unfixed', 'no vendor fix reported'
    if not item['rpm']:
        return 'blocked', 'non-RPM or unrecognized package type'
    package = locked.get(item['package'])
    if package is None or package['repository'] not in REPOS:
        return 'blocked', 'package is not a locked UBI RPM'
    installed = f"{package['epoch']}:{package['version']}-{package['release']}"
    if compare_evr(item['installed'], installed) != 0:
        raise ValueError('scanner version does not match the locked RPM')
    # Ambiguous ranges or multiple stream fixes are not evidence of unavailability.
    fixed = parse_evr(item['fixed'])
    versions = available().get((item['package'], package['architecture']), [])
    if any(compare_evr(version, fixed) >= 0 for version in versions):
        return 'blocked', 'vendor fix is available from UBI'
    return 'deferred', 'vendor fix is not yet available from UBI'


def summary(report):
    lines = ['## Vulnerability gate', '', f"Architecture: {report['architecture']}", '',
             '| Scanner | Severity | Finding | Package | Vendor fixed version | Decision | Reason |',
             '| --- | --- | --- | --- | --- | --- | --- |']
    for item in report['findings']:
        values = [item[k] for k in ('scanner', 'severity', 'cve', 'package', 'fixed', 'decision', 'reason')]
        lines.append('| ' + ' | '.join(str(v).replace('|', '&#124;').replace('\n', ' ') for v in values) + ' |')
    lines.extend(['', *[f'BLOCKED: {error}' for error in report['errors']], '',
                  'Deferred findings remain in the complete scanner reports and are rechecked on every run.', ''])
    return '\n'.join(lines)


def main(directory, architecture=None, lock_path=None):
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    report = {'schema_version': 1, 'architecture': architecture, 'findings': [], 'errors': []}
    snapshot = None
    query_error = None

    def available():
        nonlocal snapshot, query_error
        if query_error is not None:
            raise ValueError(query_error)
        if snapshot is None:
            try:
                snapshot = query_repositories(architecture, root)
            except Exception as exc:
                query_error = str(exc)
                raise
        return snapshot

    try:
        locked = {}
        if lock_path:
            lock = validate_lock(Path(lock_path))
            if architecture not in ARCHES or lock['architecture'] != architecture:
                raise ValueError('lock/runner architecture mismatch')
            locked = {p['name']: p for p in lock['packages']}
        trivy = json.loads((root / 'trivy-all.json').read_text())
        grype = json.loads((root / 'grype-all.json').read_text())
        for item in findings(trivy, grype):
            if item['severity'] not in {'HIGH', 'CRITICAL'}:
                continue
            try:
                decision, reason = classify(item, locked, available)
            except Exception as exc:
                decision, reason = 'blocked', f'cannot establish UBI availability: {exc}'
            report['findings'].append({**item, 'decision': decision, 'reason': reason})
    except Exception as exc:
        report['errors'].append(str(exc))
    if REPO_FILE.is_file():
        report['repository_sha256'] = hashlib.sha256(REPO_FILE.read_bytes()).hexdigest()
    report['blocked'] = bool(report['errors'] or any(f['decision'] == 'blocked' for f in report['findings']))
    (root / 'gate-results.json').write_text(json.dumps(report, indent=2) + '\n')
    rendered = summary(report)
    (root / 'gate-summary.md').write_text(rendered)
    print(rendered)
    return int(report['blocked'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('directory')
    parser.add_argument('--architecture', choices=ARCHES)
    parser.add_argument('--lock')
    args = parser.parse_args()
    raise SystemExit(main(args.directory, args.architecture, args.lock))
