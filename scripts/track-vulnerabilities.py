#!/usr/bin/env python3
"""Maintain one issue from trusted default-branch scheduled scan results."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


TITLE = 'UBI vulnerability fix availability'
MARKER = '<!-- ubi-fix-tracking -->'


def gh(*arguments):
    return subprocess.check_output(['gh', *arguments], text=True, timeout=60)


def collect(directory):
    state = {}
    for architecture in ('amd64', 'arm64'):
        try:
            paths = list(Path(directory).glob(f'image-security-{architecture}/gate-results.json'))
            if len(paths) != 1:
                raise ValueError('missing architecture gate report')
            report = json.loads(paths[0].read_text())
            if report['schema_version'] != 1 or report['architecture'] != architecture:
                raise ValueError('invalid architecture gate report')
            if not isinstance(report['errors'], list) or not isinstance(report['findings'], list):
                raise ValueError('invalid gate results')
            rows = []
            for item in report['findings']:
                if item['decision'] not in {'blocked', 'deferred', 'unfixed'}:
                    raise ValueError('unknown gate decision')
                if item['decision'] != 'unfixed':
                    rows.append({k: item[k] for k in ('scanner', 'cve', 'package', 'severity', 'fixed', 'decision', 'reason')})
            state[architecture] = {'findings': sorted(rows, key=lambda x: json.dumps(x, sort_keys=True)),
                                   'errors': report['errors']}
        except (ValueError, KeyError, TypeError, OSError) as exc:
            state[architecture] = {'findings': [], 'errors': [f'BLOCKED: {exc}']}
    return state


def render(state, url, digest):
    lines = [MARKER, f'<!-- state:{digest} -->', '',
             'Vendor-fixed High/Critical findings are deferred only while a successful query proves the fix is unavailable in UBI.',
             'When UBI publishes a suitable RPM, the next scan blocks until the image locks are refreshed.',
             f'Evidence: {url}', '',
             '| Architecture | Scanner | Finding | Package | Vendor fixed version | State | Reason |',
             '| --- | --- | --- | --- | --- | --- | --- |']
    for arch, report in state.items():
        for item in report['findings']:
            values = [arch, *[item[k] for k in ('scanner', 'cve', 'package', 'fixed', 'decision', 'reason')]]
            lines.append('| ' + ' | '.join(str(v).replace('|', '&#124;').replace('\n', ' ') for v in values) + ' |')
        for error in report['errors']:
            lines.append(f'\n{arch}: {error}')
    if not any(r['findings'] or r['errors'] for r in state.values()):
        lines.append('\nNo deferred or blocking findings remain in either architecture report.')
    return '\n'.join(lines) + '\n'


def update(directory, repository, url):
    state = collect(directory)
    digest = hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest()
    active = any(r['findings'] or r['errors'] for r in state.values())
    body = render(state, url, digest)
    body_file = Path(directory) / 'tracking-body.md'
    body_file.write_text(body)
    issues = json.loads(gh('issue', 'list', '--repo', repository, '--state', 'all', '--limit', '100',
                           '--search', f'"{TITLE}" in:title', '--json', 'number,title,body,state'))
    issues = [issue for issue in issues if issue['title'] == TITLE]
    if len(issues) > 1 or (issues and MARKER not in issues[0]['body']):
        raise ValueError('ambiguous tracking issue; refusing to create or edit another issue')
    if not issues:
        if active:
            print(gh('issue', 'create', '--repo', repository, '--title', TITLE, '--body-file', str(body_file)))
        return
    issue = issues[0]
    if f'<!-- state:{digest} -->' in issue['body']:
        return
    number = str(issue['number'])
    if active and issue['state'] == 'CLOSED':
        gh('issue', 'reopen', number, '--repo', repository)
    # Comment first: a failed notification must not advance the saved state.
    comment = Path(directory) / 'tracking-comment.md'
    comment.write_text('Vulnerability availability state changed.\n\n' + body)
    gh('issue', 'comment', number, '--repo', repository, '--body-file', str(comment))
    gh('issue', 'edit', number, '--repo', repository, '--body-file', str(body_file))
    if not active and issue['state'] == 'OPEN':
        gh('issue', 'close', number, '--repo', repository)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('directory')
    parser.add_argument('--repository', required=True)
    parser.add_argument('--run-url', required=True)
    args = parser.parse_args()
    update(args.directory, args.repository, args.run_url)
