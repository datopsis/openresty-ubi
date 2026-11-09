#!/usr/bin/env python3
"""Block fixed High/Critical findings; missing/invalid reports fail closed."""
import json
from pathlib import Path
import sys


def findings(trivy, grype):
    # Validate success report shape before interpreting an empty result as clean.
    if trivy.get('SchemaVersion') != 2 or not isinstance(trivy.get('Results'), list):
        raise ValueError('missing/invalid Trivy results')
    if not isinstance(grype.get('matches'), list) or not grype.get('descriptor', {}).get('version'):
        raise ValueError('missing/invalid Grype results')
    for result in trivy['Results']:
        for item in result.get('Vulnerabilities') or []:
            yield ('Trivy', item['VulnerabilityID'], item['PkgName'], item['Severity'].upper(), item.get('FixedVersion') or '')
    for item in grype['matches']:
        vulnerability = item['vulnerability']
        fix = vulnerability.get('fix', {})
        fixed = ','.join(fix.get('versions', []))
        # An available fix with missing version detail still blocks.
        if fix.get('state') == 'fixed' and not fixed:
            fixed = 'available (version unspecified)'
        yield ('Grype', vulnerability['id'], item['artifact']['name'], vulnerability['severity'].upper(), fixed)


def main(directory):
    root = Path(directory)
    trivy = json.loads((root / 'trivy-all.json').read_text())
    grype = json.loads((root / 'grype-all.json').read_text())
    blocked = []
    for scanner, cve, package, severity, fix in findings(trivy, grype):
        if severity in {'HIGH', 'CRITICAL'}:
            print(f'{scanner}: {severity} {cve} {package}; fix: {fix or "not available"}')
            if fix:
                blocked.append(cve)
    if blocked:
        raise SystemExit(f'BLOCKED: {len(blocked)} fixed High/Critical scanner findings')
    print('PASS: neither scanner reports fixed High/Critical findings; full reports retain unfixed findings')


if __name__ == '__main__':
    main(sys.argv[1])
