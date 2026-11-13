import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path('scripts').resolve()))
spec = importlib.util.spec_from_file_location('scan_gate', 'scripts/scan-gate.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class UbiGate(unittest.TestCase):
    def setUp(self):
        self.item = dict(scanner='test', cve='TEST', package='fixture', severity='HIGH',
                         installed='2.37.4-25.el9', fixed='2.37.4-28.el9_9', rpm=True)
        self.locked = {'fixture': dict(epoch=0, version='2.37.4', release='25.el9',
                                      architecture='x86_64', repository='ubi-9-baseos-rpms')}

    def classify(self, versions):
        return gate.classify(self.item, self.locked, lambda: {('fixture', 'x86_64'): versions})[0]

    def test_available_blocks_unavailable_defers(self):
        self.assertEqual(self.classify(['2.37.4-25.el9']), 'deferred')
        self.assertEqual(self.classify(['2.37.4-28.el9_9']), 'blocked')
        self.assertEqual(self.classify(['2.37.4-28.el9_9.1']), 'blocked')
        self.item['fixed'] = '2.37.4-28.el9_9.1'
        self.assertEqual(self.classify(['2.37.4-28.el9_9']), 'deferred')

    def test_epoch_and_release_comparison(self):
        for left, right, expected in [
            ('2.37.4-28.el9_9', '2.37.4-28.el9_9.1', -1),
            ('1:1.0-1', '0:99.0-9', 1),
            ('2.0-1', '0:2.0-1', 0),
            ('2.0-10', '2.0-9', 1),
            ('2.0~rc1-1', '2.0-1', -1),
            ('2.0^git1-1', '2.0-1', 1),
        ]:
            with self.subTest(left=left, right=right):
                self.assertEqual(gate.compare_evr(left, right), expected)

    def test_unparsable_or_ambiguous_versions_fail(self):
        for value in ['', 'unspecified', '>=2.0-1', '2.0', '2.0-1,3.0-1', 'x:2.0-1', '2.0-1\n', '"%{lua:1}"']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                gate.parse_evr(value)

    def test_non_rpm_and_non_ubi_block_without_query(self):
        def forbidden():
            self.fail('must not query UBI for an ineligible package')
        self.item['rpm'] = False
        self.assertEqual(gate.classify(self.item, self.locked, forbidden)[0], 'blocked')
        self.item['rpm'] = True
        self.locked['fixture']['repository'] = 'openresty-stable'
        self.assertEqual(gate.classify(self.item, self.locked, forbidden)[0], 'blocked')

    def test_missing_package_and_version_mismatch_fail(self):
        with self.assertRaises(ValueError):
            self.classify([])
        self.item['installed'] = '2.0-1'
        with self.assertRaises(ValueError):
            self.classify(['2.37.4-25.el9'])

    def reports(self, root, scanner):
        trivy = {'SchemaVersion': 2, 'Results': []}
        grype = {'matches': [], 'descriptor': {'version': 'test'}}
        if scanner == 'Trivy':
            trivy['Results'] = [{'Class': 'os-pkgs', 'Type': 'redhat', 'Vulnerabilities': [{
                'VulnerabilityID': 'TEST', 'PkgName': 'fixture', 'Severity': 'HIGH',
                'InstalledVersion': self.item['installed'], 'FixedVersion': self.item['fixed'],
                'PkgIdentifier': {'PURL': 'pkg:rpm/redhat/fixture@2.37.4-25.el9'}}]}]
        else:
            grype['matches'] = [{'artifact': {'name': 'fixture', 'version': self.item['installed'], 'type': 'rpm'},
                                 'vulnerability': {'id': 'TEST', 'severity': 'Critical',
                                                   'fix': {'state': 'fixed', 'versions': [self.item['fixed']]}}}]
        (root / 'trivy-all.json').write_text(json.dumps(trivy))
        (root / 'grype-all.json').write_text(json.dumps(grype))

    def test_both_scanners_end_to_end_fail_closed_and_report(self):
        cases = [(['2.37.4-25.el9'], False), (['2.37.4-28.el9_9'], True),
                 (ValueError('repository missing'), True),
                 (subprocess.TimeoutExpired('dnf', 180), True),
                 (subprocess.CalledProcessError(1, 'dnf'), True)]
        lock = {'architecture': 'amd64', 'packages': [{'name': 'fixture', **self.locked['fixture']}]}
        for scanner in ('Trivy', 'Grype'):
            for result, blocked in cases:
                with self.subTest(scanner=scanner, result=result), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    self.reports(root, scanner)
                    with patch.object(gate, 'validate_lock', return_value=lock), patch.object(gate, 'query_repositories') as query:
                        if isinstance(result, Exception):
                            query.side_effect = result
                        else:
                            query.return_value = {('fixture', 'x86_64'): result}
                        self.assertEqual(gate.main(root, 'amd64', 'lock.json'), int(blocked))
                    report = json.loads((root / 'gate-results.json').read_text())
                    self.assertEqual(report['blocked'], blocked)
                    self.assertEqual(report['findings'][0]['decision'], 'blocked' if blocked else 'deferred')
                    self.assertIn(self.item['fixed'], (root / 'gate-summary.md').read_text())

    def test_complete_query_and_failures(self):
        rows = '\n'.join(f'fixture|0|2.0|1|aarch64|{repo}' for repo in sorted(gate.REPOS))
        with tempfile.TemporaryDirectory() as directory, patch.object(gate, 'run', return_value=rows) as run:
            packages = gate.query_repositories('arm64', Path(directory))
            self.assertEqual(packages[('fixture', 'aarch64')], ['0:2.0-1'] * 3)
            command = run.call_args.args[0]
            self.assertIn('--forcearch=aarch64', command)
            self.assertIn('--refresh', command)
            self.assertIn('--setopt=*.skip_if_unavailable=0', command)
        for output in ['', rows.splitlines()[0], rows.replace('aarch64', 'x86_64'), rows + '\nwarning']:
            with self.subTest(output=output), tempfile.TemporaryDirectory() as directory:
                with patch.object(gate, 'run', return_value=output), self.assertRaises(ValueError):
                    gate.query_repositories('arm64', Path(directory))
        with patch.object(gate, 'REPO_FILE', Path('/nonexistent/ubi.repo')):
            with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
                gate.query_repositories('amd64', Path(directory))

    def test_query_success_with_warning_is_not_unavailable(self):
        with patch.object(gate.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '', 'repository unavailable')):
            with self.assertRaises(ValueError):
                gate.run(['dnf'])
