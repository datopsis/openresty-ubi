import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class ScanGate(unittest.TestCase):
    def test_each_scanner_blocks_only_fixed_high_critical(self):
        for scanner in ('trivy', 'grype'):
            for severity in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
                for fixed in (False, True):
                    with self.subTest(scanner=scanner, severity=severity, fixed=fixed), tempfile.TemporaryDirectory() as directory:
                        trivy = {'SchemaVersion': 2, 'Results': []}
                        grype = {'matches': [], 'descriptor': {'version': 'test'}}
                        if scanner == 'trivy':
                            trivy['Results'] = [{'Vulnerabilities': [{'VulnerabilityID': 'TEST', 'PkgName': 'fixture', 'Severity': severity, 'FixedVersion': '2' if fixed else ''}]}]
                        else:
                            grype['matches'] = [{'artifact': {'name': 'fixture'}, 'vulnerability': {'id': 'TEST', 'severity': severity, 'fix': {'state': 'fixed' if fixed else 'not-fixed', 'versions': ['2'] if fixed else []}}}]
                        Path(directory, 'trivy-all.json').write_text(json.dumps(trivy))
                        Path(directory, 'grype-all.json').write_text(json.dumps(grype))
                        result = subprocess.run([sys.executable, 'scripts/scan-gate.py', directory], capture_output=True)
                        self.assertEqual(result.returncode != 0, fixed and severity in ('HIGH', 'CRITICAL'))

    def test_missing_reports_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertNotEqual(subprocess.run([sys.executable, 'scripts/scan-gate.py', directory], capture_output=True).returncode, 0)
