import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('tracker', 'scripts/track-vulnerabilities.py')
tracker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tracker)


class Tracking(unittest.TestCase):
    def write_reports(self, root, decision):
        for arch in ('amd64', 'arm64'):
            directory = root / f'image-security-{arch}'
            directory.mkdir(exist_ok=True)
            item = dict(scanner='test', cve='TEST', package='fixture', severity='HIGH',
                        fixed='2.0-1', decision=decision, reason='test')
            (directory / 'gate-results.json').write_text(json.dumps(dict(
                schema_version=1, architecture=arch, errors=[], findings=[item] if decision else [])))

    def test_create_idempotence_transition_close_reopen(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_reports(root, 'deferred')
            with patch.object(tracker, 'gh', return_value='[]') as gh:
                tracker.update(directory, 'owner/repo', 'https://example.test/run')
                self.assertEqual(gh.call_args_list[-1].args[:2], ('issue', 'create'))
            body = (root / 'tracking-body.md').read_text()
            issue = dict(number=1, title=tracker.TITLE, body=body, state='OPEN')
            with patch.object(tracker, 'gh', return_value=json.dumps([issue])) as gh:
                tracker.update(directory, 'owner/repo', 'https://example.test/new-run')
                self.assertEqual(gh.call_count, 1)
            self.write_reports(root, 'blocked')
            with patch.object(tracker, 'gh', return_value=json.dumps([issue])) as gh:
                tracker.update(directory, 'owner/repo', 'https://example.test/new-run')
                self.assertEqual([c.args[1] for c in gh.call_args_list], ['list', 'comment', 'edit'])
            self.write_reports(root, None)
            with patch.object(tracker, 'gh', return_value=json.dumps([issue])) as gh:
                tracker.update(directory, 'owner/repo', 'https://example.test/new-run')
                self.assertEqual(gh.call_args_list[-1].args[1], 'close')
            issue.update(state='CLOSED', body=(root / 'tracking-body.md').read_text())
            self.write_reports(root, 'deferred')
            with patch.object(tracker, 'gh', return_value=json.dumps([issue])) as gh:
                tracker.update(directory, 'owner/repo', 'https://example.test/new-run')
                self.assertEqual([c.args[1] for c in gh.call_args_list], ['list', 'reopen', 'comment', 'edit'])

    def test_missing_report_is_blocked(self):
        with tempfile.TemporaryDirectory() as directory:
            state = tracker.collect(directory)
            self.assertTrue(all(report['errors'] for report in state.values()))

    def test_clean_does_not_create_issue(self):
        with tempfile.TemporaryDirectory() as directory:
            self.write_reports(Path(directory), None)
            with patch.object(tracker, 'gh', return_value='[]') as gh:
                tracker.update(directory, 'owner/repo', 'https://example.test/run')
                self.assertEqual(gh.call_count, 1)
