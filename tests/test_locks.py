import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import artifacts


class Locks(unittest.TestCase):
    def test_committed_locks(self):
        for arch in artifacts.ARCHES:
            artifacts.validate_lock(Path(f'artifacts/locks/{arch}.json'), Path('artifacts/lock-inputs.json'))

    def test_reject_mutations(self):
        original = json.loads(Path('artifacts/locks/amd64.json').read_text())
        mutations = [
            lambda x: x['packages'][0].update(sha256='0'),
            lambda x: x['packages'][0].update(architecture='aarch64'),
            lambda x: x['packages'][0].update(url='http://evil.example/a.rpm'),
            lambda x: x['packages'][0].update(signing_key_fingerprint='0' * 40),
            lambda x: x['base_images']['runtime'].update(reference='ubi9:latest'),
            lambda x: x['packages'].append(x['packages'][0]),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'lock.json'
            for mutate in mutations:
                value = copy.deepcopy(original)
                mutate(value)
                path.write_text(json.dumps(value))
                with self.assertRaises(artifacts.LockError):
                    artifacts.validate_lock(path)

    def test_runtime_version_follows_input(self):
        inputs = artifacts.validate_inputs(Path('artifacts/lock-inputs.json'))
        self.assertIn(f'org.opencontainers.image.version="{inputs["openresty_version"]}"', Path('Containerfile').read_text())


if __name__ == '__main__':
    unittest.main()
