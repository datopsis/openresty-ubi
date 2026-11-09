#!/usr/bin/env python3
"""Verify locked manifest membership and Red Hat simple-signing signatures."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import urllib.request

from artifacts import validate_inputs, sha256_file


def verify_signature(payload, digest, repository):
    critical = payload['critical']
    if critical['type'] != 'atomic container signature':
        raise ValueError('unexpected base signature type')
    if critical['image']['docker-manifest-digest'] != digest:
        raise ValueError('base signature digest mismatch')
    identity = critical['identity']['docker-reference']
    if not identity.startswith(repository + ':'):
        raise ValueError(f'base signature repository mismatch: {identity}')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--inputs', type=Path, default=Path('artifacts/lock-inputs.json'))
    parser.add_argument('--architecture', choices=['amd64', 'arm64'], required=True)
    parser.add_argument('--keys', type=Path, required=True)
    args = parser.parse_args()
    inputs = validate_inputs(args.inputs)
    with tempfile.TemporaryDirectory() as directory:
        home = Path(directory)
        fingerprints = []
        for key in inputs['signing_keys']:
            if not key['id'].startswith('redhat-'):
                continue
            path = args.keys / key['url'].rsplit('/', 1)[1]
            if sha256_file(path) != key['sha256']:
                raise ValueError('base key digest mismatch')
            shown = subprocess.check_output(['gpg', '--batch', '--homedir', directory, '--show-keys', '--with-colons', str(path)], text=True)
            if f'fpr:::::::::{key["fingerprint"]}:' not in shown:
                raise ValueError('base key fingerprint mismatch')
            fingerprints.append(key['fingerprint'])
            subprocess.run(['gpg', '--batch', '--homedir', directory, '--import', str(path)], check=True, capture_output=True)
        for role, reference in inputs['base_images'].items():
            repository = reference.split('@')[0].rsplit(':', 1)[0]
            canonical = repository + '@' + reference.rsplit('@', 1)[1]
            raw = subprocess.check_output(['skopeo', 'inspect', '--raw', 'docker://' + canonical])
            if 'sha256:' + hashlib.sha256(raw).hexdigest() != reference.rsplit('@', 1)[1]:
                raise ValueError('base manifest-list digest mismatch')
            manifests = json.loads(raw)['manifests']
            platforms = {m['platform']['architecture'] for m in manifests if m['platform']['os'] == 'linux'}
            if not {'amd64', 'arm64'} <= platforms:
                raise ValueError('base must cover both target architectures')
            child = next(m['digest'] for m in manifests if m['platform']['os'] == 'linux' and m['platform']['architecture'] == args.architecture)
            repository = reference.split('@')[0].rsplit(':', 1)[0]
            raw = subprocess.check_output(['skopeo', 'inspect', '--raw', 'docker://' + repository + '@' + child])
            if 'sha256:' + hashlib.sha256(raw).hexdigest() != child:
                raise ValueError('base child manifest digest mismatch')
            path = repository.split('/', 1)[1] + '@' + child.replace(':', '=')
            url = 'https://access.redhat.com/webassets/docker/content/sigstore/' + path + '/signature-1'
            signature = home / 'signature'
            with urllib.request.urlopen(url, timeout=60) as response:
                signature.write_bytes(response.read())
            result = subprocess.run(['gpg', '--batch', '--homedir', directory, '--status-fd=2', '--decrypt', str(signature)], check=True, text=True, capture_output=True)
            if not any(f'[GNUPG:] VALIDSIG {f} ' in result.stderr for f in fingerprints):
                raise ValueError('base signature does not use a pinned Red Hat key')
            verify_signature(json.loads(result.stdout), child, repository)
            print(f'Verified {role} linux/{args.architecture}: {child}; pinned Red Hat publisher signature')


if __name__ == '__main__':
    main()
