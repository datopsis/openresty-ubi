#!/usr/bin/env python3
"""Real HTTP and process-security evidence; run only against a native built image."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid

runtime = os.environ.get('CONTAINER_RUNTIME', 'podman')
image = os.environ.get('IMAGE', 'localhost/openresty-ubi:test')
arch = subprocess.check_output([runtime, 'image', 'inspect', '--format', '{{.Architecture}}', image], text=True).strip()
lock = json.loads(Path(f'artifacts/locks/{arch}.json').read_text())
base = ['--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges']
if 'podman' in runtime:
    base += ['--read-only-tmpfs=false']
tmpfs = ['--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777']
demo = ['-e', 'OPENRESTY_UBI_ALLOW_PLAINTEXT_DEMO=1']


def run(*args, check=True, timeout=30):
    result = subprocess.run([runtime, *args], text=True, capture_output=True, check=False, timeout=timeout)
    if check and result.returncode:
        print(result.stdout, result.stderr)
        result.check_returncode()
    return result


def negative(label, options, message):
    result = run('run', '--rm', *base, *options, image, check=False)
    assert result.returncode != 0, label
    assert message in result.stderr, (label, result.stderr)
    print(f'PASS negative: {label}')


negative('missing configuration', tmpfs, 'OPENRESTY_UBI_CONFIG')
negative('missing writable mount', demo, '/tmp')
negative('root identity', [*tmpfs, *demo, '--user=0:0'], 'refusing UID 0')
negative('missing config file', [*tmpfs, '-e', 'OPENRESTY_UBI_CONFIG=/missing.conf'], 'missing, empty, or unreadable')
with tempfile.TemporaryDirectory() as directory:
    config = Path(directory) / 'invalid.conf'
    config.write_text('this_is_not_a_directive;\n')
    config.chmod(0o644)
    negative('invalid configuration', [*tmpfs, '-v', f'{config}:/test.conf:ro', '-e', 'OPENRESTY_UBI_CONFIG=/test.conf'], 'invalid configuration: /test.conf')
    config.write_text('')
    negative('empty configuration', [*tmpfs, '-v', f'{config}:/test.conf:ro', '-e', 'OPENRESTY_UBI_CONFIG=/test.conf'], 'missing, empty, or unreadable')

version = run('run', '--rm', *base, image, '-v').stderr
assert f'openresty/{lock["openresty_version"]}' in version, version
assert run('image', 'inspect', '--format', '{{.Config.User}}', image).stdout.strip() == '999:0'
for uid in ('999', '12345'):
    name = 'openresty-test-' + uuid.uuid4().hex[:12]
    try:
        configuration = demo if uid == '999' else ['-v', f'{Path("container/nginx.conf").resolve()}:/test.conf:ro', '-e', 'OPENRESTY_UBI_CONFIG=/test.conf']
        run('run', '-d', '--name', name, *base, *tmpfs, *configuration, '--user', f'{uid}:0', '-p', '127.0.0.1::8080', image)
        port = run('port', name, '8080/tcp').stdout.strip().split(':')[-1]
        url = f'http://127.0.0.1:{port}'
        for attempt in range(50):
            try:
                with urllib.request.urlopen(url + '/healthz', timeout=1) as response:
                    assert response.read() == b'ok\n'
                break
            except (OSError, urllib.error.URLError):
                time.sleep(0.1)
        else:
            raise AssertionError(run('logs', name).stderr)
        # Repeated real requests exercise LuaJIT, CJSON and PCRE2, not just nginx -t.
        for request in range(20):
            with urllib.request.urlopen(url + '/lua', timeout=3) as response:
                body = json.load(response)
                major, minor, patch = map(int, lock['nginx_version'].split('.'))
                assert body['nginx'] == major * 1000000 + minor * 1000 + patch, body
                assert body['jit'].startswith('LuaJIT 2.1'), body
                assert body['regex'] == '42', body
        with urllib.request.urlopen(url + '/', timeout=3) as response:
            assert b'OpenResty on UBI 9' in response.read()
            assert response.headers['X-Content-Type-Options'] == 'nosniff'
            assert '1.31' not in response.headers['Server']
        # Read the kernel's actual process fields and mount options.
        report = run('exec', name, 'sh', '-ec', 'cat /proc/[0-9]*/status').stdout
        for line in report.splitlines():
            if line.startswith('Uid:'):
                assert all(int(v) == int(uid) for v in line.split()[1:]), line
            if line.startswith(('CapEff:', 'CapPrm:', 'CapBnd:')):
                assert int(line.split()[1], 16) == 0, line
            if line.startswith('NoNewPrivs:'):
                assert line.split()[1] == '1', line
        mounts = run('exec', name, 'cat', '/proc/mounts').stdout.splitlines()
        root_mount = next(line.split() for line in mounts if line.split()[1] == '/')
        assert 'ro' in root_mount[3].split(',')
        tmp_mount = next(line.split() for line in mounts if line.split()[1] == '/tmp')
        assert {'rw', 'noexec', 'nosuid', 'nodev'} <= set(tmp_mount[3].split(','))
        run('exec', name, 'sh', '-ec', '! touch /etc/readonly-probe; test ! -w /etc/nginx/nginx.conf; test ! -w /usr/bin/openresty')
        run('exec', name, 'sh', '-ec', 'for tool in rpm dnf microdnf yum opm gcc curl wget; do ! command -v "$tool"; done; test ! -d /etc/yum.repos.d; test ! -d /etc/pki/rpm-gpg')
        run('exec', name, 'sh', '-ec', 'test -z "$(find /usr /bin /sbin -type f -perm /6000 -print -quit)"')
        command = run('exec', name, 'cat', '/proc/1/cmdline').stdout
        assert 'nginx: master process' in command, command
        sockets = run('exec', name, 'cat', '/proc/net/tcp', '/proc/net/tcp6').stdout
        ports = [int(line.split()[1].split(':')[1], 16) for line in sockets.splitlines() if len(line.split()) > 3 and line.split()[3] == '0A']
        assert ports == [8080], ports
        run('stop', '--time', '15', name)
        assert run('inspect', '--format', '{{.State.ExitCode}}', name).stdout.strip() == '0'
        print(f'PASS uid={uid}: HTTP, LuaJIT, PCRE2, static content, versions, mounts, processes, capabilities, PID 1, shutdown')
    finally:
        run('rm', '-f', name, check=False)
