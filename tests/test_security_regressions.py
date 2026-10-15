from __future__ import annotations

import asyncio
import gzip
import json
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from reconmap.adapters import execute, identify
from reconmap.analysis import js_strings
from reconmap.cli import main
from reconmap.config import Scope, default_config
from reconmap.engine import Response, Scanner, bounded_response, prepare_run
from reconmap.reporting import generate_report
from reconmap.scope import ScopePolicy
from reconmap.security import redact, redact_data
from reconmap.storage import Store, atomic_json, pid_alive


def test_remaining_time_caps_http_operation(tmp_path):
    config = default_config('http://127.0.0.1:8765/'); config.scope.lab = True
    config.modules = ['http']; config.budgets.minutes = 0.001
    run, manifest = prepare_run(config, 'http://127.0.0.1:8765/', tmp_path)
    scanner = Scanner(run, manifest, config, {})
    seen = []
    class Session:
        def get(self, url, **kwargs):
            seen.append(kwargs['timeout'].total)
            raise TimeoutError('fixture: request timeout')
    scanner.session = Session()
    try:
        with pytest.raises(TimeoutError):
            asyncio.run(scanner.request(manifest['target']))
        assert 0 < seen[0] <= 0.06
    finally:
        scanner.store.close()


def test_exhausted_http_retries_mark_coverage_partial(tmp_path):
    config = default_config('example.com'); config.mode = 'demo'; config.modules = ['http']
    config.budgets.retries = 1
    run, manifest = prepare_run(config, 'example.com', tmp_path)
    assert asyncio.run(Scanner(run, manifest, config, {}, {
        manifest['target']: Response(500, {}, b'fixture server failure')
    }).run_scan()) == 'partial'
    store = Store(run)
    try:
        assert store.meta('requests') == 2
        assert next(s for s in store.rows('stages') if s['name'] == 'http')['state'] == 'partial'
    finally:
        store.close()


@pytest.mark.parametrize('path', ['//private/a', '/%2fprivate/a', '/private//a', '/%2F%2Fprivate/a'])
def test_duplicate_separator_cannot_bypass_exclusion(path):
    policy = ScopePolicy(Scope(hosts=['example.com'], exclude_paths=['/private']))
    assert not policy.decision('https://example.com' + path)[0]


@pytest.mark.parametrize('address', ['224.0.0.1', '239.255.255.250', 'ff02::1', 'ff0e::1', '::ffff:224.0.0.1'])
def test_public_policy_rejects_multicast(address):
    assert not ScopePolicy(Scope(hosts=['example.com'])).ip_allowed(address)


@pytest.mark.parametrize('code,method', [
    ('fetch("/api/run", {"method":"POST"})', 'POST'),
    ('fetch("/api/run", {method:verb})', 'UNKNOWN'),
    ('fetch("/api/run", options)', 'UNKNOWN'),
    ('fetch("/api/run", {...options})', 'UNKNOWN'),
    ('fetch("/api/run", {[key]:value})', 'UNKNOWN'),
    ('fetch("/api/run", {method:"GET", method:"POST"})', 'POST'),
    ('fetch("/api/run", {method:"OPTIONS"})', 'OPTIONS'),
    ('client.open("POST", "/api/run")', 'POST'),
    ('client.head("/api/run")', 'HEAD'),
    ('fetch("/api/run", {headers:{"x-method":"POST"}})', 'GET'),
])
def test_ast_method_options(code, method):
    routes, _, _ = js_strings(code)
    assert next(r for r in routes if r['value'] == '/api/run')['method'] == method


def test_local_map_non_get_and_unknown_methods_are_never_queued(tmp_path):
    source = tmp_path / 'input.map'
    source.write_text(json.dumps({'version': 3, 'sourcesContent': [
        'fetch("/api/post", {"method":"POST"}); fetch("/api/dynamic", options); fetch("/api/get");'
    ]}))
    config = default_config('example.com'); config.mode = 'demo'; config.local_inputs = [str(source)]
    run, manifest = prepare_run(config, 'example.com', tmp_path / 'runs')
    scanner = Scanner(run, manifest, config, {})
    try:
        scanner.local_inputs()
        assert {r['url'] for r in scanner.store.rows('jobs')} == {'https://example.com/api/get'}
        assert len(scanner.store.rows('urls')) == 3  # still retain non-GET evidence
    finally:
        scanner.store.close()


def test_real_jsluice_cannot_override_native_method_restrictions(tmp_path):
    binary = os.environ.get('RECONMAP_TEST_JSLUICE')
    if not binary:
        pytest.skip('Requires the reviewed optional jsluice binary')
    config = default_config('example.com'); config.mode = 'demo'; config.modules = ['http', 'jsluice']
    run, manifest = prepare_run(config, 'example.com', tmp_path)
    scanner = Scanner(run, manifest, config, {'jsluice': identify('jsluice', binary)})
    try:
        scanner.save_artifact(b'fetch("/api/post", {"method":"POST"}); fetch("/api/unknown", options); fetch("/api/get");', 'js', manifest['target'])
        scanner.save_artifact(b'fetch("/api/second");', 'js', manifest['target'])
        asyncio.run(scanner.local_tools())
        assert {j['url'] for j in scanner.store.rows('jobs')} == {'https://example.com/api/get', 'https://example.com/api/second'}
        assert len(list((run / 'raw/jsluice').glob('*/stdout.txt'))) == 2
    finally:
        scanner.store.close()


def test_malformed_references_do_not_abort_other_discoveries(tmp_path):
    config = default_config('example.com'); config.mode = 'demo'
    run, manifest = prepare_run(config, 'example.com', tmp_path)
    scanner = Scanner(run, manifest, config, {})
    try:
        scanner.process_response(manifest['target'], Response(200, {'content-type': 'text/html'},
            b'<a href="http://[">bad</a><a href="/good">good</a><form action="http://["></form>'
            b'<script>fetch("http://[");fetch("/api/good");</script>'), 0, 1)
        assert {r['url'] for r in scanner.store.rows('jobs')} == {'https://example.com/good', 'https://example.com/api/good'}
        assert len([r for r in scanner.store.rows('observations') if r['kind'] == 'invalid_reference']) == 3
    finally:
        scanner.store.close()


def test_private_key_and_authorization_redacted_in_every_export(tmp_path):
    config = default_config('example.com'); config.mode = 'demo'
    run, _ = prepare_run(config, 'example.com', tmp_path)
    text = '-----BEGIN PRIVATE KEY-----\nSYNTHETIC_KEY_BODY_ONLY\n-----END PRIVATE KEY-----\nAuthorization: Bearer synthetic_credential_123'
    store = Store(run)
    try:
        store.observed('fixture', 'fixture', {'excerpt': text}, 'fixture')
        generate_report(run, store)
    finally:
        store.close()
    for folder in ['reports', 'normalized']:
        for file in (run / folder).iterdir():
            assert 'SYNTHETIC_KEY_BODY_ONLY' not in file.read_text(encoding='utf-8-sig')
            assert 'synthetic_credential_123' not in file.read_text(encoding='utf-8-sig')
    assert 'SYNTHETIC_KEY_BODY_ONLY' not in redact(text.split('-----END')[0])


@pytest.mark.parametrize('name', ['AWS_SECRET_ACCESS_KEY', 'SECRET_KEY', 'DB_PASSWORD', 'access_token', 'DATABASE_URL', 'apiKey'])
def test_env_secret_names_and_short_values_are_redacted(name):
    assert '1234' not in redact(name + '=1234')
    assert '1234' not in json.dumps(redact_data({name: '1234'}))


@pytest.mark.parametrize('entry', ['reports', 'normalized/observations.jsonl', 'recon.sqlite-wal', 'raw'])
def test_report_rejects_links_and_preserves_external_files(tmp_path, entry):
    config = default_config('example.com'); config.mode = 'demo'
    run, _ = prepare_run(config, 'example.com', tmp_path / 'runs')
    external = tmp_path / 'external'; external.mkdir()
    marker = external / 'observations.jsonl'; marker.write_text('keep')
    path = run / entry
    directory = path.is_dir()
    if directory:
        path.rmdir()
    try:
        path.symlink_to(external if directory else marker, target_is_directory=directory)
    except OSError:
        pytest.skip('Creating symlinks requires native OS privileges')
    assert main(['report', '--run', str(run)]) == 3
    assert marker.read_text() == 'keep'
    assert sorted(p.name for p in external.iterdir()) == ['observations.jsonl']
    assert not (run / 'run.lock').exists()


def test_report_rejects_hardlinks_and_invalid_artifact_paths(tmp_path):
    config = default_config('example.com'); config.mode = 'demo'
    run, _ = prepare_run(config, 'example.com', tmp_path / 'runs')
    marker = tmp_path / 'outside'; marker.write_text('keep')
    linked = run / 'reports/summary.md'
    os.link(marker, linked)
    assert main(['report', '--run', str(run)]) == 3
    assert marker.read_text() == 'keep'
    linked.unlink()
    store = Store(run)
    store.execute('INSERT INTO artifacts(hash,path,kind,bytes) VALUES(?,?,?,?)', ('a'*64, '../../outside', 'js', 4))
    store.close()
    assert main(['report', '--run', str(run)]) == 3
    assert marker.read_text() == 'keep'


def test_invalid_metadata_and_database_fail_without_traceback(tmp_path, capsys):
    config = default_config('example.com'); config.mode = 'demo'
    run, manifest = prepare_run(config, 'example.com', tmp_path)
    atomic_json(run / 'manifest.json', [])
    assert main(['scan', '--resume', str(run)]) == 3
    atomic_json(run / 'manifest.json', manifest)
    (run / 'recon.sqlite').write_bytes(b'corrupt database')
    assert main(['report', '--run', str(run)]) == 3
    assert 'Database error' in capsys.readouterr().err
    empty = tmp_path / 'empty'; empty.mkdir()
    assert main(['report', '--run', str(empty)]) == 3
    assert not list(empty.iterdir())


def test_report_csp_only_allows_its_exact_script(tmp_path):
    import base64
    import hashlib
    from reconmap.reporting import REPORT_SCRIPT
    config = default_config('example.com'); config.mode = 'demo'
    run, manifest = prepare_run(config, 'example.com', tmp_path)
    generate_report(run)
    html = (run / 'reports/index.html').read_text()
    digest = base64.b64encode(hashlib.sha256(REPORT_SCRIPT.encode()).digest()).decode()
    assert f"script-src 'sha256-{digest}'" in html
    assert "script-src 'unsafe-inline'" not in html
    manifest['requests'] = '<script>alert(1)</script>'
    atomic_json(run / 'manifest.json', manifest)
    assert main(['report', '--run', str(run)]) == 3


def test_old_execution_policy_can_report_but_cannot_resume(tmp_path):
    config = default_config('example.com'); config.mode = 'demo'
    run, manifest = prepare_run(config, 'example.com', tmp_path)
    del manifest['policy_revision']; atomic_json(run / 'manifest.json', manifest)
    assert main(['report', '--run', str(run)]) == 0
    assert main(['scan', '--resume', str(run)]) == 3


@pytest.mark.parametrize('size,truncated', [(1023, False), (1024, False), (1025, True), (20000, True)])
def test_response_cap_preserves_prefix_and_exact_size(size, truncated):
    class Content:
        async def iter_chunked(self, size):
            yield b'x' * length
    length = size
    response = SimpleNamespace(status=200, headers={}, content=Content())
    result = asyncio.run(bounded_response(response, 1024))
    assert result.body == b'x' * min(size, 1024)
    assert result.truncated == truncated


def test_truncated_compressed_body_is_not_reported_as_complete():
    class Content:
        async def iter_chunked(self, size):
            yield gzip.compress(b'fixture')[:-5]
    response = SimpleNamespace(status=200, headers={'content-encoding': 'gzip'}, content=Content())
    with pytest.raises(ValueError, match='Incomplete'):
        asyncio.run(bounded_response(response, 1024))


def test_doctor_invalid_executable_is_dependency_diagnostic(tmp_path):
    path = tmp_path / 'invalid.exe'; path.write_bytes(b'not an executable'); path.chmod(0o700)
    info = identify('gitleaks', str(path))
    assert not info.supported and info.reason


def test_continuous_output_cap_does_not_deadlock(tmp_path):
    async def go():
        with pytest.raises(ValueError, match='cap'):
            await execute([sys.executable, '-c', 'import os\nwhile True: os.write(1,b"x"*65536)'], tmp_path, 2, limit=1024)
    started = time.monotonic()
    asyncio.run(go())
    assert time.monotonic() - started < 5


@pytest.mark.skipif(os.name == 'nt', reason='POSIX process groups; native Windows lifecycle still needs verification')
def test_timeout_kills_descendant_after_parent_exits(tmp_path):
    pidfile = tmp_path / 'child.pid'
    code = 'import subprocess,sys,pathlib; p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(30)"]);pathlib.Path(sys.argv[1]).write_text(str(p.pid))'
    async def go():
        with pytest.raises(TimeoutError):
            await execute([sys.executable, '-c', code, str(pidfile)], tmp_path, 0.5)
    asyncio.run(go())
    pid = int(pidfile.read_text())
    stat = Path(f'/proc/{pid}/stat')
    # Pipe EOF can arrive during kernel exit, just before /proc changes to Z.
    # Verify bounded termination rather than racing that final state transition.
    deadline = time.monotonic() + 2
    while stat.exists() and time.monotonic() < deadline:
        try:
            if stat.read_text().split()[2] == 'Z':
                break
        except FileNotFoundError:
            break
        time.sleep(0.01)
    if stat.exists():
        assert stat.read_text().split()[2] == 'Z'
    else:
        assert not pid_alive(pid)
