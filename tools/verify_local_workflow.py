"""Reproducible CLI smoke run using synthetic fixtures and a scoped local server.

Run from an installed checkout. --output-root must be a new directory. Optional
--tool NAME=PATH overrides are forwarded to the selected offline integrations.
No external target or discovery provider is contacted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml

from reconmap.cli import main as reconmap
from reconmap.config import default_config


def hashes(directory):
    return {str(p.relative_to(directory)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in directory.rglob('*') if p.is_file()}


def verify(root, overrides):
    root.mkdir(parents=True, exist_ok=False)
    checks = []

    def command(args, expected=0):
        actual = reconmap(args)
        if actual not in (expected if isinstance(expected, tuple) else (expected,)):
            raise AssertionError(f'{args[0]} returned {actual}, expected {expected}')
        return actual

    demo_root = root / 'demo'
    command(['demo', '--output-root', str(demo_root)])
    original = demo_root / 'example.com'
    demo_requests = json.loads((original / 'manifest.json').read_text())['requests']
    before = hashes(original)
    command(['demo', '--output-root', str(demo_root)])
    assert (demo_root / '1_example.com').is_dir() and hashes(original) == before
    checks += ['native demo', 'collision allocation preserves earlier output']
    command(['scan', '--resume', str(original)])
    assert json.loads((original / 'manifest.json').read_text())['requests'] == demo_requests > 0
    before = hashes(original)
    command(['diff', '--baseline', str(original), '--current', str(demo_root / '1_example.com')])
    assert hashes(original) == before
    checks += ['completed demo resume', 'immutable baseline comparison']

    config = default_config('example.com')
    config.mode = 'demo'
    config.budgets.requests = 1
    config_path = root / 'one-request.yaml'
    config_path.write_text(yaml.safe_dump(config.model_dump()), encoding='utf-8')
    command(['scan', '--target', 'example.com', '--config', str(config_path), '--output-root', str(root / 'budget')], 2)
    limited = root / 'budget/example.com'
    command(['scan', '--resume', str(limited)], 2)
    assert json.loads((limited / 'manifest.json').read_text())['requests'] == 1
    checks += ['partial report at request cap', 'resume preserves exhausted budget']

    hits = []
    pages = {
        '/': (200, 'text/html', '<title>Local regression fixture</title><a href="/admin/login">Sign in</a><a href="/assets/css/adminlte.min.css">Style</a><a href="/redirect">Redirect</a><a href="/api/users/1">Users</a><a href="/api/users/2">Users</a><script src="/bundle.js"></script>'),
        '/admin/login': (200, 'text/html', '<title>Sign in</title><form action="/admin/login" method="POST"><input name="passphrase" type="password"></form>'),
        '/assets/css/adminlte.min.css': (200, 'Text/CSS', '.ordinary { color: blue }'),
        '/api/users/1': (403, 'application/json', '{"error":"requires authentication"}'),
        '/api/users/2': (403, 'application/json', '{"error":"requires authentication"}'),
        '/bundle.js': (200, 'application/javascript', 'fetch("/api/admin/users");fetch("/api/write",{method:"POST"});fetch("/admin/excluded");'),
        '/api/admin/users': (401, 'application/json', '{"error":"requires authentication"}'),
        '/.git/HEAD': (200, 'text/plain', 'ref: refs/heads/local-fixture\n'),
        '/.env': (404, 'text/plain', 'not found'),
        '/redirect': (302, 'text/html', ''),
    }

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            status, mime, body = pages.get(self.path, (200, 'text/html', '<title>Missing page</title>'))
            data = body.encode()
            self.send_response(status)
            self.send_header('Content-Type', mime)
            if self.path == '/redirect':
                self.send_header('Location', 'http://out-of-scope.invalid/forbidden')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            hits.append('POST ' + self.path)
            self.send_error(405)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        target = f'http://127.0.0.1:{server.server_port}/'
        config = default_config(target)
        config.scope.lab = True
        config.scope.exclude_paths = ['/admin/excluded']
        config.budgets.requests = 30
        config.budgets.per_host_rps = config.budgets.overall_rps = 100
        config.budgets.retries = 0
        scope = root / 'local-scope.yaml'
        scope.write_text(yaml.safe_dump(config.model_dump()), encoding='utf-8')
        tool_args = [arg for value in overrides for arg in ('--tool', value)]
        command(['scan', '--target', target, '--config', str(scope), '--tools', 'all', '--enrich', 'tech,dedup,priority', '--output-root', str(root), *tool_args], 2)
        run = root / '127.0.0.1'
        report = json.loads((run / 'reports/investigation.json').read_text())
        rows = {r['url']: r for r in report['all_results'] if r['method'] == 'GET'}
        assert rows[target + 'assets/css/adminlte.min.css']['tier'] == 'inventory'
        assert rows[target + 'admin/login']['tier'] == 'high-interest'
        assert rows[target + '.git/HEAD']['tier'] == 'high-interest'
        assert rows[target + 'api/users/1']['group_size'] == 2
        assert '/api/admin/users' in hits
        assert not {'/api/write', '/admin/excluded', '/logout'} & set(hits)
        assert all(not path.startswith('POST ') for path in hits)
        assert report['summary']['owned_provider_requests'] == 0
        checks += ['local collection and JS-derived GET', 'POST/exclusion/redirect enforcement', 'static noise filtering', 'login/signature ranking', 'duplicate grouping']
        before_hits = list(hits)
        command(['scan', '--resume', str(run)], 2)
        command(['report', '--run', str(run)])
        before = hashes(run)
        rerun_code = command(['rerun', '--from', str(run), '--tools', '6,7', '--enrich', 'tech,dedup,priority', *tool_args], (0, 2))
        assert hits == before_hits and hashes(run) == before
        child = json.loads((root / '1_127.0.0.1/reports/investigation.json').read_text())
        assert child['summary']['target_requests'] == child['summary']['currently_observed_assets'] == 0
        if rerun_code == 2:
            assert child['summary']['partial_coverage']
        checks += ['zero-request resume', 'zero-request immutable offline rerun']
        # Same local site through the enhanced existing pipeline; no providers.
        custom=root/'curated-custom.txt'
        custom.write_text('admin\nprivate-documentation\nredirect\nlogout\nadmin/excluded\nassets/logo.png\n',encoding='utf-8')
        god_root=root/'god-mode'
        before_god=len(hits)
        command(['scan',target,'--config',str(scope),'--god-mode','--wordlist',str(custom),'--wordlist-budget','5','--output-root',str(god_root),*tool_args],2)
        god_run=god_root/'127.0.0.1'
        god_coverage=json.loads((god_run/'reports/coverage.json').read_text())
        god_hits=hits[before_god:]
        assert god_coverage['discovery']['enabled'] and god_coverage['discovery']['requests']<=5
        assert god_coverage['crawler']['requests_reserved']==len(god_hits)<=30
        assert not {'/logout','/admin/excluded','/api/write'} & set(god_hits)
        assert god_coverage['crawler']['stop_reason']
        by_tool={t['tool']:t for t in god_coverage['tools']}
        assert not any(by_tool[n]['actually_ran'] for n in ('subfinder','urlfinder','dnsx','httpx','katana','nuclei'))
        assert 'native-aiohttp' in by_tool['httpx']['native_fallbacks']
        used=json.loads((god_run/'reports/snapshot.json').read_text())['wordlist_discoveries']
        assert used and all(r['wordlist_hash'] for r in used if r['wordlist'])
        before_resume=list(hits)
        command(['resume',str(god_run),'--no-progress'],2)
        command(['rerun','--from',str(god_run),'--tools','offline',*tool_args],(0,2))
        assert hits==before_resume
        checks += ['God Mode discovery allocation and provenance','God Mode policy and tool accounting','God Mode resume/offline rerun without traffic']
        blackbox_root=root/'blackbox'
        before_blackbox=len(hits)
        command(['blackbox',target,'--config',str(scope),'--wordlist',str(custom),'--wordlist-budget','5','--output-root',str(blackbox_root),*tool_args],2)
        blackbox_run=blackbox_root/'127.0.0.1'
        graph=json.loads((blackbox_run/'graph/asset-graph.json').read_text())
        nodes={n['id']:n for n in graph['nodes']}
        assert all(e['source'] in nodes and e['destination'] in nodes for e in graph['edges'])
        assert any(e['type']=='loads_script' for e in graph['edges'])
        assert any(e['type']=='references_api' for e in graph['edges'])
        assert any(n['type']=='external_reference' and 'live-observed' not in n['states'] for n in nodes.values())
        blackbox_summary=json.loads((blackbox_run/'reports/investigation.json').read_text())['summary']
        assert blackbox_summary['workflow']=='blackbox' and len(blackbox_summary['selected_tools'])==8
        blackbox_hits=hits[before_blackbox:]
        assert len(blackbox_hits)<=30 and not {'/api/write','/admin/excluded','/logout'} & set(blackbox_hits)
        before_custom=len(hits)
        custom_root=root/'customized'
        command(['scan',target,'--config',str(scope),'--tools','httpx,katana','--output-root',str(custom_root),*tool_args],2)
        custom_coverage=json.loads((custom_root/'127.0.0.1/reports/coverage.json').read_text())
        assert {r['tool'] for r in custom_coverage['tools'] if r['selected']}=={'httpx','katana'}
        assert '/api/admin/users' not in hits[before_custom:]  # JS was captured, analysis was not selected
        checks += ['canonical BlackBox selects eight capabilities', 'BlackBox tree and graph integrity', 'observed script and inferred API relationships', 'external references remain unobserved', 'customized scans never run unselected analysis']
        result = {'passed': checks, 'blackbox_report':str(blackbox_run/'reports/index.html'),
                  'asset_map':str(blackbox_run/'graph/asset-map.html'), 'graph_summary':graph['summary'], 'blackbox_paths':blackbox_hits, 'requests': len(hits), 'paths': hits, 'summary': report['summary'],
                  'resume_requests': 0, 'rerun_requests': 0, 'parent_unchanged': True,
                  'report': str(run / 'reports/index.html'), 'god_report':str(god_run/'reports/index.html'), 'god_paths':god_hits, 'god_coverage':god_coverage}
        (root / 'verification.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        print(json.dumps(result, indent=2))
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-root', required=True, type=Path)
    parser.add_argument('--tool', action='append', default=[], metavar='NAME=PATH')
    args = parser.parse_args()
    verify(args.output_root.resolve(), args.tool)
