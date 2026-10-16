"""Presentation of persisted execution state; never predicts scan completion."""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import shutil
import sys
import time

from . import __version__
from .orchestrator import phase_plan, STAGE_NAMES
from .security import redact


def safe_text(value):
    return re.sub(r'[\x00-\x1f\x7f-\x9f]', '', redact(str(value)))


def snapshot(scanner):
    store = scanner.store
    phases = [p['name'] for p in phase_plan(scanner.config) if p['enabled']]
    stages = {s['name']: s for s in store.rows('stages')}
    results = {r['name']: json.loads(r['result_json']) for r in store.rows('stage_results')}
    count = lambda table: store.conn.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0]
    jobs = dict(store.conn.execute('SELECT state,COUNT(*) FROM jobs GROUP BY state'))
    candidate_count = store.conn.execute("SELECT COUNT(*) FROM investigation_candidates WHERE json_extract(data,'$.representative')=1 AND json_extract(data,'$.tier')!='inventory'").fetchone()[0]
    tools = []
    for name, info in scanner.tools.items():
        result = results.get(STAGE_NAMES[name], {})
        tools.append({'name': name, 'primary': result.get('primary_status', 'ready' if info.supported else 'blocked-by-policy' if info.compatible else 'incompatible' if info.available else 'missing'),
                      'status': result.get('status', 'waiting'), 'engines': result.get('actual_execution_engines', []),
                      'fallback': result.get('fallback_used', False) or (result.get('primary_status') in {'unavailable', 'incompatible', 'failed', 'partial', 'blocked-by-policy'} and any(e.startswith('native-') for e in result.get('actual_execution_engines', []))),
                      'installed': info.available, 'compatible': info.compatible, 'permitted': info.supported, 'ran': bool(store.meta('executed:'+name, False)), 'seconds': result.get('duration_seconds',0), 'count': result.get('discovered_records', 0), 'reason': result.get('failure_reason', '')})
    return {'target': scanner.manifest['target'], 'mode': scanner.config.mode, 'profile': scanner.config.profile,
            'state': scanner.manifest['state'], 'phase': next((p for p in phases if stages.get('workflow:'+p, {}).get('state') == 'running'), scanner.manifest['state']),
            'completed': sum(stages.get('workflow:'+p, {}).get('state') == 'completed' for p in phases), 'total': len(phases),
            'waiting': [p for p in phases if 'workflow:'+p not in stages], 'tools': tools,
            'hosts': count('hosts'), 'urls': count('urls'), 'requests': store.meta('requests', 0),
            'request_budget': scanner.config.budgets.requests, 'elapsed': scanner.scheduler.elapsed + time.monotonic() - scanner.scheduler.started,
            'time_budget': scanner.config.budgets.minutes*60, 'jobs': jobs,
            'tested':store.conn.execute("SELECT COUNT(DISTINCT subject) FROM observations WHERE kind='http' AND source NOT LIKE 'parent:%'").fetchone()[0],
            'wordlist_candidates':store.conn.execute("SELECT COUNT(*) FROM observations WHERE kind='content-candidate'").fetchone()[0],
            'wordlist_requests':store.meta('wordlist_requests',0), 'discovery':scanner.config.discovery.enabled,
            'candidates': candidate_count,
            'exposures': store.conn.execute("SELECT COUNT(*) FROM findings WHERE rule IN ('git-head','environment-config')").fetchone()[0],
            'findings': count('findings'), 'path': str(scanner.run), 'demo': scanner.config.mode == 'demo'}


def ansi_terminal(stream):
    if not stream.isatty() or os.environ.get('TERM') == 'dumb':
        return False
    if os.name == 'nt':
        try:
            import ctypes
            handle = ctypes.windll.kernel32.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            if not ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                return False
            return bool(ctypes.windll.kernel32.SetConsoleMode(handle, mode.value | 4))
        except (AttributeError, OSError):
            return False
    return True


class Dashboard:
    def __init__(self, enabled=True, stream=None, preset=None):
        self.stream = stream or sys.stdout
        self.live = enabled and ansi_terminal(self.stream)
        self.preset = preset or 'configured'
        self.lines = 0
        self.last_draw = 0.0
        self.last_log = None

    def __enter__(self):
        if self.live:
            self.stream.write('\x1b[?25l')
            self.stream.flush()
        return self

    def update(self, scanner, force=False):
        now = time.monotonic()
        if not force and now - self.last_draw < .2:
            return
        self.last_draw = now
        data = snapshot(scanner)
        status_key = (data['phase'], data['state'], tuple((t['name'], t['primary'], t['status'], tuple(t['engines'])) for t in data['tools']))
        if not self.live and status_key == self.last_log and not force:
            return
        self.last_log = status_key
        rows = [f'THEGODRECON {__version__} | {self.preset} | {data["mode"]}',
                f'Target: {data["target"]}',
                f'Workflow: {data["completed"]}/{data["total"]} phases completed | Current: {data["phase"]}',
                'Waiting: ' + (', '.join(data['waiting']) or 'none')]
        for tool in data['tools']:
            actual = ','.join(tool['engines']) or 'not executed'
            fallback = ' | Native fallback' if tool['fallback'] else ''
            if self.live:
                rows.append(f'{tool["name"]:10} {tool["primary"]} -> {actual}: {tool["status"]} ({tool["count"]})')
            else:
                rows.append(f'{tool["name"]:10} primary={tool["primary"]} | {tool["status"]}{fallback}')
                rows.append(f'  Engine: {actual} | records: {tool["count"]} | {tool["seconds"]:.2f}s')
                rows.append(f'  Installed: {tool["installed"]} | Compatible: {tool["compatible"]} | Direct permitted: {tool["permitted"]} | External ran: {tool["ran"]}')
            if tool['reason'] and force and not self.live:
                rows.append('  Reason: ' + tool['reason'])
        rows += [f'Hosts: {data["hosts"]} | URLs: {data["urls"]} | Review candidates: {data["candidates"]} (after ranking)',
                 f'Potential exposure signatures: {data["exposures"]} | All evidence leads: {data["findings"]}',
                 f'{"Fixture operations" if data["demo"] else "HTTP requests"}: {data["requests"]}/{data["request_budget"]} | Elapsed: {data["elapsed"]:.1f}/{data["time_budget"]:g}s',
                 'Jobs: ' + ' | '.join(f'{k}: {data["jobs"].get(k,0)}' for k in ('queued', 'running', 'completed', 'failed')),
                 'Output: ' + data['path']]
        rows.append(f'URLs tested: {data["tested"]} | Wordlist/evidence candidates: {data["wordlist_candidates"]} | Discovery requests: {data["wordlist_requests"]}')
        if force and scanner.manifest['state'] not in {'created','running'}:
            from .coverage import summarize
            rows.append('Crawler stop reason: ' + summarize(scanner.store)['crawler']['stop_reason'])
        rows = [safe_text(row) for row in rows]
        if self.live:
            width = max(24, min(112, shutil.get_terminal_size((100, 30)).columns - 1))
            border = '+' + '-'*(width-2) + '+'
            rendered = '\n'.join([border] + ['| '+row[:width-4].ljust(width-4)+' |' for row in rows] + [border]) + '\n'
            if self.lines:
                self.stream.write(f'\x1b[{self.lines}A')
            self.stream.write('\x1b[J' + rendered)
            self.lines = len(rows)+2
        else:
            self.stream.write('\n'.join(rows)+'\n')
        self.stream.flush()

    def __exit__(self, *unused):
        if self.live:
            self.stream.write('\x1b[?25h\x1b[0m')
            self.stream.flush()

    async def run(self, scanner):
        async def refresh():
            while True:
                self.update(scanner)
                await asyncio.sleep(.25)
        def changed(force=False):
            try:
                self.update(scanner, force=force)
            except (OSError, ValueError):
                # A broken terminal must not change evidence or run status.
                scanner.store.on_change = None
        scanner.store.on_change = changed
        self.update(scanner, force=True)
        monitor = asyncio.create_task(refresh())
        try:
            return await scanner.run_scan()
        finally:
            monitor.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await monitor
            scanner.store.on_change = None
