"""Bounded latest-run discovery and best-effort browser access."""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import webbrowser
from pathlib import Path

from .config import ConfigError
from .settings import load_settings, save_settings
from .storage import read_manifest, Store


def valid_report(run: Path) -> Path:
    manifest = read_manifest(run)
    if manifest['state'] in {'created', 'running'} or (run/'run.lock').exists():
        raise ValueError('Run is still active; wait for its report checkpoint')
    store = Store(run, readonly=True)
    try:
        if not store.conn.execute('SELECT 1 FROM runs WHERE run_id=?', (manifest['run_id'],)).fetchone():
            raise ValueError('Run database does not match manifest')
    finally:
        store.close()
    report = run / 'reports/index.html'
    if not report.is_file():
        raise ValueError('Run has no report yet; use reconmap report --run PATH to regenerate')
    return report.resolve()


def previous_runs() -> list[Path]:
    settings = load_settings()
    candidates = {Path(settings.last_run)} if settings.last_run else set()
    for root in {Path(settings.output_root), Path('recon-output')}:
        if root.is_dir() and not root.is_symlink() and not root.is_junction():
            # Known immediate children only; never search the entire filesystem.
            for i, child in enumerate(root.iterdir()):
                if i >= 10000:
                    break
                if child.is_dir():
                    candidates.add(child)
    valid = []
    for run in candidates:
        try:
            report = valid_report(run)
            manifest = read_manifest(run)
            valid.append((str(manifest.get('updated', manifest.get('created', ''))), run.resolve()))
        except (OSError, ValueError, sqlite3.Error):
            continue
    return [run for _, run in sorted(valid, key=lambda pair: (pair[0], str(pair[1])), reverse=True)]


def latest_report() -> Path:
    runs = previous_runs()
    if not runs:
        raise ConfigError('No valid reports found. Run reconmap demo or provide reconmap report --run PATH')
    return valid_report(runs[0])


def open_report(report: Path) -> bool:
    report = report.resolve()
    print(f'Report: {report}')
    if os.name != 'nt' and not (os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY')):
        print('Headless environment; open this file on a desktop browser.')
        return False
    try:
        opened = webbrowser.open(report.as_uri())
    except (OSError, webbrowser.Error):
        opened = False
    if not opened:
        print('Browser could not be opened; use the report path above.')
    return opened


def finish_run(run: Path, state: str, *, prompt=True):
    try:
        settings = load_settings()
        settings.last_run = str(run.resolve())
        save_settings(settings)
    except (OSError, ValueError) as exc:
        print(f'Could not save last-run preference: {exc}', file=sys.stderr)
        settings = None
    print(f'\nRun status: {state}\nRun directory: {run.resolve()}')
    try:
        summary = json.loads((run/'reports/investigation.json').read_text(encoding='utf-8'))['summary']
        print(f'Results: {summary["discovered_assets"]} URLs | High interest: {summary["high_interest"]} | Manual review: {summary["manual_review"]}')
        report = valid_report(run) if (run/"reports/index.html").exists() else (run/"reports/investigation.json").resolve()
    except (OSError, ValueError, KeyError, sqlite3.Error):
        print('Report incomplete. Preserve the run and use reconmap report --run PATH to regenerate.')
        return
    graph = summary.get('graph', {})
    print('BLACKBOX RECON FINISHED' if summary.get('workflow') == 'blackbox' else 'SCAN FINISHED')
    print('Execution: ' + state + ' | Selected tools: ' + (', '.join(summary.get('selected_tools',[])) or 'native modules'))
    if graph:
        print(f'Discovered hosts: {graph["hosts"]} | Discovered URLs: {graph["urls"]} | Tested URLs: {graph["tested_urls"]}')
        print(f'API candidates: {graph["api_candidates"]} | JavaScript resources: {graph["javascript_resources"]}')
        print(f'Graph nodes: {graph["nodes"]} | Graph relationships: {graph["edges"]}')
        print(f'Endpoint tree: {(run/"graph/endpoint-tree.txt").resolve()}')
        print(f'Interactive asset map: {(run/"graph/asset-map.html").resolve()}')
    print(f'Report: {report}')
    if state == 'interrupted':
        print(f'Resume: reconmap resume "{run.resolve()}"')
        return
    should_open = bool(settings and settings.auto_open)
    if not should_open and prompt and sys.stdin.isatty() and sys.stdout.isatty():
        try:
            answer = input('Open report or asset map? [R/m/n] ' if graph else 'Open report now? [Y/n] ').strip().lower()
            if graph and answer in {'m','map'}:
                report = (run/'graph/asset-map.html').resolve()
                should_open = True
            else:
                should_open = answer in {'','y','yes','r','report'}
        except (EOFError, KeyboardInterrupt):
            return
    if should_open:
        open_report(report)
