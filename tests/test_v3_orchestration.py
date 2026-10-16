import asyncio
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

from reconmap.adapters import ToolInfo, ProcessResult, execute, ToolTimeout, ToolOutputLimit
from reconmap.config import default_config
from reconmap.engine import Scanner, Response, prepare_run, BudgetStop
from reconmap.selectors import resolve_selection
from reconmap.storage import Store, read_manifest


def instance(tmp_path, tools='6', mode='offline'):
    config = resolve_selection(default_config('example.com'), tools=tools, mode=mode)
    run, manifest = prepare_run(config, 'example.com', tmp_path)
    infos = {name: ToolInfo(name, '/fixture', 'fixture-version', 'a'*64, True, True, 'fixture', 'reviewed fixture', True) for name in config.selected_tools}
    return Scanner(run, manifest, config, infos, {} if mode == 'demo' else None)


def artifact(scanner, text='fetch("/api/users");', kind='js'):
    return scanner.save_artifact(text.encode(), kind, scanner.manifest['target'])


def result(scanner, name='javascript-analysis'):
    return json.loads(scanner.store.conn.execute('SELECT result_json FROM stage_results WHERE name=?', (name,)).fetchone()[0])


def test_successful_external_is_first_and_does_not_run_native_discovery(tmp_path, monkeypatch):
    scanner = instance(tmp_path)
    artifact(scanner)
    calls = []
    async def run(*args, **kwargs):
        calls.append(args[0])
        return ProcessResult(0, '{"url":"/api/users","method":"GET"}', '')
    monkeypatch.setattr('reconmap.integrations.execute', run)
    def denied(*args, **kwargs): raise AssertionError('Redundant native discovery')
    monkeypatch.setattr('reconmap.integrations.analyze_js', denied)
    try:
        asyncio.run(scanner.local_tools())
        assert len(calls) == 1
        assert result(scanner)['actual_execution_engines'] == ['jsluice']
        assert not result(scanner)['fallback_used']
        assert result(scanner)['tool_identity']['version'] == 'fixture-version'
        assert result(scanner)['input_artifacts'] and result(scanner)['output_artifacts']
        assert not scanner.store.rows('jobs')
        asyncio.run(scanner.local_tools())
        assert len(calls) == 1
        scanner.store.close()
        scanner = Scanner(scanner.run, read_manifest(scanner.run), scanner.config, scanner.tools)
        asyncio.run(scanner.local_tools())
        assert len(calls) == 1  # checkpoint survives a new Scanner/process
    finally: scanner.store.close()


@pytest.mark.parametrize('failure', ['missing', 'incompatible', 'crash', 'partial', 'timeout'])
def test_failed_primary_retains_evidence_and_uses_fallback(tmp_path, monkeypatch, failure):
    scanner = instance(tmp_path, mode='demo')
    scanner.config.modules.append('http')
    scanner.config.budgets.requests = 1
    artifact(scanner, 'fetch("/api/native");fetch("/api/partial");')
    async def run(*args, **kwargs):
        partial = ProcessResult(1 if failure == 'crash' else 0, '{"url":"/api/partial","method":"GET"}\nbad-json', '')
        if failure == 'timeout': raise ToolTimeout(partial)
        return partial
    monkeypatch.setattr('reconmap.integrations.execute', run)
    if failure in {'missing', 'incompatible'}:
        scanner.tools['jsluice'].supported = False
        scanner.tools['jsluice'].available = failure != 'missing'
    try:
        asyncio.run(scanner.local_tools())
        assert result(scanner)['fallback_used']
        assert 'native-tree-sitter' in result(scanner)['actual_execution_engines']
        assert any(r['url'].endswith('/api/native') for r in scanner.store.rows('urls'))
        if failure not in {'missing', 'incompatible'}:
            assert any(o['source'] == 'jsluice' for o in scanner.store.rows('observations'))
        assert len(scanner.store.rows('jobs')) == 1
        asyncio.run(scanner.crawl())
        assert scanner.store.meta('requests') == 1
        with pytest.raises(BudgetStop): asyncio.run(scanner.request('https://example.com/api/second'))
        assert scanner.store.meta('requests') == 1
    finally: scanner.store.close()


def test_policy_block_cannot_schedule_excluded_redirect_or_prohibited_method(tmp_path, monkeypatch):
    scanner = instance(tmp_path, tools='4,5,6,8', mode='demo')
    scanner.config.scope.exclude_paths = ['/admin']
    # Persist config used by final normalization; no manifest-dependent report in this unit.
    scanner.store.set_meta('config', scanner.config.model_dump())
    artifact(scanner, 'fetch("/admin");fetch("/api/post", {method:"POST"});fetch("/logout");')
    async def run(argv, *args, **kwargs):
        assert argv[1] == 'urls'  # armed active tools must never reach execute
        return ProcessResult(1, '', 'failed')
    monkeypatch.setattr('reconmap.integrations.execute', run)
    try:
        from reconmap.orchestrator import initialize_tools, native_web
        initialize_tools(scanner)
        asyncio.run(scanner.local_tools())
        assert not scanner.store.rows('jobs')
        scanner.store.set_meta('requests', scanner.config.budgets.requests)
        scanner.add_url('https://example.com/', 'seed')
        with pytest.raises(BudgetStop): asyncio.run(native_web(scanner))
        assert scanner.store.meta('requests') == scanner.config.budgets.requests
        assert result(scanner, 'http-probing')['primary_status'] == 'blocked-by-policy'
    finally: scanner.store.close()


def test_cancelled_primary_stops_without_fallback_and_resumes(tmp_path, monkeypatch):
    scanner = instance(tmp_path)
    artifact(scanner)
    async def cancel(*args, **kwargs): raise asyncio.CancelledError()
    monkeypatch.setattr('reconmap.integrations.execute', cancel)
    try:
        with pytest.raises(asyncio.CancelledError): asyncio.run(scanner.local_tools())
        assert not result(scanner)['fallback_used']
        assert not scanner.store.rows('urls')
        async def success(*args, **kwargs): return ProcessResult(0, '{"url":"/api/users","method":"GET"}', '')
        monkeypatch.setattr('reconmap.integrations.execute', success)
        asyncio.run(scanner.local_tools())
        assert result(scanner)['primary_status'] == 'completed'
    finally: scanner.store.close()


def test_interrupted_fallback_reuses_primary_partial_checkpoint(tmp_path, monkeypatch):
    scanner = instance(tmp_path)
    artifact(scanner)
    calls = []
    async def failed(*args, **kwargs): calls.append(1); return ProcessResult(1, '{"url":"/api/partial","method":"GET"}', '')
    monkeypatch.setattr('reconmap.integrations.execute', failed)
    from reconmap.integrations import native_artifact
    def interrupted(*args, **kwargs): raise KeyboardInterrupt()
    monkeypatch.setattr('reconmap.integrations.native_artifact', interrupted)
    try:
        with pytest.raises(KeyboardInterrupt): asyncio.run(scanner.local_tools())
        assert any(o['source'] == 'jsluice' for o in scanner.store.rows('observations'))
        monkeypatch.setattr('reconmap.integrations.native_artifact', native_artifact)
        asyncio.run(scanner.local_tools())
        assert len(calls) == 1 and result(scanner)['fallback_used']
    finally: scanner.store.close()


def test_gitleaks_failure_falls_back_and_success_does_not_duplicate(tmp_path, monkeypatch):
    scanner = instance(tmp_path, tools='7')
    artifact(scanner, 'ordinary input', 'content')
    calls = []
    async def execute_tool(argv, cwd, *args, **kwargs):
        (cwd/'findings.json').write_text('[]')
        return ProcessResult(0, '', '')
    monkeypatch.setattr('reconmap.integrations.execute', execute_tool)
    monkeypatch.setattr('reconmap.integrations.secrets', lambda *args, **kwargs: calls.append(1))
    try:
        asyncio.run(scanner.local_tools())
        assert calls == []
        artifact(scanner, 'another input', 'content')
        async def fail(*args, **kwargs): return ProcessResult(1, '', 'failure')
        monkeypatch.setattr('reconmap.integrations.execute', fail)
        asyncio.run(scanner.local_tools())
        assert calls == [1]
        assert result(scanner, 'secret-detection')['fallback_used']
    finally: scanner.store.close()


def test_real_subprocess_timeout_and_output_limit_keep_prefix(tmp_path):
    async def run():
        for code, timeout, limit, error in [
            ('import time;print("record",flush=True);time.sleep(10)', .4, 1024, ToolTimeout),
            ('print("record",flush=True);print("x"*5000,flush=True)', 5, 1024, ToolOutputLimit),
        ]:
            with pytest.raises(error) as caught:
                await execute([sys.executable, '-c', code], tmp_path, timeout, limit=limit)
            assert caught.value.result.stdout.startswith('record')
            assert len(caught.value.result.stdout.encode()) <= limit
    asyncio.run(run())


def test_changed_executable_identity_refuses_before_launch(tmp_path):
    marker = tmp_path/'marker'
    async def run():
        with pytest.raises(ValueError, match='identity changed'):
            await execute([sys.executable, '-c', f'open({str(marker)!r}, "w").close()'], tmp_path, 3, expected_sha='0'*64)
    asyncio.run(run())
    assert not marker.exists()


def test_process_report_file_is_monitored_and_stopped(tmp_path):
    report = tmp_path/'findings.json'
    async def run():
        code = f'import pathlib,time;pathlib.Path({str(report)!r}).write_text("x"*5000);time.sleep(10)'
        with pytest.raises(ToolOutputLimit):
            await execute([sys.executable, '-c', code], tmp_path, 5, limit=1024, output_files=(report,))
    asyncio.run(run())


def test_primary_and_fallback_share_remaining_time_budget(tmp_path, monkeypatch):
    scanner = instance(tmp_path)
    artifact(scanner)
    async def fails_after_budget(*args, **kwargs):
        scanner.scheduler.elapsed = scanner.config.budgets.minutes * 60
        return ProcessResult(1, '', 'failed')
    monkeypatch.setattr('reconmap.integrations.execute', fails_after_budget)
    try:
        with pytest.raises(BudgetStop): asyncio.run(scanner.local_tools())
        assert not result(scanner)['fallback_used']
        assert not scanner.store.rows('urls')
    finally: scanner.store.close()


@pytest.mark.parametrize('enabled,primary_success', [(False, False), (True, False), (True, True)])
def test_urlfinder_fallback_requires_explicit_cdx_and_avoids_redundant_collection(tmp_path, monkeypatch, enabled, primary_success):
    from reconmap.orchestrator import run_pipeline
    scanner = instance(tmp_path, tools='2', mode='passive')
    if enabled: scanner.config.enrichments = ['wayback']
    calls = []
    async def tool(*args, **kwargs):
        return ProcessResult(0 if primary_success else 1, '{"url":"https://example.com/api/from-tool"}', '')
    async def cdx(scanner):
        calls.append(1)
        scanner.add_url('https://example.com/api/from-cdx', 'wayback-cdx')
        scanner.store.stage('wayback', 'completed', 'Fixture CDX response')
    monkeypatch.setattr('reconmap.integrations.execute', tool)
    monkeypatch.setattr('reconmap.enrichment.wayback.collect_wayback', cdx)
    try:
        asyncio.run(run_pipeline(scanner))
        assert bool(calls) == (enabled and not primary_success)
        record = result(scanner, 'historical-discovery')
        assert record['fallback_used'] == bool(calls)
        assert scanner.store.meta('requests', 0) == 0
        assert any(r['url'].endswith('/api/from-tool') for r in scanner.store.rows('urls'))
    finally: scanner.store.close()


def test_schema2_readonly_and_additive_migration_preserve_analyst_evidence(tmp_path):
    import sqlite3
    from reconmap.storage import DDL
    from reconmap.schema_v2 import DDL as V2_DDL
    with sqlite3.connect(tmp_path/'recon.sqlite') as db:
        db.executescript(DDL + V2_DDL)
        db.execute('PRAGMA user_version=2')
        db.execute('INSERT INTO analyst_actions(fingerprint,status,note,time) VALUES(?,?,?,?)', ('old', 'dismissed', 'preserve decision', '2020'))
    before = (tmp_path/'recon.sqlite').read_bytes()
    store = Store(tmp_path, readonly=True)
    assert store.rows('stage_results') == [] and store.rows('normalized_records') == []
    store.close()
    assert (tmp_path/'recon.sqlite').read_bytes() == before
    store = Store(tmp_path)
    try:
        assert store.conn.execute('PRAGMA user_version').fetchone()[0] == 3
        assert store.rows('analyst_actions')[0]['note'] == 'preserve decision'
    finally: store.close()


def test_native_process_paths_with_spaces_do_not_use_shell(tmp_path):
    directory = tmp_path/'directory with spaces'
    directory.mkdir()
    script = directory/'fixture code.py'
    script.write_text('import sys;print(sys.argv[1])')
    async def run():
        result = await execute([sys.executable, str(script), 'literal; $(not-a-command) & value'], directory, 5)
        assert result.code == 0 and result.stdout.strip() == 'literal; $(not-a-command) & value'
    asyncio.run(run())
