import asyncio
import json

import pytest

from reconmap.adapters import ProcessResult
from reconmap.coverage import summarize
from reconmap.integrations import _independent
from reconmap.orchestrator import initialize_tools
from reconmap.progress import snapshot
from test_v3_orchestration import instance, artifact, result


def test_empty_js_primary_runs_native_analysis_and_checkpoint(tmp_path,monkeypatch):
    scanner=instance(tmp_path,mode='demo');scanner.config.modules.append('http')
    digest=artifact(scanner,'fetch("/api/useful");')
    calls=[]
    async def empty(*args,**kwargs):calls.append(1);return ProcessResult(0,'','')
    monkeypatch.setattr('reconmap.integrations.execute',empty)
    initialize_tools(scanner)
    asyncio.run(scanner.local_tools())
    assert result(scanner)['actual_execution_engines']==['jsluice','native-tree-sitter']
    assert result(scanner)['primary_status']=='completed' and result(scanner)['fallback_used']
    assert scanner.store.conn.execute("SELECT 1 FROM jobs WHERE url='https://example.com/api/useful'").fetchone()
    coverage=summarize(scanner.store)
    assert coverage['javascript']['primary_empty_artifacts']==1 and coverage['javascript']['processed_artifacts']==1
    assert next(t for t in coverage['tools'] if t['tool']=='jsluice')['actually_ran']
    asyncio.run(scanner.local_tools());assert len(calls)==1
    scanner.store.close()


def test_js_depth_limit_not_reset_by_external_or_discovery(tmp_path,monkeypatch):
    scanner=instance(tmp_path,mode='demo');scanner.config.modules.append('http');scanner.config.budgets.depth=1
    scanner.add_url('https://example.com/bundle.js','fixture',depth=1)
    digest=scanner.save_artifact(b'fetch("/api/deep");','js','https://example.com/bundle.js')
    async def output(*a,**k):return ProcessResult(0,'{"url":"/api/deep","method":"GET"}','')
    monkeypatch.setattr('reconmap.integrations.execute',output)
    asyncio.run(scanner.local_tools())
    assert not scanner.store.conn.execute("SELECT 1 FROM jobs WHERE url='https://example.com/api/deep'").fetchone()
    from reconmap.content_discovery import evidence_candidates,candidate
    for url,source,meta in evidence_candidates(scanner):candidate(scanner,url,source,meta,slots=10)
    assert not scanner.store.conn.execute("SELECT 1 FROM jobs WHERE url='https://example.com/api/deep'").fetchone()
    assert summarize(scanner.store)['crawler']['depth_limited']>=1
    scanner.store.close()


@pytest.mark.parametrize('parallel',[1,2])
def test_bounded_independent_jobs_and_crash_isolation(tmp_path,parallel):
    scanner=instance(tmp_path,tools='6,7');scanner.config.discovery.max_concurrent_jobs=parallel
    active=0;peak=0;completed=[]
    async def worker(scanner,names):
        nonlocal active,peak
        active+=1;peak=max(peak,active)
        try:
            await asyncio.sleep(.01)
            if names[0]=='jsluice':raise ValueError('malformed input fixture')
            completed.append(names[0])
        finally:active-=1
    asyncio.run(_independent(scanner,('jsluice','gitleaks'),worker))
    assert peak==parallel and completed==['gitleaks'] and active==0
    assert scanner.store.conn.execute("SELECT state FROM stages WHERE name='jsluice'").fetchone()[0]=='partial'
    scanner.store.close()


def test_cancel_waits_for_all_independent_jobs(tmp_path):
    scanner=instance(tmp_path,tools='6,7');scanner.config.discovery.max_concurrent_jobs=2
    ended=[]
    async def check():
        entered=asyncio.Event();count=0
        async def worker(scanner,names):
            nonlocal count
            count+=1
            if count==2:entered.set()
            try:await asyncio.Event().wait()
            finally:ended.append(names[0])
        task=asyncio.create_task(_independent(scanner,('jsluice','gitleaks'),worker))
        await asyncio.wait_for(entered.wait(),2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):await task
    asyncio.run(check())
    assert set(ended)=={'jsluice','gitleaks'}
    scanner.store.close()


def test_restricted_external_status_and_dashboard_are_truthful(tmp_path):
    scanner=instance(tmp_path,tools='3,4,5,8',mode='demo')
    for info in scanner.tools.values():info.supported=False
    initialize_tools(scanner)
    coverage=summarize(scanner.store)
    assert all(t['installed'] and t['compatible'] and not t['direct_execution_permitted'] and not t['actually_ran'] for t in coverage['tools'] if t['selected'])
    scanner.store.set_meta('wordlist_requests',3)
    scanner.store.observed('https://example.com/probe','content-candidate',{},'fixture')
    data=snapshot(scanner)
    assert data['wordlist_candidates']==1 and data['wordlist_requests']==3 and data['tested']==0
    assert all(not t['ran'] for t in data['tools'])
    scanner.store.close()


def test_missing_js_artifact_does_not_abort_secret_stage(tmp_path,monkeypatch):
    scanner=instance(tmp_path,tools='6,7');scanner.config.discovery.max_concurrent_jobs=2
    artifact(scanner)
    async def worker(scanner,names):
        if names[0]=='jsluice':raise OSError('artifact missing')
        scanner.store.set_meta('secret-stage-ran',True)
    monkeypatch.setattr('reconmap.integrations._local_tools',worker)
    asyncio.run(scanner.local_tools())
    assert scanner.store.meta('secret-stage-ran')
    assert summarize(scanner.store)['javascript']['unprocessed_artifacts']==1
    scanner.store.close()


def test_failed_spawn_not_reported_as_actual_external_execution(tmp_path,monkeypatch):
    scanner=instance(tmp_path);artifact(scanner)
    async def missing(*args,**kwargs):raise OSError('Executable disappeared before spawn')
    monkeypatch.setattr('reconmap.integrations.execute',missing)
    initialize_tools(scanner);asyncio.run(scanner.local_tools())
    assert result(scanner)['primary_status']=='failed'
    assert result(scanner)['actual_execution_engines']==['native-tree-sitter']
    assert not summarize(scanner.store)['tools'][0]['actually_ran']
    scanner.store.close()


def test_native_check_counts_exclude_other_detector_findings(tmp_path):
    from reconmap.orchestrator import native_counts
    scanner=instance(tmp_path)
    scanner.store.finding('git-head','https://example.com/.git/HEAD','signature',{},source='native')
    scanner.store.finding('inferred-route-lead','https://example.com/api/foo','inference',{},source='tree-sitter')
    scanner.store.finding('gitleaks:fixture','artifact:test','secret',{},source='gitleaks')
    assert native_counts(scanner)['nuclei']==1
    scanner.store.close()
