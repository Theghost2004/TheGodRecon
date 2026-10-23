import asyncio
import hashlib
import json
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from reconmap.cli import main
from reconmap.config import default_config
from reconmap.engine import prepare_run
from reconmap.storage import DDL, Store, atomic_json, read_manifest


def tree_hash(path):
    return {str(p.relative_to(path)): hashlib.sha256(p.read_bytes()).hexdigest() for p in path.rglob('*') if p.is_file()}


def test_offline_rerun_keeps_original_evidence_and_analyst_decisions(tmp_path, monkeypatch):
    assert main(['demo','--output-root',str(tmp_path)]) == 0
    parent = tmp_path/'example.com'
    store=Store(parent); finding=store.rows('findings')[0]['fingerprint'];store.close()
    assert main(['validate','--run',str(parent),'--finding',finding,'--status','manually confirmed','--note','Explicit synthetic decision']) == 0
    before = tree_hash(parent)
    async def forbidden(*unused,**kwargs): raise AssertionError('target request in offline rerun')
    monkeypatch.setattr('reconmap.engine.Scanner.request',forbidden)
    monkeypatch.setattr('aiohttp.ClientSession._request',forbidden)
    # Legacy native analysis selection also supports immutable offline reanalysis.
    assert main(['rerun','--from',str(parent),'--modules','analysis','--mode','offline','--enrich','tech,dedup,priority']) == 0
    child=tmp_path/'1_example.com'
    assert tree_hash(parent)==before
    manifest=read_manifest(child)
    assert manifest['requests']==0 and manifest['lineage']['parent_run_id']==read_manifest(parent)['run_id']
    store=Store(child)
    try:
        lineage=store.rows('lineage')[0]
        metadata=json.loads(lineage['metadata'])
        assert metadata['parent_analyst_decisions'][0]['status']=='manually confirmed'
        assert metadata['new_target_requests_reserved']==0 and metadata['completion']=='completed'
        assert metadata['stage_completion'] and 'new_artifact_hashes' in metadata
        assert not store.rows('analyst_actions')
        assert store.rows('findings') and all(r['validation']=='candidate' for r in store.rows('findings'))
        assert store.rows('url_groups') and store.rows('endpoint_priority')
        assert store.meta('requests',0)==0
        assert all((child/a['path']).stat().st_nlink==1 for a in store.rows('artifacts'))
    finally:store.close()
    assert (child/'reports/index.html').exists() and (child/'diff/comparison.json').exists()


def test_rerun_rejects_modified_artifacts_before_allocating(tmp_path):
    assert main(['demo','--output-root',str(tmp_path)])==0
    parent=tmp_path/'example.com'
    store=Store(parent);artifact=store.rows('artifacts')[0];store.close()
    (parent/artifact['path']).write_bytes(b'x'*artifact['bytes'])
    assert main(['rerun','--from',str(parent),'--modules','analysis','--mode','offline'])==3
    assert not (tmp_path/'1_example.com').exists()


def test_demo_evidence_cannot_become_network_authorization(tmp_path, monkeypatch):
    assert main(['demo','--output-root',str(tmp_path)])==0
    async def forbidden(*unused,**kwargs):raise AssertionError('fixture target became real network authorization')
    monkeypatch.setattr('reconmap.engine.Scanner.request',forbidden)
    assert main(['rerun','--from',str(tmp_path/'example.com'),'--tools','4','--mode','standard'])==3
    assert not (tmp_path/'1_example.com').exists()


def test_rerun_rejects_locked_parent_and_symlink(tmp_path):
    assert main(['demo','--output-root',str(tmp_path)])==0
    parent=tmp_path/'example.com'
    atomic_json(parent/'run.lock',{'pid':1,'token':'locked','host':'fixture'})
    assert main(['rerun','--from',str(parent),'--modules','analysis','--mode','offline'])==3
    (parent/'run.lock').unlink()
    alias=tmp_path/'alias'
    try:alias.symlink_to(parent,target_is_directory=True)
    except OSError:pytest.skip('Native symlink privilege unavailable')
    assert main(['rerun','--from',str(alias),'--modules','analysis','--mode','offline'])==3


def test_v1_database_additive_migration_and_readonly_reuse(tmp_path):
    config=default_config('example.com');config.mode='demo';config.version=1
    run,manifest=prepare_run(config,'example.com',tmp_path)
    # Construct an actual schema-1 database with an existing analyst decision.
    (run/'recon.sqlite').unlink()
    with sqlite3.connect(run/'recon.sqlite') as db:
        db.executescript(DDL)
        db.execute('PRAGMA user_version=1')
        db.execute('INSERT INTO analyst_actions(fingerprint,status,note,time) VALUES(?,?,?,?)',('fixture','dismissed','keep this note','fixture-time'))
    manifest['schema']=1;atomic_json(run/'manifest.json',manifest)
    before=(run/'recon.sqlite').read_bytes()
    store=Store(run,readonly=True)
    assert store.rows('analyst_actions')[0]['note']=='keep this note'
    assert store.rows('technologies')==[]
    store.close();assert (run/'recon.sqlite').read_bytes()==before
    assert read_manifest(run)['schema']==1
    store=Store(run)
    from reconmap.storage import SCHEMA
    assert store.conn.execute('PRAGMA user_version').fetchone()[0]==SCHEMA
    assert store.rows('analyst_actions')[0]['note']=='keep this note'
    store.close()


def test_fresh_active_rerun_uses_new_requests_and_preserves_parent(tmp_path,monkeypatch):
    from reconmap.adapters import ToolInfo
    monkeypatch.setattr('reconmap.cli.identify_selected',lambda config,name:ToolInfo(name,None,'missing',None,False,False,'fixture','missing'))
    hits=[]
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            body=f'<title>Collection {len(hits)}</title>'.encode()
            self.send_response(200);self.send_header('Content-Type','text/html');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        def log_message(self,*unused):pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        target=f'http://127.0.0.1:{server.server_port}/'
        config=tmp_path/'scope.yaml'
        assert main(['init','--target',target,'--config',str(config),'--lab'])==0
        assert main(['scan','--target',target,'--config',str(config),'--modules','http','--output-root',str(tmp_path)])==0
        parent=tmp_path/'127.0.0.1';before=tree_hash(parent)
        # Missing external binary uses native probing without reusing old responses.
        assert main(['rerun','--from',str(parent),'--tools','4','--enrich','tech,dedup,priority'])==2
        assert hits==['/','/'] and tree_hash(parent)==before
        child=tmp_path/'1_127.0.0.1';manifest=read_manifest(child)
        assert manifest['requests']==1 and manifest['state']=='partial'
        store=Store(child)
        try:
            assert any(r['kind']=='http' and r['source']=='native' for r in store.rows('observations'))
            current=[json.loads(r['data']) for r in store.rows('normalized_records')]
            assert current and current[0]['current_status']==200
            assert current[0]['current_http'] and current[0]['prior_http']
        finally:store.close()
        store=Store(child)
        assert store.rows('tool_executions')[0]['state']=='unavailable'
        assert store.rows('urls')[0]['title']=='Collection 2'
        store.close()
    finally:server.shutdown();server.server_close();thread.join()


def test_strict_rerun_dependency_preflight_does_not_create_child(tmp_path):
    assert main(['demo','--output-root',str(tmp_path)])==0
    assert main(['rerun','--from',str(tmp_path/'example.com'),'--tools','7','--strict-tools','--tool',f'gitleaks={tmp_path/"missing.exe"}'])==4
    assert not (tmp_path/'1_example.com').exists()


def test_interrupted_evidence_copy_can_resume_without_parent_changes(tmp_path, monkeypatch):
    assert main(['demo','--output-root',str(tmp_path)])==0
    parent=tmp_path/'example.com';before=tree_hash(parent)
    import reconmap.reruns as reruns
    original=reruns.shutil.copyfile
    calls=[]
    def copy(source,destination):
        calls.append(source)
        if len(calls)==2:raise KeyboardInterrupt()
        return original(source,destination)
    monkeypatch.setattr(reruns.shutil,'copyfile',copy)
    assert main(['rerun','--from',str(parent),'--modules','analysis','--mode','offline'])==130
    child=tmp_path/'1_example.com'
    manifest=read_manifest(child)
    assert manifest['state']=='interrupted' and manifest['lineage']['initialization_pending']
    assert (child/'reports/index.html').is_file() and not (child/'run.lock').exists()
    monkeypatch.setattr(reruns.shutil,'copyfile',original)
    assert main(['scan','--resume',str(child)])==0
    assert not read_manifest(child)['lineage']['initialization_pending']
    assert tree_hash(parent)==before
