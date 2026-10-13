from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
import socket
import sqlite3
import threading
import os
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from reconmap.cli import main
from reconmap.config import Scope, default_config
from reconmap.demo import fixtures
from reconmap.engine import BudgetStop, Response, SafeResolver, Scanner, Scheduler, prepare_run
from reconmap.reporting import compare_runs, generate_report
from reconmap.scope import ScopePolicy
from reconmap.storage import Store, atomic_json


@pytest.fixture
def lab_server():
    hits=[]
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            pages={
                '/':(200,'text/html',b'<title>Lab</title><a href="/restricted">R</a><a href="/redirect">X</a><a href="/logout">bye</a><a href="/missing">missing</a><script src="/app.js"></script><script src="/dup.js"></script><form action="/submit" method="POST"><input name="x"></form>'),
                '/restricted':(403,'text/html',b'<title>Forbidden</title>'),
                '/app.js':(200,'application/javascript',b'fetch("/api/account?x=1&x=2"); fetch("/submit", {method:"POST"}); //# sourceMappingURL=app.js.map'),
                '/dup.js':(200,'application/javascript',b'fetch("/api/account?x=1&x=2"); fetch("/submit", {method:"POST"}); //# sourceMappingURL=app.js.map'),
                '/api/account?x=1&x=2':(200,'application/json',b'{"fixture":true}'),
                '/app.js.map':(200,'application/json',json.dumps({'version':3,'sources':['../../escape.js'],'sourcesContent':['fetch("/api/export")'],'mappings':''}).encode()),
                '/bomb':(200,'text/plain',gzip.compress(b'x'*1000000)),
            }
            if self.path=='/redirect':
                self.send_response(302);self.send_header('Location','http://external.test/');self.end_headers();return
            status,kind,body=pages.get(self.path,(200,'text/html',b'<title>Missing</title><p>soft 404</p>'))
            self.send_response(status);self.send_header('Content-Type',kind)
            if self.path=='/bomb':self.send_header('Content-Encoding','gzip')
            self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        def log_message(self,*args):pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    yield f'http://127.0.0.1:{server.server_port}/',hits
    server.shutdown();server.server_close();thread.join()


def lab_config(target):
    c=default_config(target);c.scope.lab=True;c.budgets.depth=3
    c.budgets.per_host_rps=100;c.budgets.overall_rps=100
    return c


def test_real_localhost_scan_and_artifacts(tmp_path,lab_server):
    target,hits=lab_server;c=lab_config(target)
    path,manifest=prepare_run(c,target,tmp_path)
    assert asyncio.run(Scanner(path,manifest,c,{}).run_scan())=='completed'
    db=Store(path);urls={r['url']:r for r in db.rows('urls')}
    assert urls[target+'restricted']['state']=='restricted'
    assert urls['http://external.test/']['state']=='external-reference'
    assert '/logout' not in hits and '/submit' not in hits
    assert len([a for a in db.rows('artifacts') if a['kind']=='js' and 'app' not in a['path']])>=1
    assert any(o['kind']=='soft-error-similarity' for o in db.rows('observations'))
    assert any(o['kind']=='inferred_endpoint' for o in db.rows('observations'))
    assert len([r for r in db.rows('relationships') if r['child']==target+'api/account?x=1&x=2'])>=2
    assert db.meta('requests')==len(hits)
    db.close()
    for output in ['manifest.json','config.effective.json','tools.json']:
        # CLI records tools.json; engine-level tests exercise the coordinator directly.
        if output!='tools.json':assert (path/output).exists()
    assert (path/'reports/index.html').is_file() and (path/'reports/findings.csv').is_file()
    assert not (tmp_path.parent/'escape.js').exists()


def test_redirect_to_private_denied_without_second_request(tmp_path,lab_server):
    target,hits=lab_server;c=lab_config(target)
    path,manifest=prepare_run(c,target,tmp_path)
    scanner=Scanner(path,manifest,c,{})
    scanner.process_response(target,Response(302,{'location':'http://169.254.169.254/latest/meta-data'},b''),0,1)
    assert not scanner.store.rows('jobs')
    assert scanner.store.rows('urls')[0]['state']=='external-reference'
    scanner.store.close()


def test_dns_rebinding_private_and_mixed_answers(tmp_path,monkeypatch):
    c=default_config('example.com');store=Store(tmp_path)
    async def go():
        loop=asyncio.get_running_loop()
        async def dns(*a,**k):return [(socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',443)),(socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',443))]
        monkeypatch.setattr(loop,'getaddrinfo',dns)
        resolver=SafeResolver(ScopePolicy(c.scope),c,store)
        with pytest.raises(OSError,match='prohibited'):await resolver.resolve('example.com',443)
        assert store.meta('dns_operations')==1
        assert len(store.rows('dns'))==2
    asyncio.run(go());store.close()


def test_gzip_bomb_bound(tmp_path,lab_server):
    target,hits=lab_server;c=lab_config(target)
    c.modules=['http'];c.budgets.response_bytes=1024
    path,manifest=prepare_run(c,target+'bomb',tmp_path)
    assert asyncio.run(Scanner(path,manifest,c,{}).run_scan())=='partial'
    db=Store(path)
    assert db.rows('urls')[0]['bytes']==1024
    assert db.meta('limits')==['response body/decompression cap reached']
    db.close()


def test_request_cap_is_persistent_and_resume_does_not_reset(tmp_path):
    c=default_config('example.com');c.mode='demo';c.budgets.requests=2
    path,manifest=prepare_run(c,'example.com',tmp_path)
    assert asyncio.run(Scanner(path,manifest,c,{},fixtures()).run_scan())=='partial'
    db=Store(path);assert db.meta('requests')==2;db.close()
    manifest=json.loads((path/'manifest.json').read_text())
    assert asyncio.run(Scanner(path,manifest,c,{},fixtures()).run_scan())=='partial'
    db=Store(path);assert db.meta('requests')==2;db.close()


def test_cancellation_partial_report_then_resume_completed_work(tmp_path):
    c=default_config('example.com');c.mode='demo';c.budgets.depth=3
    path,manifest=prepare_run(c,'example.com',tmp_path)
    scanner=Scanner(path,manifest,c,{},fixtures())
    original=scanner.request
    async def interrupt(url):
        if url.endswith('/robots.txt'):raise asyncio.CancelledError()
        return await original(url)
    scanner.request=interrupt
    assert asyncio.run(scanner.run_scan())=='interrupted'
    db=Store(path);completed={j['url'] for j in db.rows('jobs') if j['state']=='completed'};assert completed=={'https://example.com/'};db.close()
    assert (path/'reports/index.html').exists()
    manifest=json.loads((path/'manifest.json').read_text())
    scanner=Scanner(path,manifest,c,{},fixtures())
    seen=[];original=scanner.request
    async def track(url):seen.append(url);return await original(url)
    scanner.request=track
    assert asyncio.run(scanner.run_scan())=='completed'
    assert not (completed & set(seen))
    db=Store(path)
    assert len([o for o in db.rows('observations') if o['kind']=='http' and o['subject']=='https://example.com/'])==1
    db.close()


def test_passive_makes_no_target_requests(tmp_path,monkeypatch):
    c=default_config('example.com');c.mode='passive'
    path,manifest=prepare_run(c,'example.com',tmp_path)
    async def forbidden(*args,**kwargs):raise AssertionError('target request attempted')
    monkeypatch.setattr(Scanner,'request',forbidden)
    assert asyncio.run(Scanner(path,manifest,c,{}).run_scan())=='completed'
    db=Store(path);assert db.meta('requests',0)==0;assert db.rows('urls')[0]['state']=='historical-only';db.close()


def test_scheduler_rate_and_retry_after(tmp_path,monkeypatch):
    c=default_config('example.com');store=Store(tmp_path);clock=[100.0];waits=[]
    monkeypatch.setattr('reconmap.engine.time.monotonic',lambda:clock[0])
    async def wait(delay):waits.append(delay);clock[0]+=delay
    monkeypatch.setattr('reconmap.engine.asyncio.sleep',wait)
    async def go():
        s=Scheduler(c,store)
        await s.reserve('https://example.com/')
        await s.reserve('https://example.com/a')
        assert waits==[0.5]
        s.throttle('https://example.com/',429,{'retry-after':'5'})
        await s.reserve('https://example.com/b')
        assert waits[-1]==5
        assert store.meta('requests')==3
    asyncio.run(go());store.close()


def test_demo_cli_resume_report_and_diff_readonly_baseline(tmp_path):
    assert main(['demo','--output-root',str(tmp_path)])==0
    a=tmp_path/'example.com';before=(a/'recon.sqlite').read_bytes()
    db=Store(a);count=db.meta('requests');db.close()
    assert main(['scan','--resume',str(a)])==0
    db=Store(a);assert db.meta('requests')==count;db.close()
    assert main(['demo','--output-root',str(tmp_path)])==0
    b=tmp_path/'1_example.com'
    before=(a/'recon.sqlite').read_bytes()
    assert main(['diff','--baseline',str(a),'--current',str(b)])==0
    assert (a/'recon.sqlite').read_bytes()==before
    diff=json.loads((b/'diff/comparison.json').read_text())
    assert diff['new_assets']==[] and diff['changed_assets']==[]
    manifest=json.loads((b/'manifest.json').read_text());manifest['state']='partial';atomic_json(b/'manifest.json',manifest)
    assert 'incomplete' in ' '.join(compare_runs(a,b)['warnings'])


def test_report_hostile_strings_cannot_execute(tmp_path):
    c=default_config('example.com');c.mode='demo';path,manifest=prepare_run(c,'example.com',tmp_path)
    db=Store(path)
    hostile='</script><script>alert(1)</script><img src="https://evil.test/" onerror="x">'
    db.finding('fixture','https://example.com/',hostile,{'excerpt':hostile})
    db.execute("INSERT INTO urls(url,grouping_key,source,title) VALUES(?,?,?,?)",('javascript:alert(1)','bad','fixture','=WEBSERVICE("https://evil.test/")'))
    generate_report(path,db);db.close()
    text=(path/'reports/index.html').read_text()
    assert hostile not in text and '\\u003c/script\\u003e' in text
    assert '<img src="https://evil.test/"' not in text
    assert 'href="javascript:' not in text
    assert "'=WEBSERVICE" in (path/'reports/urls.csv').read_text(encoding='utf-8-sig')


@pytest.mark.skipif(os.name=='nt',reason='POSIX SIGTERM; native Windows Ctrl+C needs a console runner')
def test_real_cli_sigterm_finalizes_and_releases_lock(tmp_path,lab_server):
    target,hits=lab_server;c=lab_config(target);c.budgets.per_host_rps=2
    import yaml
    config=tmp_path/'scope.yaml';config.write_text(yaml.safe_dump(c.model_dump()))
    output=tmp_path/'runs'
    proc=subprocess.Popen([sys.executable,'-m','reconmap','scan','--target',target,'--config',str(config),'--output-root',str(output)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    run=output/'127.0.0.1'
    deadline=time.monotonic()+10
    try:
        while time.monotonic()<deadline:
            if (run/'recon.sqlite').exists():
                try:
                    with sqlite3.connect(run/'recon.sqlite') as db:
                        row=db.execute("SELECT value FROM meta WHERE key='requests'").fetchone()
                        if row and int(row[0])>=1:break
                except sqlite3.OperationalError:pass
            if proc.poll() is not None:raise AssertionError(proc.communicate())
            time.sleep(0.02)
        else:raise AssertionError('No target request began')
        proc.terminate();stdout,stderr=proc.communicate(timeout=10)
        assert proc.returncode==130,(stdout,stderr)
        manifest=json.loads((run/'manifest.json').read_text())
        assert manifest['state']=='interrupted'
        assert (run/'reports/index.html').exists() and not (run/'run.lock').exists()
    finally:
        if proc.poll() is None:proc.kill();proc.wait()
