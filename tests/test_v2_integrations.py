import asyncio
import json
import os
import socket
import sys
from pathlib import Path

import pytest

from reconmap.adapters import ToolInfo, parse_records, identify
from reconmap.cli import main
from reconmap.config import default_config
from reconmap.engine import Scanner, prepare_run
from reconmap.selectors import resolve_selection
from reconmap.security import redact
from reconmap.storage import Store, timestamp


@pytest.mark.parametrize('name,text', [
    ('dnsx','{"host":"example.com","a":["8.8.8.8"],"cname":["external.test"]}'),
    ('httpx','{"url":"https://example.com/","status_code":403,"tech":["nginx"]}'),
    ('katana','{"request":{"method":"GET","endpoint":"https://example.com/api"},"response":{"status_code":200}}'),
    ('nuclei','{"template-id":"reconmap-git-head","matched-at":"https://example.com/.git/HEAD","info":{"severity":"info"}}'),
])
def test_reviewed_active_schemas_are_parseable_but_do_not_execute(name,text):
    records,errors=parse_records(name,text+'\nmalformed-json')
    assert len(records)==1 and errors
    assert parse_records(name,'[]')[1]


def test_native_dns_only_fallback_and_private_answer_rejection(tmp_path,monkeypatch):
    config=resolve_selection(default_config('example.com'),tools='3')
    run,manifest=prepare_run(config,'example.com',tmp_path)
    info=ToolInfo('dnsx',None,'missing',None,False,False,'fixture','missing')
    scanner=Scanner(run,manifest,config,{'dnsx':info})
    class Resolver:
        async def resolve(self,*unused,**kwargs):return []
    monkeypatch.setattr('reconmap.dnschecks.dns.asyncresolver.Resolver',Resolver)
    async def go():
        loop=asyncio.get_running_loop()
        async def resolve(*unused,**kwargs):return [(socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',443))]
        monkeypatch.setattr(loop,'getaddrinfo',resolve)
        return await scanner.run_scan()
    assert asyncio.run(go())=='partial'
    store=Store(run)
    try:
        assert store.rows('dns')[0]['address']=='127.0.0.1'
        assert next(s for s in store.rows('stages') if s['name']=='dns')['state']=='partial'
        assert store.meta('requests',0)==0
        assert store.rows('tool_executions')[0]['state']=='unavailable'
    finally:store.close()


def test_parent_hosts_do_not_grant_narrowed_dns_scope(tmp_path,monkeypatch):
    config=default_config('example.com')
    run,manifest=prepare_run(config,'example.com',tmp_path)
    scanner=Scanner(run,manifest,config,{})
    scanner.store.execute('INSERT INTO hosts VALUES(?,?,?)',('excluded.example.com','untested',timestamp()))
    scanner.add_url('https://example.com/','fixture',fetch=False)
    queried=[]
    class Resolver:
        async def resolve(self,host,*unused,**kwargs):queried.append(host);return []
    monkeypatch.setattr('reconmap.dnschecks.dns.asyncresolver.Resolver',Resolver)
    try:
        from reconmap.dnschecks import observe_dns
        asyncio.run(observe_dns(scanner))
        assert queried==['example.com']
    finally:scanner.store.close()


def test_historical_url_credentials_are_redacted():
    value='https://user:fixture-password@example.com/api?t%6fken=fixture-secret'
    result=redact(value)
    assert 'fixture-password' not in result and 'fixture-secret' not in result


def test_durable_queue_is_bounded_without_dropping_discovery_evidence(tmp_path):
    config=default_config('example.com');config.mode='demo';config.budgets.requests=2
    run,manifest=prepare_run(config,'example.com',tmp_path)
    scanner=Scanner(run,manifest,config,{})
    try:
        for number in range(3):scanner.add_url(f'https://example.com/api/{number}','fixture')
        assert len(scanner.store.rows('jobs'))==2 and len(scanner.store.rows('urls'))==3
        assert any('global job queue cap' in reason for reason in scanner.limits)
    finally:scanner.store.close()


@pytest.mark.skipif(os.name=='nt',reason='Executable script fixture requires POSIX; portable command gate is tested separately')
def test_armed_active_binary_never_reaches_scan_execution(tmp_path):
    marker=tmp_path/'unauthorized-attempt'
    binary=tmp_path/'httpx'
    binary.write_text(f'#!{sys.executable}\nimport sys,pathlib\nif "-version" in sys.argv: print("1.12.0")\nelif "-h" in sys.argv: print("ProjectDiscovery -list -json -rate-limit -disable-update-check -proxy -resolvers -no-fallback-scheme -include-response-header -response-size-to-read")\nelse: pathlib.Path({str(marker)!r}).write_text("would connect outside scope");sys.exit(99)\n')
    binary.chmod(0o700)
    config=tmp_path/'scope.yaml';config.write_text('scope: {hosts: [example.com]}\nmode: demo\n')
    assert identify('httpx',str(binary)).compatible
    assert main(['scan','--target','example.com','--config',str(config),'--tools','4','--tool',f'httpx={binary}','--output-root',str(tmp_path/'out')])==2
    assert not marker.exists()
    store=Store(tmp_path/'out/example.com')
    assert store.rows('tool_executions')[0]['state']=='blocked-by-policy'
    store.close()


def test_unknown_unversioned_jsluice_hash_is_refused(tmp_path,monkeypatch):
    from reconmap.adapters import ProcessResult
    path=tmp_path/'jsluice.exe';path.write_bytes(b'unreviewed build');path.chmod(0o700)
    monkeypatch.setattr('reconmap.adapters.shutil.which',lambda name:str(path))
    async def execute(*unused,**kw):return ProcessResult(0,'jsluice - Extract URLs urls secrets','')
    monkeypatch.setattr('reconmap.adapters.execute',execute)
    info=identify('jsluice',str(path))
    assert info.available and not info.compatible and not info.supported


def test_passive_adapter_provenance_and_input_filtering(tmp_path,monkeypatch):
    from reconmap.adapters import ProcessResult
    config=resolve_selection(default_config('example.com'),tools='1,2',mode='passive')
    config.scope.hosts=['example.com','*.example.com']
    run,manifest=prepare_run(config,'example.com',tmp_path)
    tools={name:ToolInfo(name,'/fixture','reviewed','a'*64,True,True,'fixture','fixture') for name in ['subfinder','urlfinder']}
    async def execute(argv,*unused,**kw):
        if '-json' in argv:return ProcessResult(0,'{"host":"a.example.com","sources":["crtsh"]}\n{"host":"outside.test"}','')
        return ProcessResult(0,'{"url":"https://example.com/api?q=one","sources":["commoncrawl"]}\nmalformed','')
    monkeypatch.setattr('reconmap.integrations.execute',execute)
    assert asyncio.run(Scanner(run,manifest,config,tools).run_scan())=='partial'
    store=Store(run)
    try:
        assert len(store.rows('tool_executions'))==2
        assert not store.rows('jobs') and store.meta('requests',0)==0
        assert next(r for r in store.rows('urls') if 'outside.test' in r['url'])['state']=='external-reference'
        assert {'subfinder','urlfinder'} <= {r['source'] for r in store.rows('observations')}
        assert next(r for r in store.rows('tool_executions') if r['name']=='subfinder')['state']=='completed'
        assert next(r for r in store.rows('tool_executions') if r['name']=='urlfinder')['state']=='partial'
    finally:store.close()
