from __future__ import annotations

import asyncio
import json
import socket
from pathlib import Path
from types import SimpleNamespace

import dns.resolver
import pytest

from reconmap.cli import main
from reconmap.config import Scope, default_config
from reconmap.dnschecks import observe_dns
from reconmap.engine import Scanner, prepare_run
from reconmap.storage import RunLock, Store, atomic_json


def test_dns_cname_dangling_scope_and_wildcard_evidence(tmp_path,monkeypatch):
    config=default_config('example.com');config.scope.hosts=['example.com','*.example.com']
    path,manifest=prepare_run(config,'example.com',tmp_path)
    scanner=Scanner(path,manifest,config,{})
    scanner.add_url('https://example.com/','fixture',fetch=False)
    scanner.add_url('https://other.example.com/','fixture',fetch=False)
    queries=[]
    class Resolver:
        async def resolve(self,host,kind,**kwargs):
            queries.append((host,kind))
            if host=='example.com':return [SimpleNamespace(target='missing.example.com.')]
            if host=='other.example.com':return [SimpleNamespace(target='external.test.')]
            raise dns.resolver.NXDOMAIN()
    monkeypatch.setattr('reconmap.dnschecks.dns.asyncresolver.Resolver',Resolver)
    async def go():
        loop=asyncio.get_running_loop()
        async def getaddrinfo(*args,**kwargs):return [(socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',443))]
        monkeypatch.setattr(loop,'getaddrinfo',getaddrinfo)
        await observe_dns(scanner)
    asyncio.run(go())
    assert ('external.test','A') not in queries
    assert ('missing.example.com','A') in queries
    assert any(f['rule']=='dangling-dns-candidate' for f in scanner.store.rows('findings'))
    wildcard=next(o for o in scanner.store.rows('observations') if o['kind']=='dns-wildcard-evidence')
    assert json.loads(wildcard['data'])['classification']=='candidate wildcard'
    assert scanner.store.meta('dns_operations')==5
    scanner.store.close()


def test_stale_lock_explicit_recovery(tmp_path,monkeypatch):
    atomic_json(tmp_path/'run.lock',{'pid':999999,'host':'old-machine','token':'old'})
    with pytest.raises(ValueError,match='locked'):
        with RunLock(tmp_path):pass
    with RunLock(tmp_path,True):assert (tmp_path/'run.lock').exists()
    assert not (tmp_path/'run.lock').exists()


def test_bad_yaml_no_secret_in_error(tmp_path,capsys):
    p=tmp_path/'bad.yaml';p.write_text('scope: [ secretvalue : [')
    assert main(['scan','--target','example.com','--config',str(p)])==3
    assert 'secretvalue' not in capsys.readouterr().err


def test_config_unknown_field_not_logged(tmp_path,capsys):
    p=tmp_path/'bad.yaml';p.write_text('scope: {hosts: [example.com]}\npassword: supersecret')
    assert main(['scan','--target','example.com','--config',str(p)])==3
    assert 'supersecret' not in capsys.readouterr().err


def test_artifact_cap_preserves_partial_outputs(tmp_path):
    config=default_config('example.com');config.mode='demo';config.budgets.artifact_bytes=512*1024
    path,manifest=prepare_run(config,'example.com',tmp_path)
    from reconmap.demo import fixtures
    assert asyncio.run(Scanner(path,manifest,config,{},fixtures()).run_scan())=='partial'
    assert (path/'reports/index.html').exists()
    current=json.loads((path/'manifest.json').read_text())
    assert any('disk cap' in v for v in current['limits'])
    assert sum(p.stat().st_size for p in path.rglob('*') if p.is_file())<config.budgets.artifact_bytes


def test_analyst_confirmation_requires_note_and_records_action(tmp_path):
    assert main(['demo','--output-root',str(tmp_path)])==0
    run=tmp_path/'example.com';store=Store(run);fingerprint=store.rows('findings')[0]['fingerprint'];store.close()
    assert main(['validate','--run',str(run),'--finding',fingerprint,'--status','manually confirmed','--note',''])==3
    assert main(['validate','--run',str(run),'--finding',fingerprint,'--status','manually confirmed','--note','Synthetic test of explicit analyst action'])==0
    store=Store(run)
    assert store.rows('analyst_actions')[0]['status']=='manually confirmed'
    assert next(f for f in store.rows('findings') if f['fingerprint']==fingerprint)['validation']=='manually confirmed'
    store.close()


def test_template_allowlist_is_bounded():
    import yaml
    folder=Path(__file__).parents[1]/'src/reconmap/templates'
    for file in folder.glob('*.yaml'):
        data=yaml.safe_load(file.read_text())
        assert len(data['http'])==1
        request=data['http'][0]
        assert request['method']=='GET' and request['redirects'] is False
        assert request['max-size']==4096 and len(request['path'])==1
        assert not set(data)&{'dns','headless','code','javascript','tcp','workflow'}
