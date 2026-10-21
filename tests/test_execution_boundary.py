"""Offline broker, runtime prerequisite, strict and evidence regressions."""
import asyncio
import base64
import hashlib
import json
import sys
from types import SimpleNamespace

import dns.message
import dns.rrset
import pytest

from reconmap import active_tools as active
from reconmap import execution_boundary as boundary
from reconmap.adapters import ProcessResult, ToolInfo, ToolTimeout
from reconmap.cli import main
from reconmap.config import default_config
from reconmap.engine import Scanner, Response, prepare_run
from reconmap.orchestrator import STAGE_NAMES, fallback_allowed, finalize_enrichments
from reconmap.selectors import resolve_selection
from reconmap.storage import Store, read_manifest


@pytest.fixture
def scanner(tmp_path):
    config=resolve_selection(default_config('https://127.0.0.1'),tools='3,4,5,8')
    config.scope.lab=True
    config.scope.exclude_paths=['/excluded']
    config.budgets.requests=20
    config.budgets.per_host_rps=100
    config.budgets.overall_rps=100
    config.budgets.depth=2
    run,manifest=prepare_run(config,'https://127.0.0.1',tmp_path)
    infos={name:ToolInfo(name,sys.executable,'fixture',hashlib.sha256(b'fixture').hexdigest(),True,True,'fixture','fixture',True)
           for name in config.selected_tools}
    instance=Scanner(run,manifest,config,infos,{})
    instance.boundary=boundary.Boundary(True,'isolated unit fixture','/fixture/bwrap')
    instance.add_url('https://127.0.0.1/','seed')
    yield instance
    instance.store.close()


def request(url='https://127.0.0.1/',method='GET',**extra):
    return {'kind':'http','method':method,'url':url,**extra}


@pytest.mark.parametrize('url,method,extra',[
    ('https://outside.test/','GET',{}),('https://sub.127.0.0.1/','GET',{}),
    ('https://127.0.0.1:81/','GET',{}),('http://127.0.0.1/excluded/file','GET',{}),
    ('https://127.0.0.1/','POST',{}),('https://127.0.0.1/logout','GET',{}),
    ('https://127.0.0.1/','GET',{'has_credentials':True}),
    ('https://127.0.0.1/%65xcluded/secret','GET',{}),
    ('ftp://127.0.0.1/','GET',{}),('https://127.0.0.1/?action=delete','GET',{}),
])
def test_denied_requests_never_reach_transport(scanner,url,method,extra):
    broker=boundary.Broker(scanner,'katana')
    assert not asyncio.run(broker.dispatch(request(url,method,**extra)))['allowed']
    assert scanner.store.meta('requests',0)==0
    assert not any(r['kind']=='http' for r in scanner.store.rows('observations'))
    assert broker.metrics['denied_requests']==1


def test_shared_remaining_budget_and_concurrent_reservations(scanner):
    scanner.config.budgets.requests=2
    # Queue limits remain conservative; use the scheduler directly to test races.
    async def run():
        results=await asyncio.gather(*(scanner.request(f'https://127.0.0.1/{n}') for n in range(8)),return_exceptions=True)
        assert sum(isinstance(r,Response) for r in results)==2
    asyncio.run(run())
    assert scanner.store.meta('requests')==2
    broker=boundary.Broker(scanner,'httpx')
    assert not asyncio.run(broker.dispatch(request()))['allowed']
    assert scanner.store.meta('requests')==2


def test_unknown_secondary_requests_cannot_bypass_scheduler_depth(scanner):
    broker=boundary.Broker(scanner,'katana')
    assert not asyncio.run(broker.dispatch(request('https://127.0.0.1/unproven')))['allowed']
    scanner.add_url('https://127.0.0.1/deep','script',depth=3)
    assert not asyncio.run(broker.dispatch(request('https://127.0.0.1/deep')))['allowed']
    assert scanner.store.meta('requests',0)==0


def test_response_reuse_redirects_sources_and_graph(scanner):
    scanner.fixtures['https://127.0.0.1/']=Response(302,{'location':'https://outside.test/private','content-type':'text/html'},b'')
    first=boundary.Broker(scanner,'httpx');second=boundary.Broker(scanner,'katana')
    async def run():
        assert (await first.dispatch(request()))['status']==302
        assert (await second.dispatch(request()))['status']==302
        assert not (await second.dispatch(request('https://outside.test/private')))['allowed']
    asyncio.run(run())
    assert scanner.store.meta('requests')==1 and second.metrics['reused_responses']==1
    assert {r['source'] for r in scanner.store.rows('observations') if r['kind']=='external-response-delivered'}=={'httpx','katana'}
    finalize_enrichments(scanner)
    from reconmap.asset_graph import export_graph
    summary=export_graph(scanner.run,scanner.store)
    assert summary['tested_urls']==1
    data=json.loads((scanner.run/'graph/asset-graph.json').read_text(encoding='utf-8'))
    outside=next(n for n in data['nodes'] if n.get('url')=='https://outside.test/private' and n['type']!='http_request')
    assert 'live-observed' not in outside['states']
    assert any(e['type']=='redirects_to' for e in data['edges'])


def test_nuclei_cannot_use_arbitrary_already_scheduled_urls(scanner):
    broker=boundary.Broker(scanner,'nuclei')
    assert not asyncio.run(broker.dispatch(request()))['allowed']
    assert scanner.store.meta('requests',0)==0


def test_dns_queries_are_accounted_without_cname_chasing(scanner,monkeypatch):
    scanner.config.scope.hosts=['authorized.test']
    scanner.config.budgets.dns_queries=1
    calls=[]
    monkeypatch.setattr(boundary.dns.resolver,'Resolver',lambda:SimpleNamespace(nameservers=['127.0.0.1'],port=1054))
    async def udp(query,host,**kwargs):
        calls.append(str(query.question[0].name))
        answer=dns.message.make_response(query)
        answer.answer.append(dns.rrset.from_text('authorized.test.',30,'IN','CNAME','outside.test.'))
        return answer
    monkeypatch.setattr(boundary.dns.asyncquery,'udp',udp)
    broker=boundary.Broker(scanner,'dnsx')
    def query(host):
        return {'kind':'dns','wire':base64.b64encode(dns.message.make_query(host,'CNAME').to_wire()).decode()}
    async def run():
        assert (await broker.dispatch(query('authorized.test')))['allowed']
        denied=await broker.dispatch(query('outside.test'))
        assert dns.message.from_wire(base64.b64decode(denied['wire'])).rcode()==5
        assert not (await broker.dispatch(query('authorized.test')))['allowed']
    asyncio.run(run())
    assert calls==['authorized.test.'] and scanner.store.meta('dns_operations')==1
    assert scanner.store.rows('dns')[0]['source']=='dnsx'


def test_synthetic_transport_dns_never_becomes_infrastructure(scanner):
    broker=boundary.Broker(scanner,'httpx')
    message={'kind':'dns','wire':base64.b64encode(dns.message.make_query('127.0.0.1','A').to_wire()).decode()}
    assert asyncio.run(broker.dispatch(message))['allowed']
    assert scanner.store.rows('dns')==[] and scanner.store.meta('dns_operations',0)==0


@pytest.mark.parametrize('case',['missing','incompatible','backend','native','template'])
def test_strict_preflight_specific_failures_before_run(tmp_path,monkeypatch,case,capsys):
    from reconmap import cli
    config=resolve_selection(default_config('https://example.com'),tools='4,8')
    config.strict_tools=True
    info=lambda name:ToolInfo(name,'/fixture/'+name,'fixture','a'*64,case!='missing',case not in {'missing','incompatible'},'fixture','bad version/flags',case!='incompatible')
    monkeypatch.setattr(cli,'identify_selected',lambda config,name:info(name))
    monkeypatch.setattr(boundary,'probe_boundary',lambda:boundary.Boundary(case!='backend','namespace prerequisite absent'))
    if case=='native':config.execution_engines={'httpx':'native'}
    if case=='template':config.scope.exclude_paths=['/.env']
    assert cli.run(config,'https://example.com',tmp_path/'runs',no_progress=True)==4
    assert not (tmp_path/'runs').exists()
    error=capsys.readouterr().err
    assert {'missing':'Executable not found','incompatible':'Unsupported executable','backend':'namespace prerequisite absent',
            'native':'Native engine explicitly selected','template':'cannot comply with scope'}[case] in error


@pytest.mark.parametrize('strict',[False,True])
@pytest.mark.parametrize('failure',['crash','timeout','partial'])
def test_partial_external_output_persists_and_strict_refuses_fallback(scanner,monkeypatch,strict,failure):
    scanner.config.strict_tools=strict
    async def run(scanner,info,cwd,argv,inputs):
        broker=boundary.Broker(scanner,info.name)
        await broker.dispatch(request())
        result=ProcessResult(1 if failure=='crash' else 0,'{"url":"https://127.0.0.1/","status_code":200}\ninvalid','RECONMAP_TOOL_STARTED')
        if failure=='timeout':
            error=ToolTimeout(result);error.broker=broker;raise error
        return result,broker
    monkeypatch.setattr(active,'run_contained',run)
    assert asyncio.run(active.run_active(scanner,'httpx')) is False
    assert scanner.store.meta('requests')==1
    assert scanner.store.meta('executed:httpx') is True
    result=json.loads(scanner.store.rows('stage_results')[0]['result_json'])
    assert result['actual_execution_engines']==['httpx']
    assert result['process_executions'][0]['input_count']==1
    assert result['discovered_records']==1 and not result['fallback_used']
    assert fallback_allowed(scanner,'httpx') is (not strict)
    assert any(r['kind']=='external-tool-output' for r in scanner.store.rows('observations'))


def test_successful_external_resume_reuses_inputs_and_reports_process(scanner,monkeypatch):
    calls=[]
    async def run(scanner,info,cwd,argv,inputs):
        calls.append(inputs)
        broker=boundary.Broker(scanner,'httpx');await broker.dispatch(request())
        return ProcessResult(0,'{"url":"https://127.0.0.1/","status_code":200}','RECONMAP_TOOL_STARTED'),broker
    monkeypatch.setattr(active,'run_contained',run)
    assert asyncio.run(active.run_active(scanner,'httpx'))
    scanner.store.close()
    scanner.store=Store(scanner.run)
    assert asyncio.run(active.run_active(scanner,'httpx'))
    assert len(calls)==1 and scanner.store.meta('requests')==1
    from reconmap.reporting import generate_report
    generate_report(scanner.run,scanner.store)
    coverage=json.loads((scanner.run/'reports/coverage.json').read_text(encoding='utf-8'))
    result=next(t for t in coverage['tools'] if t['tool']=='httpx')
    assert result['actually_ran'] and result['engines']==['httpx']
    assert result['process_executions'][0]['exit_code']==0


def test_nuclei_match_requires_current_delivered_response_and_signature(scanner):
    scanner.fixtures['https://127.0.0.1/.git/HEAD']=Response(200,{'content-type':'text/plain'},b'ref: refs/heads/main\n')
    hit={'template-id':'reconmap-git-head-v1','matched-at':'https://127.0.0.1/.git/HEAD'}
    active.ingest(scanner,'nuclei',[hit],'raw/fixture')
    assert scanner.store.rows('findings')==[]
    broker=boundary.Broker(scanner,'nuclei')
    assert asyncio.run(broker.dispatch(request(hit['matched-at'])))['allowed']
    active.ingest(scanner,'nuclei',[hit],'raw/fixture')
    findings=scanner.store.rows('findings')
    assert len(findings)==1 and findings[0]['source']=='nuclei'
    assert findings[0]['severity']=='unassessed'
    assert json.loads(findings[0]['evidence'])['template_id']==hit['template-id']


def test_windows_backend_is_precise_and_never_probes_linux(monkeypatch):
    monkeypatch.setattr(boundary.platform,'system',lambda:'Windows')
    monkeypatch.setattr(boundary.subprocess,'run',lambda *a,**k:pytest.fail('Windows attempted Linux isolation'))
    result=boundary.probe_boundary()
    assert not result.available and 'No verified' in result.reason


def test_namespace_failure_never_spawns_tool(scanner,tmp_path,monkeypatch):
    monkeypatch.setattr(boundary,'probe_boundary',lambda:boundary.Boundary(False,'user namespace disabled'))
    monkeypatch.setattr(boundary,'execute',lambda *a,**k:pytest.fail('Uncontained execution'))
    with pytest.raises(ValueError,match='user namespace disabled'):
        asyncio.run(boundary.run_contained(scanner,scanner.tools['httpx'],tmp_path,[],[]))


def test_dns_broker_enforces_rate_without_trusting_tool_flags(scanner, monkeypatch):
    scanner.config.scope.hosts=['authorized.test']
    scanner.config.budgets.overall_rps=2
    scanner.config.budgets.per_host_rps=1
    now=[100.0];waits=[]
    monkeypatch.setattr(boundary.time,'monotonic',lambda:now[0])
    # Scheduler uses the same monotonic clock; reset its origin for this fixture.
    scanner.scheduler.started=now[0]
    async def sleep(seconds):
        waits.append(seconds);now[0]+=seconds
    async def udp(query,*args,**kwargs):return dns.message.make_response(query)
    monkeypatch.setattr(boundary.asyncio,'sleep',sleep)
    monkeypatch.setattr(boundary.dns.asyncquery,'udp',udp)
    monkeypatch.setattr(boundary.dns.resolver,'Resolver',lambda:SimpleNamespace(nameservers=['127.0.0.1'],port=1054))
    broker=boundary.Broker(scanner,'dnsx')
    message={'kind':'dns','wire':base64.b64encode(dns.message.make_query('authorized.test','A').to_wire()).decode()}
    async def run():
        assert (await broker.dispatch(message))['allowed']
        assert (await broker.dispatch(message))['allowed']
    asyncio.run(run())
    assert waits==[1.0] and scanner.store.meta('dns_operations')==2


def test_repeated_tool_invocations_accumulate_measured_usage(scanner):
    from reconmap.orchestrator import record_execution
    for value in (2,3):
        record_execution(scanner,'httpx',state='completed',process={'request_accounting':{'http_requests':value}},
                         accounting={'http_requests':value,'reused_responses':1,'backend':boundary.BACKEND})
    row=scanner.store.conn.execute('SELECT result_json FROM stage_results WHERE name=?',(STAGE_NAMES['httpx'],)).fetchone()
    data=json.loads(row[0])
    assert data['request_accounting']['http_requests']==5
    assert data['request_accounting']['reused_responses']==2
    assert len(data['process_executions'])==2


def test_katana_script_admission_keeps_method_depth_and_provenance(scanner):
    base='https://127.0.0.1'
    scanner.fixtures[base+'/']=Response(200,{'content-type':'text/html'},b'<script src="/app.js"></script>')
    scanner.fixtures[base+'/app.js']=Response(200,{'content-type':'application/javascript'},b'fetch("/api/from-script");fetch("/api/change",{method:"POST"});')
    scanner.fixtures[base+'/api/from-script']=Response(200,{'content-type':'application/json'},b'[]')
    broker=boundary.Broker(scanner,'katana')
    async def run():
        for path in ('/','/app.js','/api/from-script'):
            reply=await broker.dispatch(request(base+path))
            assert reply['allowed'],reply
        assert not (await broker.dispatch(request(base+'/api/change')))['allowed']
    asyncio.run(run())
    assert scanner.store.meta('requests')==3
