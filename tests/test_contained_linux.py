"""Genuine binaries and adversarial processes in the production Linux sandbox.

Required CI uses RECONMAP_REQUIRE_CONTAINMENT=1: missing isolation fails that job.
The portable/core job can run without this optional Linux-only backend.
"""
import asyncio
import hashlib
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import aiohttp.web
import dns.message
import dns.rrset
import pytest

from reconmap import execution_boundary as boundary
from reconmap.adapters import ToolInfo, identify, ToolTimeout, ToolOutputLimit
from reconmap.config import default_config
from reconmap.engine import Scanner, Response, prepare_run
from reconmap.selectors import resolve_selection
from reconmap.storage import Store, read_manifest


@pytest.fixture
def isolated():
    status=boundary.probe_boundary()
    if os.environ.get('RECONMAP_REQUIRE_CONTAINMENT')=='1':
        assert status.available,status.reason
    elif not status.available:
        pytest.skip(status.reason)
    return status


def make_scanner(tmp_path,target,tools='4',strict=True,fixtures=None):
    config=resolve_selection(default_config(target),tools=tools)
    config.scope.lab=True;config.scope.exclude_paths=['/excluded']
    config.strict_tools=strict;config.budgets.depth=3
    config.budgets.per_host_rps=50;config.budgets.overall_rps=50
    config.budgets.requests=40;config.budgets.provider_seconds=30
    # Katana waits one request-timeout for queue quiescence per input root.
    # This local fixture needs no Internet latency; keep three roots inside the
    # deliberately short process ceiling instead of consuming 3 * 15 seconds.
    config.budgets.timeout=2
    run,manifest=prepare_run(config,target,tmp_path)
    return Scanner(run,manifest,config,{},fixtures)


def script_info(tmp_path,code):
    path=tmp_path/'isolated fixture'
    path.write_text('#!/usr/bin/python3\n'+code,encoding='utf-8');path.chmod(0o700)
    return ToolInfo('httpx',str(path),'fixture',hashlib.sha256(path.read_bytes()).hexdigest(),True,True,'fixture','fixture',True)


def test_isolation_blocks_direct_child_egress_and_https_exclusions(tmp_path,isolated):
    async def run():
        hits=[]
        async def host_service(reader,writer):
            hits.append(True);writer.close()
        service=await asyncio.start_server(host_service,'127.0.0.1',0)
        port=service.sockets[0].getsockname()[1]
        scanner=make_scanner(tmp_path,'https://127.0.0.1/',fixtures={'https://127.0.0.1/':Response(200,{'content-type':'text/plain'},b'approved response')})
        scanner.add_url('https://127.0.0.1/','seed')
        info=script_info(tmp_path,f'''
import http.client,json,socket,ssl,subprocess,sys
def blocked_direct():
 try:
  socket.create_connection(('127.0.0.1',{port}),timeout=1)
 except OSError:return
 raise AssertionError('Host network reachable without broker')
blocked_direct()
descendant=subprocess.run([sys.executable,'-c',"import socket;socket.create_connection(('127.0.0.1',{port}),timeout=1)"],check=False,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
assert descendant.returncode!=0,'Descendant reached host network'
try:
 socket.socket(40,socket.SOCK_STREAM)
except OSError:pass
else:raise AssertionError('AF_VSOCK must be denied by seccomp')
for path,expected in [('/',200),('/excluded/private',451)]:
 connection=http.client.HTTPSConnection('127.0.0.1',18080,context=ssl._create_unverified_context(),timeout=5)
 connection.set_tunnel('127.0.0.1',443)
 connection.request('GET',path)
 response=connection.getresponse();assert response.status==expected,(path,response.status)
 response.read();connection.close()
print(json.dumps({{'url':'https://127.0.0.1/','status_code':200}}))
''')
        try:
            result,broker=await boundary.run_contained(scanner,info,tmp_path,[],['https://127.0.0.1/'])
            assert result.code==0,result.stderr
            assert 'RECONMAP_TOOL_STARTED' in result.stderr
            assert scanner.store.meta('requests')==1 and not hits
            assert broker.metrics['denied_requests']==1
            assert not scanner.store.conn.execute("SELECT 1 FROM observations WHERE subject LIKE '%excluded%' AND kind='http'").fetchone()
        finally:
            scanner.store.close();service.close();await service.wait_closed()
    asyncio.run(run())


@pytest.mark.parametrize('failure',['timeout','output','crash','cancel'])
def test_isolated_process_limits_and_partial_prefix(tmp_path,isolated,failure):
    scanner=make_scanner(tmp_path,'http://127.0.0.1/')
    scanner.config.budgets.provider_seconds=1
    scanner.config.budgets.response_bytes=1024
    body='import sys,time\nprint("complete record",flush=True)\n'
    body+= 'print("x"*10000,flush=True)\ntime.sleep(10)\n' if failure=='output' else 'sys.exit(7)\n' if failure=='crash' else 'time.sleep(10)\n'
    info=script_info(tmp_path,body)
    async def run():
        operation=boundary.run_contained(scanner,info,tmp_path,[],[])
        if failure=='crash':
            result,_=await operation
            assert result.code==7 and result.stdout.startswith('complete record')
        elif failure=='cancel':
            task=asyncio.create_task(operation)
            await asyncio.sleep(.5);task.cancel()
            with pytest.raises(asyncio.CancelledError):await task
        else:
            with pytest.raises(ToolOutputLimit if failure=='output' else ToolTimeout) as caught:
                await operation
            assert caught.value.result.stdout.startswith('complete record')
    try:asyncio.run(run())
    finally:scanner.store.close()


@pytest.mark.parametrize('scheme',['http','https'])
def test_real_four_tools_strict_pipeline_reports_and_resume(tmp_path,isolated,monkeypatch,scheme):
    directory=os.environ.get('RECONMAP_TEST_ACTIVE_TOOLS')
    if not directory:
        if os.environ.get('RECONMAP_REQUIRE_CONTAINMENT')=='1':pytest.fail('Reviewed active binary directory required')
        pytest.skip('Set RECONMAP_TEST_ACTIVE_TOOLS to reviewed Linux binaries')
    infos={name:identify(name,str(Path(directory)/name)) for name in ('dnsx','httpx','katana','nuclei')}
    assert all(info.supported for info in infos.values()),{name:info.reason for name,info in infos.items()}
    async def run():
        hits=[];questions=[]
        class DNSFixture(asyncio.DatagramProtocol):
            def connection_made(self,transport):self.transport=transport
            def datagram_received(self,data,address):
                query=dns.message.from_wire(data);question=query.question[0]
                questions.append((str(question.name),question.rdtype))
                answer=dns.message.make_response(query)
                if question.rdtype in {1,28}:
                    answer.answer.append(dns.rrset.from_text(str(question.name),1,'IN',question.rdtype,'127.0.0.1' if question.rdtype==1 else '::1'))
                self.transport.sendto(answer.to_wire(),address)
        udp,_=await asyncio.get_running_loop().create_datagram_endpoint(DNSFixture,local_addr=('127.0.0.1',0))
        dns_port=udp.get_extra_info('sockname')[1]
        monkeypatch.setattr(boundary.dns.resolver,'Resolver',lambda:SimpleNamespace(nameservers=['127.0.0.1'],port=dns_port))
        async def handler(request):
            hits.append((request.method,request.path))
            bodies={'/':('<script src="/app.js"></script><a href="/api/v1/projects">API</a><a href="/excluded/private">excluded</a><a href="http://outside.invalid/">outside</a><form action="/session" method="POST"></form>','text/html'),
                    '/app.js':('fetch("/api/from-script");','application/javascript'),
                    '/api/v1/projects':('[]','application/json'),'/api/from-script':('[]','application/json'),
                    '/.git/HEAD':('ref: refs/heads/main\n','text/plain'),
                    '/.env':('DB_PASSWORD=synthetic-fixture\n','text/plain')}
            body,mime=bodies.get(request.path,('missing','text/plain'))
            return aiohttp.web.Response(text=body,content_type=mime,status=200 if request.path in bodies else 404)
        app=aiohttp.web.Application();app.router.add_route('*','/{path:.*}',handler)
        runner=aiohttp.web.AppRunner(app);await runner.setup()
        context=None
        if scheme=='https':
            import ssl,subprocess
            cert,key=tmp_path/'target-cert.pem',tmp_path/'target-key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),
                '-out',str(cert),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-days','1'],capture_output=True,check=True)
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
            # Trust only this fixture's CA; production TLS validation is unchanged.
            trusted=ssl.create_default_context(cafile=str(cert))
            connector=aiohttp.TCPConnector
            monkeypatch.setattr(boundary.aiohttp,'TCPConnector',lambda **kw:connector(ssl=trusted,**kw))
        site=aiohttp.web.TCPSite(runner,'127.0.0.1',0,ssl_context=context);await site.start()
        port=site._server.sockets[0].getsockname()[1]
        scanner=make_scanner(tmp_path,f'{scheme}://localhost:{port}/',tools='3,4,5,8')
        scanner.tools=infos
        run_path=scanner.run
        try:
            state=await scanner.run_scan()
            store=Store(run_path)
            try:
                results={r['name']:json.loads(r['result_json']) for r in store.rows('stage_results')}
                assert state=='completed',json.dumps({name:{k:r[k] for k in ('status','failure_reason','request_accounting')} for name,r in results.items()}) + str([dict(r) for r in store.rows('stages') if r['state']=='failed']) + ' denials='+str([(r['subject'],r['data']) for r in store.rows('observations') if r['kind']=='external-request-denied'])+' hits='+str(hits)
                for name in infos:
                    assert store.meta('executed:'+name) is True,name
                assert questions and all(host=='localhost.' for host,_ in questions)
                assert all(method=='GET' and not path.startswith('/excluded') and path!='/session' for method,path in hits)
                assert len(hits)==len(set(hits)),hits
                assert ('GET','/app.js') in hits and ('GET','/api/from-script') in hits, str([(r['subject'],r['data']) for r in store.rows('observations') if r['kind']=='external-request-denied'])
                assert any(r['source']=='nuclei' and r['rule']=='git-head' for r in store.rows('findings'))
                assert any(r['source']=='dnsx' for r in store.rows('dns'))
                assert all(not r['fallback_used'] for r in results.values())
                assert (run_path/'reports/index.html').is_file() and (run_path/'graph/asset-map.html').is_file()
                original_count=store.meta('requests')
            finally:store.close()
            resumed=Scanner(run_path,read_manifest(run_path),scanner.config,infos)
            assert await resumed.run_scan()=='completed'
            assert len(hits)==original_count
        finally:
            udp.close();await runner.cleanup()
    asyncio.run(run())


@pytest.mark.skipif(sys.platform!='linux',reason='Linux worker; no platform backend implied')
def test_https_proxy_preserves_original_host_authority(tmp_path,monkeypatch):
    import base64, http.client, shutil, ssl, subprocess
    if not shutil.which('openssl'):pytest.skip('Local TLS fixture requires OpenSSL')
    from reconmap import isolated_worker as worker
    messages=[]
    async def rpc(message):
        messages.append(message)
        return {'allowed':True,'status':200,'body':base64.b64encode(b'fixture').decode(),'headers':{}}
    monkeypatch.setattr(worker,'rpc',rpc)
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(tmp_path/'key'),
                    '-out',str(tmp_path/'cert'),'-subj','/CN=fixture','-days','1'],capture_output=True,check=True)
    async def run():
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(tmp_path/'cert',tmp_path/'key')
        server=await asyncio.start_server(lambda r,w:worker.proxy(r,w,context),'127.0.0.1',0)
        port=server.sockets[0].getsockname()[1]
        def requests():
            for host in ('127.0.0.1','127.0.0.1:443'):
                conn=http.client.HTTPSConnection('127.0.0.1',port,context=ssl._create_unverified_context(),timeout=5)
                conn.set_tunnel('127.0.0.1',443);conn.request('GET','/Case?a=1&a=2',headers={'Host':host})
                response=conn.getresponse();assert response.status==200;response.read();conn.close()
        try:await asyncio.to_thread(requests)
        finally:server.close();await server.wait_closed()
    asyncio.run(run())
    assert [m['url'] for m in messages if m['kind']=='http']==[
        'https://127.0.0.1/Case?a=1&a=2','https://127.0.0.1:443/Case?a=1&a=2']


@pytest.mark.parametrize('name',['subfinder','urlfinder'])
def test_real_provider_processes_with_isolated_fixture_responses(tmp_path,isolated,monkeypatch,name):
    """Actual provider clients, actual parsers/SQLite, zero public provider traffic.

    Only the invocation transport is redirected to the production namespace and
    fixture-backed broker. This is not a mocked executable or fabricated output.
    """
    import datetime
    from reconmap import integrations
    directory=os.environ.get('RECONMAP_TEST_ACTIVE_TOOLS')
    if not directory:
        if os.environ.get('RECONMAP_REQUIRE_CONTAINMENT')=='1':pytest.fail('Reviewed binary directory required')
        pytest.skip('Reviewed provider binaries required')
    info=identify(name,str(Path(directory)/name))
    assert info.supported,info.reason
    target='authorized.test'
    if name=='subfinder':
        origin='https://api.hackertarget.com'
        fixtures={origin+'/hostsearch/?q='+target:Response(200,{'content-type':'text/plain'},b'api.authorized.test,192.0.2.1\n')}
        source='hackertarget'
    else:
        origin='https://index.commoncrawl.org'
        year=datetime.datetime.now(datetime.UTC).year
        fixtures={origin+'/collinfo.json':Response(200,{'content-type':'application/json'},json.dumps([
            {'id':f'CC-MAIN-{year}-fixture','cdx-api':origin+'/fixture-index'}]).encode()),
            origin+'/fixture-index?url=*.'+target:Response(200,{'content-type':'text/plain'},b'{"url":"https://authorized.test/historical-api"}\n')}
        source='commoncrawl'
    provider=make_scanner(tmp_path/'provider',origin,fixtures=fixtures)
    provider.config.scope.lab=False
    for url in fixtures:provider.add_url(url,'controlled-provider-fixture')
    config=resolve_selection(default_config('https://'+target),tools=name)
    config.scope.hosts=[target,'*.'+target]
    config.provider_sources[name]=[source]
    config.strict_tools=True
    run,manifest=prepare_run(config,'https://'+target,tmp_path/'scan')
    scanner=Scanner(run,manifest,config,{name:info})
    processes=[]
    async def invoke(argv,cwd,timeout,**kwargs):
        assert argv[0]==info.path and kwargs['expected_sha']==info.sha256
        result,broker=await boundary.run_contained(provider,info,cwd,argv[1:]+['-proxy','http://127.0.0.1:18080'],[])
        processes.append((result,broker.metrics))
        return result
    monkeypatch.setattr(integrations,'execute',invoke)
    try:
        asyncio.run(scanner.collect_passive())
        assert processes and processes[0][0].code==0,[(r.stderr,m) for r,m in processes]
        assert 'RECONMAP_TOOL_STARTED' in processes[0][0].stderr
        assert scanner.store.meta('executed:'+name) is True
        rows=[r for r in scanner.store.rows('observations') if r['source']==name and r['kind']=='provider']
        assert rows,(processes[0][0], [(r['subject'],r['data']) for r in provider.store.rows('observations')])
        stage=scanner.store.conn.execute('SELECT state,detail FROM stages WHERE name=?',(name,)).fetchone()
        assert stage['state']=='completed',(dict(stage),processes[0][0].stderr)
        assert scanner.store.meta('requests',0)==0
        assert provider.store.meta('requests')==len(fixtures)
        if name=='urlfinder':
            assert any(r['kind']=='historical-discovery' for r in scanner.store.rows('observations'))
            assert all(r['status'] is None for r in scanner.store.rows('urls'))
        else:
            assert any(r['host']=='api.authorized.test' for r in scanner.store.rows('hosts'))
    finally:
        provider.store.close();scanner.store.close()
