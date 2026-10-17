"""Evidence identity, graph integrity, safe exports and bounded viewer regressions."""
import asyncio
import copy
import json
import shutil
import sqlite3
import subprocess
import time

import pytest

from reconmap.asset_graph import build_graph, export_graph, persist_graph, render_dot, render_tree
from reconmap.asset_map import render_map
from reconmap.config import default_config
from reconmap.engine import Scanner, Response, prepare_run
from reconmap.enrichment.prioritization import prioritize
from reconmap.normalization import normalize_evidence, request_identity
from reconmap.storage import Store, SCHEMA, read_manifest


@pytest.fixture
def scanner(tmp_path):
    config=default_config('example.com');config.mode='demo';config.budgets.depth=4
    run,manifest=prepare_run(config,'example.com',tmp_path)
    instance=Scanner(run,manifest,config,{}, {})
    yield instance
    instance.store.close()


def response(scanner,path,body='',status=200,mime='text/html',**headers):
    url='https://example.com'+path
    scanner.add_url(url,'fixture',fetch=False)
    scanner.process_response(url,Response(status,{'content-type':mime,**headers},body.encode()),0,len(scanner.store.rows('observations'))+1)
    return url


def graph(scanner):
    scanner.correlate();prioritize(scanner.store,scanner.config.priority)
    result=build_graph(scanner.store)
    ids={n['id'] for n in result['nodes']}
    assert all(e['source'] in ids and e['destination'] in ids and e['evidence'] for e in result['edges'])
    assert len(ids)==len(result['nodes'])
    assert len({e['id'] for e in result['edges']})==len(result['edges'])
    return result


def resource(g,url):
    return next(n for n in g['nodes'] if n.get('url')==url and n['type']!='http_request')


def test_observed_script_api_form_and_external_relationships(scanner):
    page=response(scanner,'/dashboard','<script src="/assets/app.js"></script><a href="https://outside.test/login">SSO</a><form method="POST" action="/session"><input name="user"></form>')
    script=response(scanner,'/assets/app.js','fetch("/api/v1/projects");fetch("/api/v1/submit",{method:"POST"});',mime='application/javascript')
    g=graph(scanner);nodes={n['id']:n for n in g['nodes']}
    assert any(e['type']=='loads_script' and nodes[e['source']].get('url')==page and nodes[e['destination']].get('url')==script for e in g['edges'])
    assert any(e['type']=='references_api' and nodes[e['source']].get('url')==script and nodes[e['destination']].get('url')=='https://example.com/api/v1/projects' and e['semantics']=='statically-inferred' for e in g['edges'])
    assert any(ref.get('hash') for e in g['edges'] if e['type']=='loads_script' for ref in e['evidence'])
    api=resource(g,'https://example.com/api/v1/projects')
    assert api['type']=='api_endpoint' and 'live-observed' not in api['states']
    outside=resource(g,'https://outside.test/login')
    assert outside['type']=='external_reference' and 'html-linked' in outside['states']
    assert any(e['type']=='submits_to' for e in g['edges'])
    assert any(n['type']=='parameter' and n['label']=='user (form)' for n in g['nodes'])
    assert not any('outside.test' in r['url'] for r in scanner.store.rows('jobs'))


def test_prefix_groups_are_structural_not_fabricated_observations(scanner):
    response(scanner,'/api/v1/projects','[]',mime='application/json')
    g=graph(scanner)
    assert not any(n.get('url') in {'https://example.com/api/','https://example.com/api/v1/'} for n in g['nodes'])
    groups={n['label']:n for n in g['nodes'] if n['type']=='path_group'}
    assert groups['/api/']['states']==['structural-only']
    assert groups['/api/v1/']['states']==['structural-only']
    assert all(e['semantics']=='structural' for e in g['edges'] if e['type']=='contains_path')
    tree=render_tree(g)
    assert '/api/v1/' in tree and 'structural' in tree


def test_method_context_case_port_query_identity_and_shared_provenance(scanner):
    urls=['https://example.com/api/Users?a=1&a=2','https://example.com/api/users?a=1&a=2',
          'https://example.com/api/Users?a=2&a=1','https://example.com:443/api/Users?a=1&a=2']
    for url in urls:
        for source in ('jsluice','urlfinder'):scanner.add_url(url,source,fetch=False)
        for method,context in [('GET','role-a'),('POST','role-a'),('GET','role-b')]:
            scanner.store.observed(url,'inferred_endpoint',{'method':method,'authorization_context':context},'fixture')
    g=graph(scanner);requests=[n for n in g['nodes'] if n['type']=='http_request']
    assert len(requests)==12
    assert all(len(n['parameters'])==2 and n['status'] is None for n in requests)
    assert all({'jsluice','urlfinder'} <= set(n['sources']) for n in requests)
    assert len({n['id'] for n in requests})==12
    assert build_graph(scanner.store)==g


def test_historical_identity_remains_stable_when_observed(scanner):
    url='https://example.com/api/legacy'
    scanner.add_url(url,'urlfinder',fetch=False)
    scanner.store.observed(url,'historical-discovery',{'archive_status':200},'urlfinder')
    before=graph(scanner);old=resource(before,url)
    assert old['states']==['historical']
    assert all(n.get('status') is None for n in before['nodes'])
    response(scanner,'/api/legacy','[]',mime='application/json')
    current=resource(graph(scanner),url)
    assert current['id']==old['id'] and {'live-observed','historical'} <= set(current['states'])


def test_redirect_cycles_and_shared_scripts_do_not_duplicate_nodes(scanner):
    a=response(scanner,'/a','',302,location='/b')
    b=response(scanner,'/b','',302,location='/a')
    response(scanner,'/one','<script src="/shared.js"></script>')
    response(scanner,'/two','<script src="/shared.js"></script>')
    script=response(scanner,'/shared.js','fetch("/api/current");',mime='application/javascript')
    g=graph(scanner);nodes={n['id']:n for n in g['nodes']}
    scripts=[n for n in g['nodes'] if n['type']=='javascript_resource' and n.get('url')==script]
    assert len(scripts)==1
    assert len([e for e in g['edges'] if e['type']=='loads_script' and e['destination']==scripts[0]['id']])==2
    pairs={(nodes[e['source']].get('url'),nodes[e['destination']].get('url')) for e in g['edges'] if e['type']=='redirects_to'}
    assert {(a,b),(b,a)} <= pairs
    assert len(render_tree(g))<10000


def test_same_body_distinct_urls_keep_artifact_and_source_edges(scanner):
    a=response(scanner,'/a.js','fetch("/api/user")',mime='application/javascript')
    b=response(scanner,'/b.js','fetch("/api/user")',mime='application/javascript')
    g=graph(scanner);artifacts=[n for n in g['nodes'] if n['type']=='artifact']
    assert len(artifacts)==1
    nodes={n['id']:n for n in g['nodes']}
    assert {nodes[e['source']].get('url') for e in g['edges'] if e['type']=='references_api' and nodes[e['source']].get('url')}=={a,b}


def test_out_of_scope_redirect_is_unobserved_and_not_requested(scanner):
    response(scanner,'/redirect','',302,location='https://elsewhere.test/admin')
    g=graph(scanner);dest=resource(g,'https://elsewhere.test/admin')
    assert dest['type']=='external_reference' and 'redirect-destination' in dest['states']
    assert 'live-observed' not in dest['states']
    assert any(e['type']=='redirects_to' and e['destination']==dest['id'] for e in g['edges'])
    assert not any('elsewhere' in r['url'] for r in scanner.store.rows('jobs'))


def test_exposure_uses_existing_ranking_and_analyst_decisions(scanner):
    url=response(scanner,'/.git/HEAD','ref: refs/heads/main\n',mime='text/plain')
    response(scanner,'/assets/css/adminlte.min.css','body{}',mime='text/css')
    g=graph(scanner)
    findings=[n for n in g['nodes'] if n['type']=='exposure_candidate']
    assert any('source-control' in n['label'] for n in findings)
    assert all(n['severity']=='unassessed' for n in findings)
    css=next(n for n in g['nodes'] if n['type']=='http_request' and n['url'].endswith('adminlte.min.css'))
    assert css['review_priority']=='Low'
    assert any(n.get('url')==url and n['type']=='http_request' and n['classification']=='potential-exposure' for n in g['nodes'])


def test_json_dot_html_and_sqlite_are_consistent_safe_exports(scanner,tmp_path):
    unicode_paths=('/dashboard/überblick','/api/café','/हिन्दी')
    page=response(scanner,unicode_paths[0],'<a href="/api/café">café</a><a href="/हिन्दी">हिन्दी</a>')
    for path in unicode_paths[1:]:
        response(scanner,path,'<title>überblick — café — हिन्दी</title>')
    response(scanner,'/x?value=%22%3E%3Cscript%3E','<title>&lt;img src=x onerror=alert(1)&gt;</title>')
    scanner.add_url('https://example.com/x','</script><img src=x onerror=alert(1)>',fetch=False)
    scanner.store.observed('https://example.com/x','discovery',{'parent':'https://example.com/'},'</script><img src=x onerror=alert(1)>')
    expected=graph(scanner)
    summary=export_graph(scanner.run,scanner.store)
    exported=json.loads((scanner.run/'graph/asset-graph.json').read_text(encoding='utf-8'))
    assert summary==exported['summary']
    assert summary==json.loads((scanner.run/'graph/graph-summary.json').read_text(encoding='utf-8'))
    assert exported['edges']==expected['edges']
    nodes={n['id']:n for n in exported['nodes']}
    linked={nodes[e['destination']].get('url') for e in exported['edges']
            if e['type']=='links_to' and nodes[e['source']].get('url')==page}
    assert {'https://example.com'+path for path in unicode_paths[1:]} <= linked
    for path in unicode_paths:
        assert resource(exported,'https://example.com'+path)==resource(expected,'https://example.com'+path)
    assert len(scanner.store.rows('graph_nodes'))==summary['nodes']
    assert len(scanner.store.rows('graph_edges'))==summary['edges']
    html=(scanner.run/'graph/asset-map.html').read_text(encoding='utf-8')
    payload=html.split('<script id="graph-data" type="application/json">',1)[1].split('</script>',1)[0]
    assert json.loads(payload)==exported
    assert "connect-src 'none'" in html and "script-src 'sha256-" in html
    assert '</script><img' not in html and '\\u003c/script\\u003e' in html
    assert 'innerHTML' not in html and 'fetch(' not in html
    assert 'Previous relationships' in html and 'pageSize=60' in html
    dot=scanner.run/'graph/asset-graph.dot'
    dot_text=dot.read_text(encoding='utf-8')
    tree=(scanner.run/'graph/endpoint-tree.txt').read_text(encoding='utf-8')
    assert all(path in dot_text and path in tree for path in unicode_paths)
    assert dot_text.startswith('digraph TheGodRecon {')
    if shutil.which('dot'):
        subprocess.run(['dot','-Tdot',str(dot),'-o',str(tmp_path/'parsed.dot')],check=True,capture_output=True,timeout=20)


def test_large_graph_paginates_and_prefix_depth_is_bounded(scanner):
    response(scanner,'/api/0','[]',mime='application/json')
    template=normalize_evidence(scanner.store)[0]
    records=[]
    for number in range(2000):
        r=copy.deepcopy(template);r['url']=f'https://example.com/api/v1/items/{number}?page={number}'
        r['identity']=request_identity(r['url'],'GET');r['query_pairs']=[('page',str(number))]
        records.append(r)
    start=time.monotonic();g=build_graph(scanner.store,records,[])
    assert g['summary']['urls']==2000 and time.monotonic()-start<15
    page=render_map(g)
    assert page.count('id="results"')==1 and 'slice(page*pageSize' in page
    r=copy.deepcopy(template);r['url']='https://example.com/'+'a/'*1000+'end';r['identity']=request_identity(r['url'],'GET')
    deep=build_graph(scanner.store,[r],[])
    assert len([n for n in deep['nodes'] if n['type']=='path_group'])<=64
    assert r['url'] in render_tree(deep)


def test_schema3_readonly_and_graph_migration_preserve_old_evidence(tmp_path):
    from reconmap.storage import DDL
    from reconmap.schema_v2 import DDL as V2
    from reconmap.schema_v3 import DDL as V3
    with sqlite3.connect(tmp_path/'recon.sqlite') as db:
        db.executescript(DDL+V2+V3);db.execute('PRAGMA user_version=3')
        db.execute('INSERT INTO analyst_actions(fingerprint,status,note,time) VALUES(?,?,?,?)',('old','dismissed','retain','2020'))
    before=(tmp_path/'recon.sqlite').read_bytes();old=Store(tmp_path,readonly=True)
    assert old.rows('graph_nodes')==[];old.close()
    assert (tmp_path/'recon.sqlite').read_bytes()==before
    store=Store(tmp_path)
    assert store.schema==SCHEMA and store.rows('analyst_actions')[0]['note']=='retain'
    assert store.rows('graph_nodes')==[];store.close()


def test_interruption_preserves_graph_and_resume_reuses_requests(tmp_path):
    config=default_config('example.com');config.mode='demo'
    run,manifest=prepare_run(config,'example.com',tmp_path)
    fixtures={'https://example.com/':Response(200,{'content-type':'text/html'},b'<a href="/second">next</a>')}
    scanner=Scanner(run,manifest,config,{},fixtures);original=scanner.request
    async def interrupt(url):
        if url.endswith('/second'):raise asyncio.CancelledError()
        return await original(url)
    scanner.request=interrupt
    assert asyncio.run(scanner.run_scan())=='interrupted'
    assert (run/'graph/asset-map.html').exists()
    resumed=Scanner(run,read_manifest(run),config,{},fixtures)
    asyncio.run(resumed.run_scan());store=Store(run)
    assert len([o for o in store.rows('observations') if o['kind']=='http' and o['subject']=='https://example.com/'])==1
    assert store.rows('graph_nodes');store.close()


def test_html_escaping_malicious_dot_labels_and_graph_symlink_refusal(scanner,tmp_path):
    response(scanner,'/x','<title>Fixture</title>')
    g=graph(scanner)
    g['nodes'][0]['label']='"; x -> y; // </script><img src=https://bad.test onerror=alert(1)>'
    page=render_map(g)
    assert '</script><img' not in page
    dot=tmp_path/'hostile.dot';dot.write_text(render_dot(g),encoding='utf-8')
    if shutil.which('dot'):
        subprocess.run(['dot','-Tdot',str(dot),'-o',str(tmp_path/'safe.dot')],check=True,capture_output=True,timeout=10)
    scanner.manifest['state']='partial'
    from reconmap.storage import atomic_json
    atomic_json(scanner.run/'manifest.json',scanner.manifest)
    outside=tmp_path/'outside';outside.mkdir()
    try:(scanner.run/'graph').symlink_to(outside,target_is_directory=True)
    except OSError:pytest.skip('Platform does not allow symlink fixtures')
    from reconmap.reporting import generate_report
    with pytest.raises(ValueError,match='link'):generate_report(scanner.run,scanner.store)
    assert list(outside.iterdir())==[]


def test_subdomains_group_only_under_observed_parent(scanner):
    scanner.add_url('https://example.com/','seed',fetch=False)
    scanner.add_url('https://api.example.com/v1/users','html-link',fetch=False)
    scanner.add_url('https://unrelated.test/','html-link',fetch=False)
    g=graph(scanner);nodes={n['id']:n for n in g['nodes']}
    edges=[e for e in g['edges'] if e['type']=='contains_host']
    assert len(edges)==1
    assert nodes[edges[0]['source']]['label']=='example.com'
    assert nodes[edges[0]['destination']]['label']=='api.example.com'
    assert 'api.example.com [subdomain' in render_tree(g)
    assert not any(n['label']=='test' for n in g['nodes'])
