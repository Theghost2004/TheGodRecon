import asyncio
import hashlib
import json
from pathlib import Path

import pytest

from reconmap.config import default_config
from reconmap.content_discovery import candidate, dictionary, evidence_candidates, job_key, prepare_hosts, request_cap
from reconmap.coverage import summarize, discovery_rows
from reconmap.engine import Scanner, Response, prepare_run
from reconmap.storage import Store, read_manifest
from reconmap.wordlists import select_lists


def scanner_at(tmp_path, entries='admin\nadmin\nredirect\nlogout\nblocked\nassets/logo.png\n'):
    wordlist=tmp_path/'custom.txt';wordlist.write_text(entries)
    c=default_config('example.com');c.mode='demo';c.modules=['http','crawl','analysis','checks'];c.enrichments=['tech','dedup','priority']
    c.discovery.enabled=True;c.discovery.wordlists=[str(wordlist)];c.discovery.request_budget=5
    c.budgets.requests=100;c.budgets.depth=3;c.scope.exclude_paths=['/blocked']
    path,manifest=prepare_run(c,'example.com',tmp_path/'runs')
    fixtures={
        'https://example.com/':Response(200,{'content-type':'text/html'},b'<title>App</title>'),
        'https://example.com/admin':Response(403,{'content-type':'text/html'},b'Forbidden'),
        'https://example.com/redirect':Response(302,{'location':'https://outside.test/'},b''),
    }
    return Scanner(path,manifest,c,{},fixtures)


def test_end_to_end_candidates_scope_report_and_resume(tmp_path,monkeypatch):
    monkeypatch.setattr('reconmap.wordlists.download',lambda *a:pytest.fail('scan downloaded dictionary'))
    scanner=scanner_at(tmp_path)
    asyncio.run(scanner.run_scan())
    store=Store(scanner.run)
    rows=discovery_rows(store);tested={r['url'] for r in rows if r['tested']}
    assert 'https://example.com/admin' in tested and 'https://example.com/redirect' in tested
    assert not any(r['tested'] for r in rows if any(x in r['url'] for x in ('logout','blocked','logo.png')))
    assert len([r for r in rows if r['url'].endswith('/admin')])==1
    assert all(r['wordlist_hash'] for r in rows)
    coverage=summarize(store)
    assert coverage['crawler']['restricted_responses']==1 and coverage['crawler']['out_of_scope_references']>=2
    assert coverage['crawler']['filtered_static_noise']==1
    assert coverage['discovery']['requests']==2
    assert 'No further eligible' in coverage['crawler']['stop_reason']
    assert not any(f['severity']!='unassessed' for f in store.rows('findings') if f['subject'].endswith('/admin'))
    requests=store.meta('requests');store.close()
    for file in ['coverage.json','wordlist_discoveries.csv','tool_coverage.csv','snapshot.json','index.html']:
        assert (scanner.run/'reports'/file).exists()
    html=(scanner.run/'reports/index.html').read_text()
    assert 'Wordlist Discoveries' in html and 'Content-Security-Policy' in html
    # Snapshot resumes without original user file and never repeats completed jobs.
    Path(scanner.config.discovery.wordlists[0]).unlink()
    resumed=Scanner(scanner.run,read_manifest(scanner.run),scanner.config,{},scanner.fixtures)
    asyncio.run(resumed.run_scan());store=Store(scanner.run)
    assert store.meta('requests')==requests
    assert len(store.meta('wordlists_used'))==1
    store.close()


def test_subbudget_charges_redirects_retries_and_descendants(tmp_path):
    scanner=scanner_at(tmp_path,'retry\nredirect\n')
    scanner.config.discovery.request_budget=2;scanner.config.budgets.retries=1
    scanner.fixtures.update({'https://example.com/retry':Response(503,{},b'later'),
                             'https://example.com/redirect':Response(302,{'location':'/child'},b'')})
    candidate(scanner,'https://example.com/retry','wordlist:test',{},slots=2)
    candidate(scanner,'https://example.com/redirect','wordlist:test',{},slots=1)
    asyncio.run(scanner.crawl())
    assert scanner.store.meta('requests')==scanner.store.meta('wordlist_requests')==2
    jobs={r['url']:r for r in scanner.store.rows('jobs')}
    assert jobs['https://example.com/redirect']['state']=='deferred'
    scanner.store.close()


def test_descendants_cannot_escape_discovery_allocation(tmp_path):
    scanner=scanner_at(tmp_path);scanner.config.discovery.request_budget=1
    scanner.fixtures['https://example.com/probe']=Response(200,{'content-type':'text/html'},b'<a href="/child">child</a><script>fetch("/api/child")</script>')
    candidate(scanner,'https://example.com/probe','wordlist:test',{},slots=1)
    asyncio.run(scanner.crawl())
    jobs={r['url']:r for r in scanner.store.rows('jobs')}
    assert jobs['https://example.com/child']['state']=='deferred'
    assert jobs['https://example.com/api/child']['state']=='deferred'
    assert scanner.store.meta('requests')==1
    scanner.store.close()


def test_interrupted_discovery_resumes_remaining_allocation(tmp_path):
    scanner=scanner_at(tmp_path,'first\nsecond\nthird\n');scanner.config.discovery.request_budget=2
    original=scanner.request
    async def interrupted(url):
        if url.endswith('/second'):raise asyncio.CancelledError()
        return await original(url)
    scanner.request=interrupted
    assert asyncio.run(scanner.run_scan())=='interrupted'
    store=Store(scanner.run);assert store.meta('wordlist_requests')==1;store.close()
    resumed=Scanner(scanner.run,read_manifest(scanner.run),scanner.config,{},scanner.fixtures)
    asyncio.run(resumed.run_scan());store=Store(scanner.run)
    assert store.meta('wordlist_requests')==2
    assert len([r for r in store.rows('observations') if r['kind']=='http' and r['subject'].endswith('/first')])==1
    store.close()


def test_candidate_caps_exact_scope_and_snapshot_integrity(tmp_path):
    scanner=scanner_at(tmp_path);scanner.config.discovery.max_entries=2
    assert candidate(scanner,'https://example.com/admin','wordlist:test',{},slots=5)
    assert not candidate(scanner,'https://sub.example.com/admin','wordlist:test',{},slots=5)
    assert not candidate(scanner,'https://example.com/later','wordlist:test',{},slots=5)
    assert scanner.store.meta('discovery_entry_cap')
    scanner.config.discovery.god_mode=True;prepare_hosts(scanner)
    assert 'Exact-host' in scanner.store.conn.execute("SELECT detail FROM stages WHERE name='wordlist-hosts'").fetchone()[0]
    saved,_=dictionary(scanner,'custom:1',scanner.config.discovery.wordlists[0])
    (scanner.run/saved['snapshot']).write_bytes(b'bad')
    with pytest.raises(ValueError,match='integrity'):dictionary(scanner,'custom:1',scanner.config.discovery.wordlists[0])
    scanner.store.close()


def test_openapi_candidates_get_only_scope_applied_later(tmp_path):
    scanner=scanner_at(tmp_path)
    url='https://example.com/openapi.json';scanner.add_url(url,'fixture')
    document={'openapi':'3.1.0','servers':[{'url':'/api/v1'}],'paths':{'/users':{'get':{}},'/users/{id}':{'get':{}},'/delete':{'post':{}}}}
    scanner.process_response(url,Response(200,{'content-type':'application/json'},json.dumps(document).encode()),0,1)
    values=[url for url,source,meta in evidence_candidates(scanner) if source=='openapi']
    assert values==['https://example.com/api/v1/users']
    scanner.store.close()


def test_selector_uses_current_application_context(tmp_path):
    scanner=scanner_at(tmp_path)
    installed={'available':dict.fromkeys(['common','api','assets'])}
    assert [n for n,_ in select_lists(scanner.store,installed)]==['common']
    scanner.add_url('https://example.com/api/users','historical',fetch=False)
    assert [n for n,_ in select_lists(scanner.store,installed)]==['common']
    scanner.process_response('https://example.com/api/users',Response(200,{'content-type':'application/json'},b'{}'),0,1)
    scanner.save_artifact(b'fetch("/api/users")','js','https://example.com/app.js')
    assert [n for n,_ in select_lists(scanner.store,installed)]==['common','api','assets']
    scanner.store.close()


def test_missing_wordlist_reports_partial_no_download(tmp_path,monkeypatch):
    scanner=scanner_at(tmp_path);scanner.config.discovery.wordlists=[]
    monkeypatch.setattr('reconmap.content_discovery.locate',lambda:{'installed':False,'available':{}})
    asyncio.run(scanner.run_scan());store=Store(scanner.run)
    stage=store.conn.execute("SELECT state,detail FROM stages WHERE name='content-discovery'").fetchone()
    assert stage['state']=='partial' and 'No verified' in stage['detail']
    assert store.meta('wordlist_requests',0)==0;store.close()


def test_html_base_sitemap_index_dtd_and_depth(tmp_path):
    scanner=scanner_at(tmp_path)
    scanner.add_url('https://example.com/start','fixture')
    scanner.process_response('https://example.com/start',Response(200,{'content-type':'text/html'},b'<base href="/app/"><script src="bundle.js"></script><a href="page">p</a>'),0,1)
    jobs={r['url'] for r in scanner.store.rows('jobs')}
    assert {'https://example.com/app/bundle.js','https://example.com/app/page'} <= jobs
    scanner.process_response('https://example.com/sitemap.xml',Response(200,{'content-type':'application/xml'},b'<sitemapindex><sitemap><loc>pages.xml</loc></sitemap></sitemapindex>'),0,1)
    assert scanner.store.conn.execute("SELECT 1 FROM jobs WHERE url='https://example.com/pages.xml'").fetchone()
    scanner.process_response('https://example.com/bad.xml',Response(200,{'content-type':'application/xml'},b'<!DOCTYPE x [<!ENTITY a "https://example.com/bad">]><urlset><url><loc>&a;</loc></url></urlset>'),0,1)
    assert any(r['kind']=='parse_error' for r in scanner.store.rows('observations'))
    scanner.add_url('https://example.com/too-deep','fixture',depth=10)
    assert summarize(scanner.store)['crawler']['depth_limited']==1
    scanner.store.close()


def test_soft404_and_static_asset_are_low_priority(tmp_path):
    scanner=scanner_at(tmp_path,'adminlte.min.css\nghost\n')
    scanner.fixtures['https://example.com/adminlte.min.css']=Response(301,{'content-type':'text/css','location':'/style.css'},b'')
    asyncio.run(scanner.run_scan());store=Store(scanner.run)
    ranked=[json.loads(r['data']) for r in store.rows('investigation_candidates')]
    assert all(c['tier']!='high-interest' for c in ranked if c['url'].endswith(('adminlte.min.css','ghost')))
    assert any(r['kind']=='soft-error-similarity' and r['subject'].endswith('/ghost') for r in store.rows('observations'))
    store.close()


def test_budget_share_is_ceiling_and_zero_allocation(tmp_path):
    scanner=scanner_at(tmp_path);scanner.config.budgets.requests=4
    assert request_cap(scanner.config)==0
    assert not candidate(scanner,'https://example.com/admin','wordlist:test',{},slots=0)
    assert not scanner.store.rows('jobs');scanner.store.close()


def test_god_mode_over_controlled_localhost(tmp_path):
    import threading
    from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
    from reconmap.presets import apply_god_mode
    from reconmap.adapters import ToolInfo
    hits=[]
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            self.send_response(403 if self.path=='/private' else 200)
            self.send_header('Content-Type','text/html');self.end_headers()
            self.wfile.write(b'<title>Local fixture</title>')
        def log_message(self,*args):pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        target=f'http://127.0.0.1:{server.server_port}/'
        config=default_config(target);config.scope.lab=True;config=apply_god_mode(config)
        custom=tmp_path/'local.txt';custom.write_text('private\nlogout\n')
        config.discovery.wordlists=[str(custom)];config.discovery.request_budget=2
        config.budgets.requests=30;config.budgets.overall_rps=config.budgets.per_host_rps=100
        tools={name:ToolInfo(name,None,'missing',None,False,False,'','missing',False) for name in config.selected_tools}
        path,manifest=prepare_run(config,target,tmp_path/'local-runs')
        assert asyncio.run(Scanner(path,manifest,config,tools).run_scan())=='partial'
        store=Store(path);coverage=summarize(store)
        assert store.meta('requests')==len(hits) and coverage['discovery']['requests']==1
        assert '/private' in hits and '/logout' not in hits
        assert store.meta('provider_requests',0)==0
        assert not any(t['actually_ran'] for t in coverage['tools'])
        store.close()
    finally:server.shutdown();server.server_close();thread.join()


def test_dictionary_names_without_observation_stay_out_of_shortlist(tmp_path):
    from reconmap.enrichment.prioritization import prioritize,source_family
    scanner=scanner_at(tmp_path)
    for source in ('wordlist:api','wordlist:custom:1'):
        candidate(scanner,'https://example.com/api/admin/users',source,{},slots=0)
    ranked=prioritize(scanner.store,scanner.config.priority)
    assert ranked and all(r['tier']=='inventory' and r['score']<=5 for r in ranked)
    assert source_family('wordlist:api')==source_family('wordlist:custom:1')
    assert any('Untested dictionary' in reason for r in ranked for reason in r['reasons'])
    scanner.store.close()
