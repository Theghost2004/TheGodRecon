from __future__ import annotations

import json

from reconmap.analysis import PageParser, analyze_js, analyze_map, js_strings, secrets
from reconmap.security import redact
from reconmap.storage import Store, safe_csv


def test_ast_endpoints_methods_unresolved_and_keys():
    text='''fetch('/api/one?x=1&x=2'); fetch('/api/two', {method:'POST',body:{email:user}}); const unknown=`/api/${id}`; const literal='https://external.test/a';'''
    routes,unresolved,keys=js_strings(text)
    assert {r['value'] for r in routes}=={'/api/one?x=1&x=2','/api/two','https://external.test/a'}
    assert next(r for r in routes if r['value']=='/api/two')['method']=='POST'
    assert next(r for r in routes if r['value']=='/api/one?x=1&x=2')['method']=='GET'
    assert unresolved==['`/api/${id}`'] and 'email' in keys


def test_html_forms_inline_comments():
    p=PageParser();p.feed('<title>Hello &amp; Bye</title><script>fetch("/api")</script><script src="/a.js"></script><form method="post" action="/upload"><input name="file"></form><!-- token=secretvalue -->')
    assert p.title=='Hello & Bye'
    assert p.references==[('/a.js','script')]
    assert p.forms==[{'action':'/upload','method':'POST','parameters':['file']}]
    assert p.inline==['fetch("/api")']
    assert p.comments==[' token=secretvalue ']


def test_cached_analysis_preserves_page_relationships(tmp_path):
    store=Store(tmp_path)
    for url in ('https://example.com/a.js','https://example.com/other/a.js'):
        refs=analyze_js(store,'fetch("relative") ; fetch("/api?x=1"); fetch("/post",{method:"POST"})',url,'a'*64)
        assert ('https://example.com/post','inferred_endpoint_non_get') in refs
    assert len([r for r in store.rows('relationships') if r['child']=='https://example.com/api?x=1'])==2
    assert len(store.rows('parameters'))>=1
    store.close()


def test_source_map_no_untrusted_paths_or_external_fetch(tmp_path):
    store=Store(tmp_path)
    text=json.dumps({'version':3,'sources':['../../escape.js','https://external.test/a'],'sourcesContent':['fetch("/api")',None]})
    assert analyze_map(store,text,'https://example.com/app.js.map','b'*64,4096)==[('https://example.com/api','inferred_endpoint')]
    assert not (tmp_path.parent/'escape.js').exists()
    assert {p.name for p in tmp_path.iterdir()} <= {'recon.sqlite','recon.sqlite-wal','recon.sqlite-shm'}
    assert analyze_map(store,text,'https://example.com/app.js.map','b'*64,1)==[]
    assert store.rows('stages')[0]['state']=='partial'
    store.close()


def test_secrets_are_redacted_and_synthetic_not_confirmed(tmp_path):
    secret='ghp_'+'X'*36
    store=Store(tmp_path)
    secrets(store,'const token="'+secret+'"','a'*64,'fixture',synthetic=True)
    records=store.rows('findings')
    assert records and secret not in json.dumps(records)
    assert all(f['validation']=='candidate' and f['severity']=='unassessed' for f in records)
    assert secret not in redact('token="'+secret+'"')
    assert 'supersecret' not in redact('https://example.com/?token=supersecret')
    store.close()


def test_csv_formula_injection():
    for text in ('=1+1','+SUM(A1)','-2+3','@cmd','   =1'):
        assert safe_csv(text).startswith("'")
    assert safe_csv('ordinary')=='ordinary'


def test_dynamic_concatenation_not_invented_and_relative_fetch():
    routes,unresolved,keys=js_strings('fetch("/api/" + userId); fetch("api/relative");')
    assert [r['value'] for r in routes]==['api/relative']
    assert '"/api/" + userId' in unresolved


def test_html_parser_caps_make_incomplete_coverage_visible():
    p=PageParser();p.feed('<form>'+('<input name="item">'*1001)+'</form>')
    assert p.truncated and len(p.forms[0]['parameters'])==1000
