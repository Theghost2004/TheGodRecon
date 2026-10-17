"""BlackBox and explicit normal selections use one engine without scope widening."""
import asyncio
import hashlib
import json
from pathlib import Path

import pytest
import yaml

from reconmap.cli import effective_config, main, parser
from reconmap.config import default_config, ScanConfig, ConfigError
from reconmap.coverage import summarize
from reconmap.engine import Scanner, Response, prepare_run
from reconmap.selectors import resolve_selection
from reconmap.storage import Store, read_manifest
from reconmap.tool_registry import BY_NAME


def config(command='blackbox', *args):
    return effective_config(parser().parse_args([command,'example.com',*args]))


def test_canonical_and_aliases_share_one_profile():
    chosen=config()
    assert chosen.workflow=='blackbox' and chosen.graph
    assert chosen.selected_tools==list(BY_NAME)
    assert chosen.discovery.enabled and chosen.enrichments
    assert chosen.scope==default_config('example.com').scope
    for alias in ('--god-mode','--full-coverage'):
        assert config('scan',alias)==chosen
    assert config('scan','--all-tool').selected_tools==chosen.selected_tools
    assert not config('scan','--all-tool').discovery.enabled
    assert config('scan','--deep').budgets.depth==4


@pytest.mark.parametrize('options', [('--tools','1'),('--exclude-tools','8'),('--no-graph',),('--mode','offline'),('--formats','json')])
def test_blackbox_rejects_incomplete_profile(options):
    with pytest.raises(ValueError): config('blackbox',*options)


def test_custom_selection_exclusions_and_prerequisites():
    chosen=config('scan','--tools','subfinder,httpx,katana','--exclude-tools','1')
    assert chosen.selected_tools==['httpx','katana']
    assert not {'analysis','checks','dns'} & set(chosen.modules)
    assert config('scan','--exclude-tools','7,8').selected_tools==list(BY_NAME)[:6]
    assert config('scan','--tools','all','--exclude-tools','all').modules==[]
    assert 'http' not in config('scan','--tools','katana').modules
    assert 'checks' not in config('scan','--tools','nuclei').modules


def test_manual_wordlists_replace_yaml_and_exclusions(tmp_path):
    first=tmp_path/'first.txt';first.write_text('admin\n')
    second=tmp_path/'second.txt';second.write_text('api\n')
    c=default_config('example.com');c.discovery.wordlists=[str(first)]
    source=tmp_path/'scope.yaml';source.write_text(yaml.safe_dump(c.model_dump()))
    chosen=config('scan','--config',str(source),'--wordlist',str(second),'--exclude-wordlist','common')
    assert chosen.discovery.wordlists==[str(second)] and chosen.discovery.enabled
    assert chosen.discovery.exclude_wordlists==['common']
    assert config('scan','--auto-wordlists').discovery.enabled


def test_safe_tool_options_and_format_configuration():
    c=config('scan','--engine','jsluice=native','--provider-source','subfinder=hackertarget','--formats','json,csv')
    assert c.execution_engines=={'jsluice':'native'}
    assert c.provider_sources['subfinder']==['hackertarget']
    assert c.report_formats==['json','csv']
    with pytest.raises(ValueError):config('scan','--provider-source','subfinder=unreviewed')
    with pytest.raises(ValueError):config('scan','--engine','httpx=unsafe')


def test_old_nondefault_god_config_digest_preserved():
    c=default_config('example.com');c.discovery.enabled=True;c.discovery.god_mode=True
    old=c.model_dump()
    for key in ('workflow','graph','execution_engines','report_formats'):old.pop(key)
    old['discovery'].pop('exclude_wordlists')
    assert c.digest()==hashlib.sha256(json.dumps(old,sort_keys=True).encode()).hexdigest()


@pytest.mark.parametrize('selected,forbidden', [('jsluice','secret'),('gitleaks','inferred_endpoint')])
def test_local_selected_capability_never_runs_other_analysis(tmp_path, selected, forbidden):
    path=tmp_path/'app.js';path.write_text('fetch("/api/users"); const key="AKIAEXAMPLE0000000000";')
    c=resolve_selection(default_config('example.com'),tools=selected,mode='offline')
    c.local_inputs=[str(path)];c.execution_engines[selected]='native'
    source=tmp_path/'scope.yml';source.write_text(yaml.safe_dump(c.model_dump()))
    assert main(['scan','example.com','--config',str(source),'--output-root',str(tmp_path/'runs'),'--no-progress']) in {0,2}
    store=Store(tmp_path/'runs/example.com')
    try:
        if forbidden=='secret':assert not [r for r in store.rows('findings') if r['subject'].startswith('artifact:')]
        else:assert not [r for r in store.rows('observations') if r['kind']==forbidden]
        coverage=summarize(store)
        assert {t['tool'] for t in coverage['tools'] if t['selected']}=={selected}
        row=next(t for t in coverage['tools'] if t['tool']==selected)
        assert row['engines']==['native-tree-sitter' if selected=='jsluice' else 'native-secret-patterns']
        assert not row['actually_ran'] and row['installed'] is None
    finally:store.close()


def test_native_preference_never_identifies_executable(monkeypatch):
    from reconmap.cli import identify_selected
    monkeypatch.setattr('reconmap.cli.identify',lambda *a:pytest.fail('executed native-selected binary'))
    c=config('scan','--tools','6','--engine','jsluice=native')
    assert not identify_selected(c,'jsluice').supported


@pytest.mark.parametrize('tool',['katana','nuclei'])
def test_missing_prerequisite_is_partial_without_http(tmp_path,tool):
    assert main(['scan','example.com','--mode','demo','--tools',tool,'--engine',tool+'=native','--output-root',str(tmp_path/'runs'),'--no-progress'])==2
    data=json.loads((tmp_path/'runs/example.com/reports/coverage.json').read_text())
    assert data['crawler']['http_responses']==0
    row=next(t for t in data['tools'] if t['tool']==tool)
    assert row['engines']==[] and 'prerequisite' in row['reason']


def test_blackbox_partial_exports_resume_collision_and_json_formats(tmp_path):
    args=['blackbox','example.com','--mode','demo','--max-requests','1','--output-root',str(tmp_path/'runs'),'--no-progress']
    for tool in BY_NAME:args.extend(['--engine',tool+'=native'])
    assert main(args)==2
    run=tmp_path/'runs/example.com'
    for file in ('endpoint-tree.txt','asset-graph.json','asset-graph.dot','graph-summary.json','asset-map.html'):
        assert (run/'graph'/file).is_file()
    assert 'endpoint relationship map' in (run/'reports/index.html').read_text()
    before=json.loads((run/'graph/asset-graph.json').read_text())
    assert main(['resume',str(run),'--no-progress'])==2
    after=json.loads((run/'graph/asset-graph.json').read_text())
    assert {n['id'] for n in before['nodes']}=={n['id'] for n in after['nodes']}
    assert read_manifest(run)['requests']==1
    assert main(args)==2 and (tmp_path/'runs/1_example.com/graph/asset-map.html').exists()
    assert main(['scan','example.com','--mode','demo','--tools','4','--engine','httpx=native','--formats','json','--no-graph','--output-root',str(tmp_path/'json'),'--no-progress']) in {0,2}
    assert not (tmp_path/'json/example.com/reports/index.html').exists()
    assert not (tmp_path/'json/example.com/graph').exists()
    assert (tmp_path/'json/example.com/reports/investigation.json').exists()


def test_environment_preflight_is_readonly_and_informational(monkeypatch):
    from reconmap.environment import diagnostics
    monkeypatch.setattr('reconmap.environment.platform.system',lambda:'Windows')
    data=diagnostics()
    assert data['linux_effective_capabilities_hex'] is None
    assert 'No verified' in data['network_controls']['external_active']
    assert 'No privilege elevation' in data['note']


def test_manual_dictionary_precedence_and_exclusion_during_execution(tmp_path,monkeypatch):
    from reconmap.content_discovery import run as discover
    wordlist=tmp_path/'manual.txt';wordlist.write_text('manual\nmanual\n')
    c=default_config('example.com');c.mode='demo';c.modules=['http']
    c.discovery.enabled=True;c.discovery.wordlists=[str(wordlist)]
    path,manifest=prepare_run(c,'example.com',tmp_path/'runs')
    scanner=Scanner(path,manifest,c,{}, {})
    monkeypatch.setattr('reconmap.content_discovery.select_lists',lambda *a:pytest.fail('automatic lists override manual selection'))
    scanner.add_url(manifest['target'],'seed',fetch=False)
    asyncio.run(discover(scanner))
    assert [r['name'] for r in scanner.store.meta('wordlists_used')]==['custom:1']
    entries=[json.loads(r['data']) for r in scanner.store.rows('observations') if r['kind']=='content-candidate']
    assert len(entries)==1 and entries[0]['entry']=='manual'
    scanner.store.close()
    c.discovery.exclude_wordlists=[str(wordlist)]
    path,manifest=prepare_run(c,'example.com',tmp_path/'runs')
    scanner=Scanner(path,manifest,c,{}, {})
    asyncio.run(discover(scanner))
    assert not scanner.store.meta('wordlists_used',[])
    scanner.store.close()


def test_http_selection_uses_transport_resolver_without_dns_enumerator(tmp_path,monkeypatch):
    from reconmap.cli import identify_selected
    from reconmap.orchestrator import run_pipeline
    c=resolve_selection(default_config('example.com'),tools='httpx')
    c.execution_engines={'httpx':'native'}
    path,manifest=prepare_run(c,'example.com',tmp_path)
    scanner=Scanner(path,manifest,c,{'httpx':identify_selected(c,'httpx')},{'https://example.com/':Response(200,{},b'fixture')})
    monkeypatch.setattr('reconmap.dnschecks.observe_dns',lambda *a:pytest.fail('unselected DNS enumeration'))
    asyncio.run(run_pipeline(scanner))
    assert not any(r['name']=='dns-enumeration' for r in scanner.store.rows('stage_results'))
    assert scanner.store.meta('requests')==1
    scanner.store.close()


def test_exclusions_preserve_yaml_native_intent(tmp_path):
    c=default_config('example.com');source=tmp_path/'scope.yml'
    source.write_text(yaml.safe_dump(c.model_dump()))
    chosen=config('scan','--config',str(source),'--exclude-tools','7,8')
    assert chosen.selected_tools==['httpx','katana','jsluice']
    assert all(chosen.execution_engines[n]=='native' for n in chosen.selected_tools)
    without_http=config('scan','--tools','4,5','--exclude-tools','4')
    assert 'http' not in without_http.modules and 'crawl' not in without_http.modules
