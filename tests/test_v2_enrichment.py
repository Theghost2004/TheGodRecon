import asyncio
import json
import socket
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from reconmap.config import GroupingSettings, PrioritySettings, default_config
from reconmap.engine import BudgetStop, Response, Scanner, prepare_run
from reconmap.enrichment.asn import enrich_asn, parse_network, parse_organization
from reconmap.enrichment.grouping import group_urls, signature
from reconmap.enrichment.prioritization import prioritize
from reconmap.enrichment.providers import ProviderClient, ProviderResolver, validate_provider_url
from reconmap.enrichment.technology import fingerprint, analyze_captured
from reconmap.enrichment.wayback import collect_wayback, parse_cdx
from reconmap.storage import Store, timestamp


class FakeProvider:
    responses = []
    calls = []
    def __init__(self, scanner): self.scanner = scanner
    async def __aenter__(self): return self
    async def __aexit__(self, *unused): pass
    async def get(self, url):
        self.calls.append(url)
        return self.responses.pop(0), 1000, False


def scanner(tmp_path, mode='passive'):
    config = default_config('example.com'); config.mode = mode
    path, manifest = prepare_run(config, 'example.com', tmp_path)
    return Scanner(path, manifest, config, {})


def cdx(rows, tail=''):
    return json.dumps([['timestamp','original','statuscode','mimetype','digest'], *rows]) + ('\n\n' + tail if tail else '')


def test_wayback_pagination_provenance_and_excluded_scheduling(tmp_path, monkeypatch):
    instance = scanner(tmp_path)
    FakeProvider.calls = []
    FakeProvider.responses = [cdx([
        ['20200101000000','https://example.com/api?a=1','200','text/html','digest-a'],
        ['20210101000000','https://external.test/admin','200','text/html','digest-b'],
    ], 'next-key'), cdx([['20220101000000','https://example.com/account','200','text/html','digest-c']])]
    monkeypatch.setattr('reconmap.enrichment.wayback.ProviderClient', FakeProvider)
    try:
        asyncio.run(collect_wayback(instance))
        rows = instance.store.rows('historical_urls')
        assert len(rows) == 3 and sum(r['allowed'] for r in rows) == 2
        assert {r['archived_at'] for r in rows} == {'20200101000000','20210101000000','20220101000000'}
        assert not instance.store.rows('jobs')  # passive collection never probes
        assert parse_qs(urlsplit(FakeProvider.calls[1]).query)['resumeKey'] == ['next-key']
        assert instance.store.meta('wayback:completed')
        asyncio.run(collect_wayback(instance)); assert len(FakeProvider.calls) == 2
    finally: instance.store.close()


def test_wayback_failures_and_page_caps_are_partial(tmp_path, monkeypatch):
    instance = scanner(tmp_path); instance.config.providers.wayback_pages = 1
    FakeProvider.calls = []; FakeProvider.responses = [cdx([], 'next')]
    monkeypatch.setattr('reconmap.enrichment.wayback.ProviderClient', FakeProvider)
    try:
        asyncio.run(collect_wayback(instance))
        assert next(r for r in instance.store.rows('stages') if r['name'] == 'wayback')['state'] == 'partial'
        FakeProvider.responses = ['{"bad":"shape"}']
        asyncio.run(collect_wayback(instance))
        assert not instance.store.rows('historical_urls')
    finally: instance.store.close()


@pytest.mark.parametrize('text', ['{}', '[["wrong"]]', '[["timestamp","original","statuscode","mimetype","digest"],[null]]', '[[]]'])
def test_malformed_cdx(text):
    with pytest.raises(ValueError): parse_cdx(text)


def test_asn_ipv4_ipv6_evidence_without_scope_expansion(tmp_path, monkeypatch):
    instance = scanner(tmp_path, 'standard')
    for address in ['8.8.8.8','2001:4860:4860::8888','127.0.0.1']:
        instance.store.execute('INSERT INTO dns(host,address,kind,time,source) VALUES(?,?,?,?,?)', ('example.com', address, 'AAAA' if ':' in address else 'A', timestamp(), 'fixture'))
    FakeProvider.calls = []
    FakeProvider.responses = [
        json.dumps({'status':'ok','data':{'prefix':'2001:4860::/32','asns':[15169]}}),
        json.dumps({'status':'ok','data':{'resource':'AS15169','holder':'GOOGLE'}}),
        json.dumps({'status':'ok','data':{'prefix':'8.8.8.0/24','asns':[15169]}}),
    ]
    monkeypatch.setattr('reconmap.enrichment.asn.ProviderClient', FakeProvider)
    try:
        asyncio.run(enrich_asn(instance))
        rows = [r for r in instance.store.rows('infrastructure') if r['source'] == 'ripe-stat']
        assert len(rows) == 2 and {r['asn'] for r in rows} == {'15169'}
        assert len(FakeProvider.calls) == 3  # organization queried once
        assert not instance.store.rows('jobs') and instance.config.scope.hosts == ['example.com']
        assert all(r['provider_hint'] == 'Google Cloud' for r in rows)
        assert all('127.0.0.1' not in url for url in FakeProvider.calls)
    finally: instance.store.close()


def test_asn_unavailable_source_does_not_fabricate_intelligence(tmp_path, monkeypatch):
    instance = scanner(tmp_path, 'standard')
    instance.store.execute('INSERT INTO dns(host,address,kind,time,source) VALUES(?,?,?,?,?)', ('example.com','8.8.8.8','A',timestamp(),'fixture'))
    FakeProvider.calls = []; FakeProvider.responses = ['{"status":"error"}']
    monkeypatch.setattr('reconmap.enrichment.asn.ProviderClient', FakeProvider)
    try:
        asyncio.run(enrich_asn(instance))
        rows = instance.store.rows('infrastructure')
        assert rows and all(r['asn'] == '' and r['source'] == 'native-dns-observation' for r in rows)
        assert next(s for s in instance.store.rows('stages') if s['name'] == 'asn')['state'] == 'partial'
    finally: instance.store.close()


@pytest.mark.parametrize('text,address', [('{"status":"ok","data":{"prefix":"10.0.0.0/8","asns":[1]}}','8.8.8.8'), ('{"status":"ok","data":{"prefix":"8.8.8.0/24","asns":[-1]}}','8.8.8.8'), ('[]','8.8.8.8')])
def test_untrusted_asn_responses(text, address):
    with pytest.raises(ValueError): parse_network(text, address)


def test_technology_no_versions_or_secret_cookie_values(tmp_path):
    store = Store(tmp_path)
    try:
        fingerprint(store,'https://example.com/', {'server':'nginx/9.9.9','set-cookie':'csrftoken=private-cookie-value; Path=/'}, '<input name="csrfmiddlewaretoken"><script src="/_next/static/app.js"></script>', 'a'*64)
        rows = store.rows('technologies')
        assert {r['name'] for r in rows} == {'Django','Next.js','nginx'}
        assert next(r for r in rows if r['name'] == 'Django')['confidence'] == 'high'
        assert all(r['version'] == '' and 'private-cookie-value' not in r['evidence'] for r in rows)
    finally: store.close()


def test_grouping_preserves_cases_ports_methods_and_parameter_multiplicity(tmp_path):
    settings = GroupingSettings()
    a='https://example.com/api/users/123?q=one&q=two'
    b='https://example.com/api/users/456?q=three&q=four'
    assert signature(a,settings,'GET')[0] == signature(b,settings,'GET')[0]
    for other, method in [('https://example.com/API/users/456?q=three&q=four','GET'),('https://example.com:443/api/users/456?q=three&q=four','GET'),('https://example.com/api/users/456?q=one','GET'),(b,'POST')]:
        assert signature(a,settings,'GET')[0] != signature(other,settings,method)[0]
    instance = scanner(tmp_path)
    try:
        for url, source in [(a,'source-a'),(a,'source-b'),(b,'source-a')]: instance.add_url(url,source)
        before = instance.store.rows('urls')
        group_urls(instance.store, settings)
        assert instance.store.rows('urls') == before
        assert len(instance.store.rows('url_groups')) == 1
        assert len(instance.store.rows('url_group_members')) == 3
        assert not instance.store.rows('jobs')
    finally: instance.store.close()


def test_priority_requires_evidence_and_is_configurable(tmp_path):
    instance = scanner(tmp_path)
    try:
        instance.add_url('https://example.com/admin','guessed')
        instance.add_url('https://example.com/api/users','fixture')
        instance.store.execute('UPDATE urls SET status=403,state=? WHERE url=?',('restricted','https://example.com/api/users'))
        prioritize(instance.store, PrioritySettings())
        rows = {r['url']:r for r in instance.store.rows('endpoint_priority')}
        assert rows['https://example.com/admin']['score'] <= 35 and rows['https://example.com/admin']['confidence'] == 'unknown'
        assert rows['https://example.com/api/users']['score'] > rows['https://example.com/admin']['score']
        before = rows['https://example.com/api/users']['score']
        prioritize(instance.store, PrioritySettings(weights={'observed':0}))
        assert next(r for r in instance.store.rows('endpoint_priority') if r['url'].endswith('/api/users'))['score'] < before
    finally: instance.store.close()


@pytest.mark.parametrize('url', ['http://web.archive.org/cdx/search/cdx','https://web.archive.org.evil.test/cdx/search/cdx','https://web.archive.org/web/123','https://user:pass@stat.ripe.net/data/network-info/data.json','https://127.0.0.1/cdx/search/cdx','https://stat.ripe.net:8443/data/network-info/data.json'])
def test_provider_allowlist_rejects_unreviewed_destinations(url):
    with pytest.raises(ValueError): validate_provider_url(url)


def test_provider_resolver_rejects_private_mixed_and_rebound_answers(monkeypatch):
    async def run():
        loop = asyncio.get_running_loop()
        answers = [('8.8.8.8',443)]
        async def resolve(*unused,**kw): return [(socket.AF_INET,socket.SOCK_STREAM,6,'',a) for a in answers]
        monkeypatch.setattr(loop,'getaddrinfo',resolve)
        resolver=ProviderResolver()
        assert (await resolver.resolve('stat.ripe.net'))[0]['host'] == '8.8.8.8'
        answers.append(('127.0.0.1',443))
        with pytest.raises(OSError): await resolver.resolve('stat.ripe.net')
        with pytest.raises(OSError): await resolver.resolve('external.test')
    asyncio.run(run())


def test_provider_owned_budget_and_cache_are_separate_from_targets(tmp_path):
    instance = scanner(tmp_path); instance.config.providers.requests = 1
    calls=[]
    class Body:
        async def iter_chunked(self,size): yield b'fixture metadata'
    class Reply:
        status=200; headers={}; content=Body()
        async def __aenter__(self): return self
        async def __aexit__(self,*unused): pass
    class Session:
        def get(self,url,**kwargs): calls.append((url,kwargs)); return Reply()
    async def run():
        client=ProviderClient(instance); client.session=Session()
        url='https://stat.ripe.net/data/network-info/data.json?resource=8.8.8.8'
        assert (await client.get(url))[2] is False
        assert (await client.get(url))[2] is True
        with pytest.raises(BudgetStop): await client.get(url.replace('8.8.8.8','8.8.4.4'))
    try:
        asyncio.run(run())
        assert len(calls)==1 and calls[0][1]['allow_redirects'] is False
        assert instance.store.meta('provider_requests')==1 and instance.store.meta('requests',0)==0
    finally: instance.store.close()


def test_demo_disables_new_provider_access(tmp_path, monkeypatch):
    instance=scanner(tmp_path,'demo')
    def forbidden(*unused): raise AssertionError('provider client constructed')
    monkeypatch.setattr('reconmap.enrichment.asn.ProviderClient',forbidden)
    monkeypatch.setattr('reconmap.enrichment.wayback.ProviderClient',forbidden)
    try:
        asyncio.run(enrich_asn(instance));asyncio.run(collect_wayback(instance))
        assert all(s['state']=='skipped' for s in instance.store.rows('stages'))
    finally:instance.store.close()


def test_wayback_cancellation_closes_provider_context(tmp_path, monkeypatch):
    instance=scanner(tmp_path)
    closed=[]
    class CancelledProvider:
        def __init__(self,scanner):pass
        async def __aenter__(self):return self
        async def __aexit__(self,*unused):closed.append(True)
        async def get(self,url):raise asyncio.CancelledError()
    monkeypatch.setattr('reconmap.enrichment.wayback.ProviderClient',CancelledProvider)
    try:
        with pytest.raises(asyncio.CancelledError):asyncio.run(collect_wayback(instance))
        assert closed==[True] and not instance.store.rows('historical_urls')
    finally:instance.store.close()


def test_provider_retry_after_stops_before_exceeding_run_time(tmp_path):
    instance=scanner(tmp_path)
    class Reply:
        status=429;headers={'Retry-After':'100000'}
        async def __aenter__(self):return self
        async def __aexit__(self,*unused):pass
    class Session:
        def get(self,*unused,**kwargs):return Reply()
    async def run():
        client=ProviderClient(instance);client.session=Session()
        with pytest.raises(BudgetStop,match='Retry-After'):
            await client.get('https://web.archive.org/cdx/search/cdx?url=example.com')
    try:
        asyncio.run(run())
        assert instance.store.meta('provider_requests')==1
        assert instance.store.meta('requests',0)==0
    finally:instance.store.close()
