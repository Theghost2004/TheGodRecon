"""Evidence-first candidates feeding the existing scope policy and HTTP queue."""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

from .config import request_url
from .orchestrator import record_execution
from .storage import artifact_path
from .wordlists import CATALOG, load_dictionary, locate, select_lists, selected_entries, read_file, safe_path


def job_key(url):
    return 'discovery-job:' + hashlib.sha256(request_url(url).encode()).hexdigest()


def request_cap(config):
    return min(config.discovery.request_budget, config.budgets.requests // 5)


def dictionary(scanner, name, path, expected=None, task='content', reason='custom local dictionary'):
    """Snapshot selected input; resume uses the verified copy, never a changed file."""
    identity = hashlib.sha256((name+'\0'+str(path)).encode()).hexdigest()
    key = 'wordlist-input:' + identity
    saved = scanner.store.meta(key)
    if saved:
        relative = saved['snapshot']
        if not re.fullmatch(r'raw/wordlists/[0-9a-f]{64}\.txt', relative):
            raise ValueError('Invalid wordlist snapshot path')
        loaded = load_dictionary(scanner.run/relative, 100000, task, {'sha256': saved['sha256'], 'bytes': saved['bytes']})
        return saved, loaded['entries']
    loaded = load_dictionary(Path(path), 100000, task, expected)
    scanner.check_disk_budget(loaded['bytes'])
    relative = 'raw/wordlists/' + loaded['sha256'] + '.txt'
    target = safe_path(scanner.run/relative)
    target.parent.mkdir(exist_ok=True)
    if not target.exists():
        with target.open('xb') as stream: stream.write(loaded['data'])
    else:
        read_file(target, loaded)
    saved = {k:v for k,v in loaded.items() if k not in {'data','entries'}}
    saved.update(name=name, snapshot=relative, reason=reason,
                 revision=CATALOG['revision'] if expected else 'custom', confidence='low; dictionary candidate only')
    scanner.store.set_meta(key, saved)
    used = scanner.store.meta('wordlists_used', [])
    if not any(r['name'] == name and r['sha256'] == saved['sha256'] for r in used):
        used.append(saved); scanner.store.set_meta('wordlists_used', used)
    return saved, loaded['entries']


def mark_job(scanner, url):
    if not scanner.store.conn.execute('SELECT 1 FROM jobs WHERE url=?', (request_url(url),)).fetchone():
        scanner.store.set_meta(job_key(url), True)


def candidate(scanner, url, source, provenance, *, depth=1, slots=0):
    """Record a proposal independently of whether it can enter the request queue."""
    try:
        url = request_url(url)
    except ValueError:
        return False
    depth = provenance.get('depth', depth)
    allowed, why = scanner.policy.decision(url)
    existing = scanner.store.conn.execute('SELECT state FROM jobs WHERE url=?', (url,)).fetchone()
    tested = scanner.store.conn.execute("SELECT 1 FROM observations WHERE kind='http' AND subject=? AND source NOT LIKE 'parent:%'", (url,)).fetchone()
    reason = 'already tested' if tested else 'already scheduled' if existing else why if not allowed else 'discovery allocation exhausted' if slots <= 0 else 'eligible'
    identity = 'content-candidate:' + hashlib.sha256((url+'\0'+source+'\0'+provenance.get('sha256','')).encode()).hexdigest()
    if not scanner.store.conn.execute('SELECT 1 FROM observations WHERE identity=?', (identity,)).fetchone():
        count = scanner.store.conn.execute("SELECT COUNT(*) FROM observations WHERE kind='content-candidate'").fetchone()[0]
        if count >= scanner.config.discovery.max_entries:
            scanner.store.set_meta('discovery_entry_cap', True)
            return False
        scanner.store.observed(url, 'content-candidate', {**provenance, 'method':'GET', 'candidate_state':'untested proposal',
            'confidence': provenance.get('confidence','low'), 'selection_reason':reason, 'depth':depth}, source, identity=identity)
    if reason == 'eligible':
        mark_job(scanner, url)
    scanner.add_url(url, source, provenance.get('parent',''), depth=depth, fetch=reason == 'eligible')
    if reason == 'eligible':
        job = scanner.store.conn.execute('SELECT state FROM jobs WHERE url=?', (url,)).fetchone()
        return bool(job and job[0] == 'queued')
    return False


def origins(scanner):
    # Observed, in-scope origins only; never turn a historical hostname into
    # authorization for all schemes or ports.
    values = {urlunsplit(urlsplit(scanner.manifest['target'])._replace(path='/',query='',fragment=''))}
    for row in scanner.store.rows('urls'):
        if row['status'] is not None and scanner.policy.decision(row['url'])[0]:
            values.add(urlunsplit(urlsplit(row['url'])._replace(path='/',query='',fragment='')))
    return sorted(values)[:20]


def evidence_candidates(scanner):
    seen = set()
    count = 0
    for row in scanner.store.conn.execute("SELECT subject,kind,data,source FROM observations WHERE kind IN ('inferred_endpoint','historical-discovery') ORDER BY id"):
        data = json.loads(row['data'])
        if row['kind'] == 'inferred_endpoint' and data.get('method') != 'GET':
            continue
        if row['subject'] not in seen:
            seen.add(row['subject']); count += 1
            depth = 1
            if row['kind'] == 'inferred_endpoint' and data.get('hash'):
                depths = [r[0] for r in scanner.store.conn.execute("SELECT j.depth FROM jobs j JOIN relationships r ON j.url=r.parent WHERE r.child=? AND r.kind='response_body'", ('artifact:'+data['hash'],))]
                depth = min(depths, default=0)+1
            yield row['subject'], row['source'], {'parent':row['subject'],'evidence_kind':row['kind'],'depth':depth,'confidence':'medium' if row['kind']=='inferred_endpoint' else 'low'}
            if count >= scanner.config.discovery.max_entries: return
    for row in scanner.store.rows('urls'):
        if not row['hash'] or row['status'] != 200 or row['content_type'] not in {'application/json','text/json'}:
            continue
        artifact = scanner.store.conn.execute('SELECT path FROM artifacts WHERE hash=?', (row['hash'],)).fetchone()
        if not artifact: continue
        path = artifact_path(scanner.run, artifact[0])
        with path.open('rb') as stream: body = stream.read(scanner.config.budgets.response_bytes+1)
        if len(body)>scanner.config.budgets.response_bytes or hashlib.sha256(body).hexdigest()!=row['hash']:
            raise ValueError('Captured API document integrity mismatch')
        try: document=json.loads(body)
        except (ValueError, UnicodeError): continue
        if not isinstance(document,dict) or not (document.get('openapi') or document.get('swagger')) or not isinstance(document.get('paths'),dict):
            continue
        origin = urlunsplit(urlsplit(row['url'])._replace(path='/', query='', fragment=''))
        base = urljoin(origin,str(document.get('basePath','')).rstrip('/')+'/')
        servers=document.get('servers')
        if isinstance(servers,list) and servers and isinstance(servers[0],dict) and isinstance(servers[0].get('url'),str):
            base=urljoin(row['url'],servers[0]['url'].rstrip('/')+'/')
        for route, methods in list(document['paths'].items())[:scanner.config.discovery.max_entries]:
            if not isinstance(route,str) or not route.startswith('/') or any(c in route for c in '{}') or not isinstance(methods,dict) or 'get' not in methods:
                continue
            url=urljoin(base,route.lstrip('/'))
            if url in seen: continue
            seen.add(url); count+=1
            yield url, 'openapi', {'parent':row['url'],'evidence_kind':'captured OpenAPI GET path','depth':row['depth']+1,'sha256':row['hash'],'confidence':'medium'}
            if count>=scanner.config.discovery.max_entries:return
    # Small API documentation candidates derived from actual path prefixes;
    # no combinatorial products of arbitrary JavaScript strings.
    prefixes=set()
    for row in scanner.store.rows('urls'):
        match=re.match(r'(.*/api(?:/v[0-9]+)?)/',row['url'])
        if match and (row['status'] is not None or row['source'] in {'jsluice','inferred_endpoint'}):
            prefixes.add(match[1])
    for prefix in sorted(prefixes)[:5]:
        for suffix in ('openapi.json','swagger.json'):
            yield prefix+'/'+suffix, 'observed-api-prefix', {'parent':prefix,'evidence_kind':'API prefix supplement','confidence':'low'}


def prepare_hosts(scanner):
    if not scanner.config.discovery.god_mode:
        return
    target=urlsplit(scanner.manifest['target'])
    patterns=[p[2:] for p in scanner.config.scope.hosts if p.startswith('*.') and (target.hostname==p[2:] or target.hostname.endswith('.'+p[2:]))]
    if not patterns:
        scanner.store.stage('wordlist-hosts','skipped','Exact-host scope: no dictionary subdomains authorized')
        return
    if scanner.config.discovery.wordlists or 'dns' in scanner.config.discovery.exclude_wordlists:
        scanner.store.stage('wordlist-hosts','skipped','Explicit dictionaries/exclusions take precedence over automatic DNS list selection')
        return
    installed=locate()
    if not installed['installed']:
        scanner.store.stage('wordlist-hosts','skipped','Verified DNS dictionary unavailable; no scope expansion')
        return
    spec=installed['available']['dns']
    source,entries=dictionary(scanner,'dns',spec['location'],spec,'dns','explicit wildcard scope only')
    cap=min(20,scanner.config.budgets.dns_queries//4,request_cap(scanner.config)//2,scanner.config.discovery.max_entries)
    offered=0
    for entry in entries:
        for suffix in patterns:
            host=entry+'.'+suffix
            netloc=host+(':'+str(target.port) if target.port else '')
            url=urlunsplit(target._replace(netloc=netloc))
            if not scanner.policy.decision(url)[0]: continue
            if offered>=cap:break
            candidate(scanner,url,'wordlist:dns',source,slots=cap-offered)
            offered+=1
        if offered>=cap:break
    scanner.store.stage('wordlist-hosts','completed',f'{offered} scoped hostname proposals; native DNS/HTTP retain their budgets and destination checks')


async def run(scanner):
    if not scanner.config.discovery.enabled:
        return
    started=time.monotonic()
    scanner.store.stage('content-discovery','running','Evidence before curated dictionary guesses; shared HTTP scheduler')
    record_execution(scanner,'content-discovery',engine='native-content-discovery',state='running')
    before_count=scanner.store.conn.execute("SELECT COUNT(*) FROM observations WHERE kind='content-candidate'").fetchone()[0]
    problems=[]
    interrupted=False
    installed=locate()
    cap=request_cap(scanner.config)
    pending=sum(scanner.store.meta(job_key(r['url']),False) and r['state'] in {'queued','running'} for r in scanner.store.rows('jobs'))
    slots=max(0,cap-int(scanner.store.meta('wordlist_requests',0))-pending)
    try:
        for url,source,provenance in evidence_candidates(scanner):
            scanner.scheduler.check_time()
            if candidate(scanner,url,source,provenance,slots=slots):slots-=1
        selected=[] if scanner.config.discovery.wordlists else select_lists(scanner.store,installed)
        inputs=[('custom:'+str(i+1),path,None,'explicit custom dictionary') for i,path in enumerate(scanner.config.discovery.wordlists)]
        for name,reason in selected:
            spec=installed['available']['common' if name=='php' else name]
            inputs.append((name,spec['location'],spec,reason))
        # On resume saved dictionaries remain usable even if original sources
        # disappeared. Preserve their exact selection and source provenance.
        for old in scanner.store.meta('wordlists_used',[]):
            if old['name']!='dns' and not any(name==old['name'] for name,*_ in inputs):
                inputs.append((old['name'],old['path'],None,old['reason']))
        excluded = scanner.config.discovery.exclude_wordlists
        inputs = [(name,path,spec,reason) for name,path,spec,reason in inputs if name not in excluded and str(path) not in excluded]
        if not inputs:
            problems.append('No verified SecLists/custom dictionaries; only evidence-derived candidates considered')
        for name,path,spec,reason in inputs:
            scanner.scheduler.check_time()
            try:
                provenance,entries=dictionary(scanner,name,path,spec,reason=reason)
            except (OSError,ValueError) as exc:
                problems.append(str(exc));continue
            entries=selected_entries(name,entries)[:scanner.config.discovery.max_entries]
            target_origins = origins(scanner)
            for entry in entries:
                scanner.scheduler.check_time()
                for origin in target_origins:
                    if candidate(scanner,urljoin(origin,entry),'wordlist:'+name,{**provenance, 'entry':entry},slots=slots):slots-=1
        scanner.store.set_meta('discovery_generated',True)
        from .orchestrator import web_workflow
        await web_workflow(scanner)
    except (asyncio.CancelledError, KeyboardInterrupt):
        interrupted=True
        problems.append('Discovery interrupted; evidence and remaining allocation retained')
        raise
    except (OSError,ValueError) as exc:
        problems.append(str(exc))
    except Exception as exc:
        problems.append(str(exc))
        raise
    finally:
        if scanner.store.meta('discovery_entry_cap'):
            problems.append('Candidate entry cap reached; remaining dictionary entries not proposed')
        unallocated=scanner.store.conn.execute("SELECT COUNT(*) FROM observations WHERE kind='content-candidate' AND json_extract(data,'$.selection_reason')='discovery allocation exhausted'").fetchone()[0]
        if unallocated:problems.append(f'{unallocated} proposals retained without scheduling because discovery allocation was exhausted')
        deferred=scanner.store.conn.execute("SELECT COUNT(*) FROM jobs WHERE state='deferred'").fetchone()[0]
        if deferred:problems.append(f'{deferred} requests deferred by the discovery sub-budget')
        status='interrupted' if interrupted else 'partial' if problems else 'completed'
        detail='; '.join(problems) or 'Eligible candidates processed by native scheduler; a dictionary match is not a vulnerability'
        scanner.store.stage('content-discovery',status,detail)
        record_execution(scanner,'content-discovery',engine='native-content-discovery',state=status,reason=detail if problems else '',
            count=max(0,scanner.store.conn.execute("SELECT COUNT(*) FROM observations WHERE kind='content-candidate'").fetchone()[0]-before_count),
            accounting={'discovery_requests':scanner.store.meta('wordlist_requests',0),'discovery_request_cap':cap,'shared_target_requests':scanner.store.meta('requests',0)},
            seconds=time.monotonic()-started,limitations=problems,outputs=['recon.sqlite:observations','raw/wordlists'])
