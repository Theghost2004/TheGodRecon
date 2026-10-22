"""Deterministic evidence graph derived from the shared normalized request inventory.

Resource nodes aggregate evidence labels, never HTTP method reachability. Request
nodes retain the exact normalized identity. Prefix edges express URL structure,
not observed links or directory existence. The cache is rebuilt atomically.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from urllib.parse import urlsplit, urlunsplit

from .config import request_url
from .security import redact_data
from .storage import atomic_json

GRAPH_VERSION = 1


def stable_id(kind, identity):
    return hashlib.sha256(json.dumps([kind, identity], ensure_ascii=True, sort_keys=True).encode()).hexdigest()


def observation_ref(row):
    detail = json.loads(row['data'])
    return {"table": "observations", "id": row['id'], "source": row['source'],
            "kind": row['kind'], "timestamp": row['time'],
            **{k: detail[k] for k in ('hash', 'artifact') if detail.get(k)}}


class Builder:
    def __init__(self):
        self.nodes = {}
        self.edges = {}

    def node(self, kind, identity, label, **data):
        key = stable_id(kind, identity)
        if key not in self.nodes:
            self.nodes[key] = {'id': key, 'type': kind, 'label': label, 'sources': [], 'states': [], 'evidence': [], **data}
        return key

    def edge(self, source, destination, kind, *, semantics, evidence=(), confidence='medium'):
        key = stable_id('edge', [source, destination, kind, semantics])
        if key not in self.edges:
            self.edges[key] = {'id': key, 'source': source, 'destination': destination, 'type': kind,
                'semantics': semantics, 'confidence': confidence, '_evidence': {}}
        for item in evidence:
            if item.get('time') and not item.get('timestamp'):
                item = {**item, 'timestamp':item['time']}
            self.edges[key]['_evidence'][json.dumps(item, sort_keys=True)] = item

    def finish(self):
        edges = []
        for row in self.edges.values():
            refs = row.pop('_evidence')
            evidence = [refs[k] for k in sorted(refs)]
            edges.append({**row, 'evidence': evidence, 'sources': sorted({e.get('source','') for e in evidence if e.get('source')}),
                          'timestamps': sorted({e['timestamp'] for e in evidence if e.get('timestamp')})})
        return {'schema_version': GRAPH_VERSION, 'nodes': sorted(self.nodes.values(), key=lambda n:n['id']),
                'edges': sorted(edges, key=lambda e:e['id'])}


def build_graph(store, records=None, candidates=None):
    records = records if records is not None else [json.loads(r['data']) for r in store.rows('normalized_records')]
    candidates = candidates if candidates is not None else [json.loads(r['data']) for r in store.rows('investigation_candidates')]
    rankings = {r['identity']:r for r in candidates}
    builder = Builder()
    by_url = defaultdict(list)
    observations = store.rows('observations')
    obs_by_subject = defaultdict(list)
    for row in observations:
        obs_by_subject[row['subject']].append(row)
    config = store.meta('config', {})
    targets = [h for h in config.get('scope',{}).get('hosts',[]) if not h.startswith('*.')]
    hosts = {}
    def host_node(host):
        if host not in hosts:
            kind = 'subdomain' if any(host.endswith('.'+base) for base in targets) else 'domain'
            hosts[host] = builder.node(kind, host, host)
        return hosts[host]
    for row in store.rows('hosts'):
        key = host_node(row['host'])
        builder.nodes[key]['evidence'] = [observation_ref(r) for r in obs_by_subject[row['host']]]
        builder.nodes[key]['sources'] = sorted({r['source'] for r in obs_by_subject[row['host']]})
    resources = {}
    for record in records:
        by_url[record['url']].append(record)
    for url, values in sorted(by_url.items()):
        parsed = urlsplit(url)
        origin = urlunsplit(parsed._replace(path='', query='', fragment=''))
        host = host_node(parsed.hostname)
        origin_id = builder.node('origin', origin, origin)
        refs = [{'table':'normalized_records', 'id':r['identity'], 'source':s} for r in values for s in r.get('sources',[])]
        if not refs: refs = [{'table':'normalized_records','id':values[0]['identity'],'source':'normalized evidence'}]
        builder.edge(host, origin_id, 'shares_origin', semantics='structural', evidence=refs, confidence='high')
        states = set()
        for r in values:
            if r.get('current_http'): states.add('live-observed')
            if r.get('historical') or r.get('prior_http') or 'historical' in r.get('signals',[]): states.add('historical')
            if 'seed' in r.get('sources',[]): states.add('user-selected-target')
            if 'redirect' in r.get('sources',[]): states.add('redirect-destination')
            if r.get('inferred_endpoints'): states.add('javascript-inferred')
            if any(s in {'html-link','link','form-action','script','html-script'} for s in r.get('sources',[])): states.add('html-linked')
        if not states: states.add('discovered-unobserved')
        types = set()
        mime = {r.get('content_type','') or '' for r in values}
        if parsed.path.lower().endswith(('.js','.mjs')) or any('javascript' in t for t in mime): types.add('javascript_resource')
        api = bool(re.search(r'/(api|graphql)(?:/|$)', parsed.path, re.I)) and not parsed.path.lower().endswith(('.css','.png','.jpg','.woff','.js','.map'))
        if api: types.add('api_endpoint')
        if any(t.startswith(('image/','font/')) or t=='text/css' for t in mime) or parsed.path.lower().endswith(('.css','.png','.jpg','.svg','.woff','.woff2','.ico')):
            types.add('static_resource')
        if not any(r.get('allowed') for r in values): types.add('external_reference')
        if 'historical' in states and 'live-observed' not in states: types.add('historical_url')
        if any(o['kind']=='form' for o in obs_by_subject[url]): types.add('form_action')
        kind = next((t for t in ('external_reference','javascript_resource','static_resource','api_endpoint','historical_url','form_action') if t in types),'webpage')
        key = builder.node('resource', url, url, url=url, types=sorted(types|{kind}), states=sorted(states),
            sources=sorted({s for r in values for s in r.get('sources',[])}), evidence=refs,
            observation_note='Resource aggregates evidence types; consult request children for method-specific status')
        builder.nodes[key]['type'] = kind
        resources[url] = key
        parent = origin_id
        # Empty path segments and explicit ports remain in both identity and hierarchy.
        segments = parsed.path.split('/')
        for index in range(2, min(len(segments), 66)):
            prefix = '/'.join(segments[:index]) + '/'
            directory = builder.node('path_group', [origin,prefix], prefix, states=['structural-only'], sources=['URL path structure'])
            builder.edge(parent, directory, 'contains_path', semantics='structural', evidence=refs, confidence='high')
            parent = directory
        builder.edge(parent, key, 'contains_path', semantics='structural', evidence=refs, confidence='high')
        builder.edge(key, origin_id, 'shares_origin', semantics='structural', evidence=refs, confidence='high')
        for r in values:
            ranked = rankings.get(r['identity'], {})
            request = builder.node('http_request', r['identity'], f"{r['method']} {url}",
                url=url, original_urls=r.get('original_urls',[]), method=r['method'], authorization_context=r.get('authorization_context'),
                parameters=r.get('query_pairs',[]), states=['live-observed'] if r.get('current_http') else ['historical'] if r.get('historical') or r.get('prior_http') or 'historical' in r.get('signals',[]) else ['inferred' if r.get('inferred_endpoints') else 'unobserved'],
                status=r.get('current_status'), reachability=r.get('reachability'), sources=r.get('sources',[]), evidence=r.get('evidence',[]),
                classification=ranked.get('classification'), review_priority=ranked.get('review_priority'), evidence_confidence=ranked.get('evidence_confidence'),
                ranking_reasons=ranked.get('reasons',[]), normalized_identity=r['identity'])
            builder.edge(key, request, 'has_request', semantics='structural', evidence=r.get('evidence',[]) or refs, confidence='high')
            for index, pair in enumerate(r.get('query_pairs', [])):
                parameter = builder.node('parameter', [r['identity'],index,pair], f"{pair[0]}={pair[1]}", states=['request-identity'], sources=r.get('sources',[]))
                builder.edge(request, parameter, 'has_parameter', semantics='structural', evidence=refs, confidence='high')
            for parameter in r.get('parameters',[]):
                if parameter.get('location')=='query': continue
                param = builder.node('parameter', [r['identity'],parameter], parameter.get('name','')+' ('+parameter.get('location','')+')',
                    states=['observed-parameter-reference'], sources=[parameter.get('source','')], evidence=[{'table':'parameters', **parameter}])
                builder.edge(request,param,'has_parameter',semantics='observed-reference',evidence=refs)
            for source in r.get('sources',[]):
                source_id = builder.node('discovery_source', source, source, sources=[source])
                builder.edge(request, source_id, 'discovered_by', semantics='provenance', evidence=[e for e in r.get('evidence',[]) if e.get('source')==source] or refs)
            for history in r.get('historical',[]):
                # Historical entries stay attached to their request; never create current HTTP.
                history_id = builder.node('historical_observation', [r['identity'],history], url+' (historical)', states=['historical'], sources=r.get('sources',[]), detail=history)
                builder.edge(request, history_id, 'historically_observed', semantics='historical', evidence=refs)
    artifacts = {}
    for row in store.rows('artifacts'):
        artifacts['artifact:'+row['hash']] = builder.node('artifact', row['hash'], row['kind']+' '+row['hash'][:12],
            artifact=row['path'], sha256=row['hash'], states=['captured'], sources=['captured artifact'], evidence=[{'table':'artifacts','id':row['hash'],'artifact':row['path']}])
    relationships = store.rows('relationships')
    for row in relationships:
        if row['kind']=='source_map_content' and row['child'].startswith('embedded:'):
            digest = row['child'].removeprefix('embedded:')
            node = builder.node('artifact',digest,'embedded JavaScript '+digest[:12],states=['captured-embedded'],sources=['source map'],evidence=[row])
            artifacts[row['child']] = artifacts['artifact:'+digest] = node
    mapping = {'redirect':'redirects_to', 'form-action':'submits_to', 'script':'loads_script', 'html-script':'loads_script',
               'jsluice':'references_api','source_map_content':'has_evidence','inferred_endpoint':'references_api','inferred_endpoint_non_get':'references_api','response_body':'has_evidence', 'source_map':'links_to'}
    # Relationship rows persist even when scheduling was denied. They never imply a request occurred.
    for row in relationships:
        src = resources.get(row['parent']) or artifacts.get(row['parent'])
        dst = resources.get(row['child']) or artifacts.get(row['child'])
        if not src or not dst: continue
        kind = mapping.get(row['kind'], 'links_to')
        semantics = 'statically-inferred' if 'inferred_endpoint' in row['kind'] or row['kind']=='jsluice' else 'observed-reference'
        if row['source'].startswith('parent:'): semantics = 'prior-run-reference'
        matches = []
        for obs in obs_by_subject[row['child']]:
            detail = json.loads(obs['data'])
            if detail.get('parent') == row['parent'] or ('inferred_endpoint' in row['kind'] and detail.get('hash') == row['parent'].removeprefix('artifact:')):
                matches.append(observation_ref(obs))
        evidence = matches or [{'table':'relationships','parent':row['parent'],'child':row['child'],'kind':row['kind'],'source':row['source']}]
        builder.edge(src,dst,kind,semantics=semantics,evidence=evidence)
        # Native AST relationship source records its exact script base. Do not
        # cross-product shared bodies with every URL that happened to serve them.
        if semantics == 'statically-inferred' and row['source'] in resources:
            builder.edge(resources[row['source']],dst,kind,semantics=semantics,evidence=evidence)
    for obs in observations:
        if obs['kind'] != 'inferred_endpoint': continue
        detail = json.loads(obs['data'])
        src = resources.get(detail.get('source_url')) or artifacts.get('artifact:'+str(detail.get('hash')))
        dst = resources.get(obs['subject'])
        if src and dst:
            builder.edge(src,dst,'references_api',semantics='statically-inferred',evidence=[observation_ref(obs)])
    # HTTP Location is authoritative even for imported observations without a
    # discovery relationship. Destination may be denied/unobserved.
    for r in records:
        for redirect in r.get('redirect_chain',[]):
            src = resources.get(redirect.get('url',redirect.get('from')))
            dst = resources.get(redirect.get('destination',redirect.get('location',redirect.get('to'))))
            if src and dst:
                builder.edge(src,dst,'redirects_to',semantics='observed-reference',evidence=r.get('evidence',[]))
    for finding in store.rows('findings'):
        finding_evidence = json.loads(finding['evidence'])
        src = resources.get(finding['subject']) or artifacts.get(finding['subject'])
        if not src and finding['subject'].startswith('artifact:'):
            src = artifacts.get('artifact:'+str(finding_evidence.get('hash')))
        if not src: continue
        related = [rankings[r['identity']] for r in by_url.get(finding['subject'],[]) if r['identity'] in rankings]
        kind = 'exposure_candidate' if finding['subject'].startswith('artifact:') or any(c.get('classification')=='potential-exposure' for c in related) else 'investigation_candidate'
        node = builder.node(kind, finding['fingerprint'], finding['title'], states=[finding['validation']], sources=[finding['source']],
            validation=finding['validation'], severity=finding['severity'], confidence=finding['confidence'], evidence=finding_evidence, finding_id=finding['fingerprint'],
            investigation_ranking=[{k:c.get(k) for k in ('identity','classification','review_priority','evidence_confidence','tier')} for c in related])
        builder.edge(src,node,'has_candidate',semantics='analyst-lead',evidence=[{'table':'findings','id':finding['fingerprint'],'source':finding['source'],'timestamp':finding['time']}])
    for host, key in hosts.items():
        parts = host.split('.')
        parent = next(('.'.join(parts[i:]) for i in range(1,len(parts)) if '.'.join(parts[i:]) in hosts),None)
        if parent:
            builder.edge(hosts[parent],key,'contains_host',semantics='structural',
                evidence=[{'source':'observed hostname structure','host':host,'parent':parent}],confidence='high')
    graph = builder.finish()
    stage_results = [json.loads(r['result_json']) for r in store.rows('stage_results')]
    runs = store.rows('runs')
    graph['summary'] = {'execution_state': runs[-1]['state'] if runs else 'unknown',
        'target':runs[-1]['target'] if runs else None,
        'workflow':config.get('workflow','scan'),
        'capability_coverage':[{k:r.get(k) for k in ('stage','selected_primary_tool','actual_execution_engines','status','failure_reason','coverage_limitations')} for r in stage_results],
        'nodes':len(graph['nodes']), 'edges':len(graph['edges']),
        'node_types':dict(Counter(n['type'] for n in graph['nodes'])), 'edge_types':dict(Counter(e['type'] for e in graph['edges'])),
        'hosts':len(hosts), 'urls':len(resources), 'requests':len(records),
        'tested_urls':len({r['url'] for r in records if r.get('current_http')}),
        'api_candidates':sum('api_endpoint' in n.get('types',[]) for n in graph['nodes']),
        'javascript_resources':sum('javascript_resource' in n.get('types',[]) for n in graph['nodes']),
        'coverage_notes':['Path grouping is structural, not evidence of an existing directory.',
            'Live-observed means an HTTP response was captured; redirects/errors/restrictions are not successful endpoint validation.',
            'Inferred, historical and external references do not establish current reachability.',
            'Resource nodes aggregate evidence; HTTP request nodes retain method, context and query identity.',
            'At most 64 structural prefix groups per URL; original URLs and request identities are always retained.',
            'No network requests are made to generate or view this map.']}
    return graph


def persist_graph(store, graph):
    # One transaction replaces the derived cache; cancellation cannot leave half a graph.
    with store.conn:
        store.conn.execute('DELETE FROM graph_edges')
        store.conn.execute('DELETE FROM graph_nodes')
        store.conn.executemany('INSERT INTO graph_nodes VALUES(?,?,?)', [(n['id'],n['type'],json.dumps(n)) for n in graph['nodes']])
        store.conn.executemany('INSERT INTO graph_edges VALUES(?,?,?,?,?)', [(e['id'],e['source'],e['destination'],e['type'],json.dumps(e)) for e in graph['edges']])
    store.set_meta('graph_summary', graph['summary'])


def clean_label(value):
    return re.sub(r'[\x00-\x1f\x7f-\x9f]', '', str(value))


def render_tree(graph):
    nodes = {n['id']:n for n in graph['nodes']}
    children = defaultdict(set)
    for edge in graph['edges']:
        if edge['type'] in {'contains_path','contains_host'} or edge['type']=='has_request' or (edge['type']=='shares_origin' and nodes[edge['source']]['type'] in {'domain','subdomain'}):
            children[edge['source']].add(edge['destination'])
    lines = ['TheGodRecon endpoint hierarchy', 'Path prefixes are structural groups. Observed/inferred links are in asset-graph.json.', '']
    host_children = {e['destination'] for e in graph['edges'] if e['type']=='contains_host'}
    roots = sorted((n for n in nodes.values() if n['type'] in {'domain','subdomain'} and n['id'] not in host_children), key=lambda n:n['label'])
    # Iterative traversal: long paths/cycles cannot overflow Python's stack.
    stack = [(n['id'],0) for n in reversed(roots)]
    visited = set()
    while stack:
        key, depth = stack.pop()
        node = nodes[key]
        label = clean_label(node['label'])
        lines.append('  '*min(depth,32) + ('+- ' if depth else '') + label + ' ['+node['type']+'; '+', '.join(node['states'])+('; '+node['classification'] if node.get('classification') else '')+']')
        if key in visited: continue
        visited.add(key)
        stack.extend((child,depth+1) for child in sorted(children[key], key=lambda k:(nodes[k]['label'],k), reverse=True))
    return '\n'.join(lines)+'\n'


def render_dot(graph):
    quote = lambda value: json.dumps(clean_label(value),ensure_ascii=False)
    lines = ['digraph TheGodRecon {', '  graph [rankdir=LR];', '  node [shape=box];']
    for node in graph['nodes']:
        lines.append(f'  "{node["id"]}" [label={quote(node["label"]+" ["+node["type"]+"]")}];')
    for edge in graph['edges']:
        lines.append(f'  "{edge["source"]}" -> "{edge["destination"]}" [label={quote(edge["type"]+" / "+edge["semantics"])}];')
    return '\n'.join(lines+['}'])+'\n'


def export_graph(run, store, records=None, candidates=None):
    graph = build_graph(store,records,candidates)
    persist_graph(store,graph)
    exported = redact_data(graph)
    directory = run/'graph'
    directory.mkdir(exist_ok=True)
    atomic_json(directory/'asset-graph.json',exported)
    atomic_json(directory/'graph-summary.json',exported['summary'])
    (directory/'endpoint-tree.txt').write_text(render_tree(exported),encoding='utf-8')
    (directory/'asset-graph.dot').write_text(render_dot(exported),encoding='utf-8')
    from .asset_map import render_map
    report_href = '../reports/index.html' if 'html' in store.meta('config',{}).get('report_formats',['html']) else '../reports/investigation.json'
    (directory/'asset-map.html').write_text(render_map(exported, report_href),encoding='utf-8')
    return graph['summary']
