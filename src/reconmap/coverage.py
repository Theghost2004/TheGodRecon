"""Coverage derived from durable evidence; counts are observations, not estimates."""
from __future__ import annotations

import json
from collections import Counter

from .orchestrator import STAGE_NAMES
from .tool_registry import BY_NAME, NATIVE_COVERAGE


def discovery_rows(store):
    candidates = {}
    for row in store.rows('investigation_candidates'):
        value = json.loads(row['data'])
        if value.get('method') == 'GET': candidates[value['url']] = value
    http = {}
    redirects = {}
    for row in store.rows('observations'):
        if row['kind'] == 'http' and not row['source'].startswith('parent:'):
            http[row['subject']] = json.loads(row['data'])
        if row['kind'] == 'discovery' and row['source'] == 'redirect':
            redirects.setdefault(json.loads(row['data']).get('parent'), []).append(row['subject'])
    urls = {r['url']:r for r in store.rows('urls')}
    rows = []
    for row in store.conn.execute("SELECT * FROM observations WHERE kind='content-candidate' ORDER BY id"):
        detail = json.loads(row['data'])
        observed = http.get(row['subject'], {})
        ranked = candidates.get(row['subject'], {})
        inventory = urls.get(row['subject'], {})
        rows.append({'url':row['subject'], 'source':row['source'], 'wordlist':detail.get('name'),
                     'wordlist_hash':detail.get('sha256'), 'wordlist_version':detail.get('revision'),
                     'tested':bool(observed), 'status':observed.get('status'),
                     'content_type': inventory.get('content_type') if observed else None,
                     'redirect_destinations':redirects.get(row['subject'], []),
                     'body_hash':observed.get('hash'), 'confidence':ranked.get('evidence_confidence', detail.get('confidence','low')),
                     'review_priority':ranked.get('review_priority','Low'), 'classification':ranked.get('classification','untested proposal'),
                     'group_size':ranked.get('group_size',1), 'evidence_id':row['id'], 'timestamp':row['time'], 'provenance':detail})
    return rows


def summarize(store):
    observations = store.rows('observations')
    http = [r for r in observations if r['kind']=='http' and not r['source'].startswith('parent:')]
    statuses = [json.loads(r['data']).get('status',0) for r in http]
    filters = [json.loads(r['data']).get('reason','') for r in observations if r['kind']=='scheduling-filter']
    jobs = Counter(r['state'] for r in store.rows('jobs'))
    limits = [r['detail'] for r in store.rows('stages') if r['name']=='core' and r['detail']]
    reasons = []
    if limits: reasons.extend(limits)
    if jobs['queued'] or jobs['running']: reasons.append('Eligible queue remains; execution stopped or was interrupted before draining it')
    if jobs['deferred']: reasons.append('Discovery allocation exhausted; deferred dictionary descendants were retained')
    if store.meta('discovery_entry_cap'): reasons.append('Candidate entry ceiling reached; remaining dictionary entries were not proposed')
    if any(r['kind']=='content-candidate' and json.loads(r['data']).get('selection_reason')=='discovery allocation exhausted' for r in observations):
        reasons.append('Discovery allocation exhausted; additional proposals remain untested')
    if not reasons: reasons.append('No further eligible in-scope URLs were discovered')
    crawler = {'urls_discovered':len(store.rows('urls')), 'urls_scheduled':sum(jobs.values()),
        'urls_tested':len({r['subject'] for r in http}), 'http_responses':len(http),
        'redirect_only':sum(300<=s<400 for s in statuses), 'restricted_responses':sum(s in {401,403} for s in statuses),
        'filtered_static_noise':sum('static/bulk' in r for r in filters),
        'out_of_scope_references':len({r['subject'] for r in observations if r['kind']=='discovery' and not json.loads(r['data']).get('allowed',False)}),
        'depth_limited':sum(r=='depth limit' for r in filters), 'request_failures':sum(r['kind']=='request_error' for r in observations),
        'soft_error_candidates':sum(r['kind']=='soft-error-similarity' for r in observations),
        'queue_remaining':jobs['queued']+jobs['running'], 'discovery_deferred':jobs['deferred'],
        'requests_reserved':store.meta('requests',0), 'stop_reason':'; '.join(reasons)}
    artifacts = {a['hash'] for a in store.rows('artifacts') if a['kind'] in {'js','map'}}
    analyses = [json.loads(r['data']) for r in observations if r['kind']=='artifact-analysis' and r['source']=='jsluice']
    processed = {r['hash'] for r in analyses if r.get('processed')}
    # Native-only analysis has no external-tool checkpoint; its artifact flag is
    # written after native analysis, but must not represent selected-tool work.
    config = store.meta('config',{})
    if 'jsluice' not in config.get('modules',[]):
        processed |= {a['hash'] for a in store.rows('artifacts') if a['analyzed'] and a['hash'] in artifacts}
    javascript = {'captured_artifacts':len(artifacts), 'processed_artifacts':len(processed & artifacts),
                  'unprocessed_artifacts':len(artifacts-processed),
                  'primary_failed_artifacts':len({r['hash'] for r in analyses if r['primary_status'] in {'failed','partial'}}),
                  'primary_empty_artifacts':len({r['hash'] for r in analyses if r['primary_status']=='completed' and r['primary_records']==0}),
                  'inferred_records':sum(r['kind']=='inferred_endpoint' for r in observations),
                  'unresolved_expressions':sum(r['kind']=='unresolved_expression' for r in observations),
                  'details':analyses}
    results = {r['name']:json.loads(r['result_json']) for r in store.rows('stage_results')}
    tools = []
    for selected in store.rows('tool_executions'):
        name=selected['name']; result=results.get(STAGE_NAMES[name],{})
        info=result.get('tool_identity',{})
        engines=result.get('actual_execution_engines',[])
        tools.append({'tool':name,'installed':info.get('available',False),'compatible':info.get('compatible',False),
            'direct_execution_permitted':bool(info.get('supported')) and not BY_NAME[name].policy_reason,
            'actually_ran':bool(store.meta('executed:'+name, name in engines)), 'primary_status':result.get('primary_status','pending'),
            'coverage_status':result.get('status','pending'), 'engines':engines,
            'native_fallbacks':[e for e in engines if e.startswith('native-')],
            'records':result.get('discovered_records',0),'duration_seconds':result.get('duration_seconds',0),
            'reason':result.get('failure_reason',''), 'limitations':result.get('coverage_limitations',[]),
            'native_capability_and_limits':NATIVE_COVERAGE[name], 'version':info.get('version'), 'executable':info.get('path'), 'sha256':info.get('sha256')})
    settings=config.get('discovery',{})
    return {'crawler':crawler, 'javascript':javascript, 'tools':tools,
            'discovery':{'enabled':settings.get('enabled',False), 'god_mode':settings.get('god_mode',False),
                'candidates':store.conn.execute("SELECT COUNT(*) FROM observations WHERE kind='content-candidate'").fetchone()[0],
                'requests':store.meta('wordlist_requests',0),
                'request_cap':min(settings.get('request_budget',100),config.get('budgets',{}).get('requests',5000)//5),
                'wordlists_used':store.meta('wordlists_used',[])}}
