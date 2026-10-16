import json

import pytest

from reconmap.config import default_config, PrioritySettings
from reconmap.engine import Scanner, Response, prepare_run
from reconmap.enrichment.prioritization import prioritize, classify_route
from reconmap.normalization import normalize_evidence, request_identity
from reconmap.storage import timestamp


@pytest.fixture
def scanner(tmp_path):
    config = default_config('example.com')
    config.budgets.depth = 3
    run, manifest = prepare_run(config, 'example.com', tmp_path)
    instance = Scanner(run, manifest, config, {})
    yield instance
    instance.store.close()


def response(scanner, path, body='<title>Application</title>', status=200, mime='text/html', **headers):
    url = 'https://example.com' + path
    scanner.add_url(url, 'fixture', fetch=False)
    scanner.process_response(url, Response(status, {'content-type': mime, **headers}, body.encode()), 0, len(scanner.store.rows('observations')) + 1)
    return url


def ranked(scanner):
    scanner.correlate()
    return {r['url']: r for r in prioritize(scanner.store, PrioritySettings()) if r['method'] in {'GET', 'UNKNOWN'}}


@pytest.mark.parametrize('path,mime', [
    ('/assets/css/adminlte.min.css', 'text/css'),
    ('/admin/login.css', 'text/html'),
    ('/myadminpanel', 'text/html'),
    ('/x?next=/admin/login', 'text/html'),
    ('/assets/administration.svg', 'image/svg+xml'),
    ('/apiary', 'text/html'),
    ('/administrator-notes.txt', 'text/plain'),
])
def test_misleading_route_names_never_become_admin_findings(scanner, path, mime):
    url = response(scanner, path, 'ordinary asset', mime=mime)
    record = ranked(scanner)[url]
    assert record['classification'] not in {'administration', 'authentication', 'api'}
    assert record['tier'] == 'inventory'
    assert not [f for f in scanner.store.rows('findings') if f['subject'] == url and f['rule'] == 'route-lead']


def test_meaningful_login_and_signature_outrank_asset_without_vulnerability_claim(scanner):
    login = response(scanner, '/admin/login', '<title>Sign in</title><form action="/admin/login" method="POST"><input type="password" name="password"></form>')
    asset = response(scanner, '/assets/css/adminlte.min.css', 'a {color: black}', mime='text/css')
    git = response(scanner, '/.git/HEAD', 'ref: refs/heads/main\n', mime='text/plain')
    rows = ranked(scanner)
    assert rows[login]['classification'] == 'authentication'
    assert rows[login]['tier'] == 'high-interest'
    assert rows[git]['score'] > rows[asset]['score']
    assert rows[git]['evidence_confidence'] == 'high'
    assert all(r['vulnerability_severity'] == 'unassessed' for r in rows.values())
    assert all(f['validation'] == 'candidate' for f in scanner.store.rows('findings'))
    # A signature pasted in CSS at an unrelated path is not Git metadata evidence.
    decoy = response(scanner, '/admin.css', 'ref: refs/heads/main\n', mime='text/css')
    assert ranked(scanner)[decoy]['tier'] == 'inventory'


def test_redirect_status_and_out_of_scope_destination_are_separate(scanner):
    url = response(scanner, '/assets/admin.css', '', status=301, mime='text/css', location='https://external.test/admin')
    record = ranked(scanner)[url]
    assert record['current_status'] == 301 and record['reachability'] == 'redirect-only'
    assert record['tier'] == 'inventory'
    assert record['redirect_chain'][0]['allowed'] is False
    assert record['final_observed_destination'] is None
    assert not any('external.test' in j['url'] for j in scanner.store.rows('jobs'))
    dest = response(scanner, '/admin/login', '<form><input type="password"></form>')
    origin = response(scanner, '/entry', '', status=302, location='/admin/login')
    record = ranked(scanner)[origin]
    assert record['current_status'] == 302
    assert record['final_observed_destination']['url'] == dest
    assert record['final_observed_destination']['status'] == 200


def test_history_never_uses_archive_status_as_current(scanner):
    url = 'https://example.com/api/users'
    scanner.add_url(url, 'urlfinder', fetch=False)
    scanner.store.execute('INSERT INTO historical_urls VALUES(?,?,?,?,?,?,?,?,?,?,?)', ('fixture', url, url, '20200101', '200', 'application/json', 'old-hash', 'wayback-cdx', 1, 'allowed', timestamp()))
    record = ranked(scanner)[url]
    assert record['current_status'] is None
    assert record['reachability'] == 'historical-only'
    assert record['historical_statuses'] == ['200']
    assert record['tier'] != 'high-interest'
    response(scanner, '/api/users', '{"users":[]}', mime='application/json')
    assert ranked(scanner)[url]['current_status'] == 200


def test_repeated_sources_and_identical_content_preserve_provenance(scanner):
    first = response(scanner, '/api/users/1', '{"users":[]}', mime='application/json')
    second = response(scanner, '/api/users/2', '{"users":[]}', mime='application/json')
    for _ in range(10):
        for source in ['subfinder', 'urlfinder', 'parent:urlfinder', 'jsluice', 'tree-sitter']:
            scanner.add_url(first, source, fetch=False)
    before = ranked(scanner)
    scanner.add_url(first, 'urlfinder', parent='another-page', fetch=False)
    after = ranked(scanner)
    assert before[first]['score'] == after[first]['score']
    assert after[first]['content_group'] == after[second]['content_group']
    assert len(after[first]['content_members']) == 2
    assert 'urlfinder' in after[first]['sources']
    assert len([r for r in after.values() if r['representative']]) == 1
    assert after[first]['group_size'] == 2
    assert len(scanner.store.rows('urls')) == 2


def test_numeric_route_family_does_not_flood_shortlist(scanner):
    for number in range(100):
        response(scanner, f'/api/users/{number}', '{"error":"sign in"}', status=403, mime='application/json')
    rows = list(ranked(scanner).values())
    assert len(rows) == 100
    assert sum(r['representative'] for r in rows) == 1
    assert all(r['group_size'] == 100 for r in rows)
    assert len(next(r for r in rows if r['representative'])['group_members']) == 100
    assert all(r['vulnerability_severity'] == 'unassessed' for r in rows)


def test_exact_requests_preserve_query_case_method_port_and_context(scanner):
    urls = ['https://example.com/api/Users?a=1&a=2', 'https://example.com/api/users?a=1&a=2',
            'https://example.com/api/Users?a=2&a=1', 'https://example.com:443/api/Users?a=1&a=2']
    for url in urls:
        scanner.add_url(url, 'fixture', fetch=False)
        for method, context in [('GET', 'role-a'), ('POST', 'role-a'), ('GET', 'role-b')]:
            scanner.store.observed(url, 'inferred_endpoint', {'method': method, 'authorization_context': context}, 'fixture')
    records = normalize_evidence(scanner.store)
    assert len(records) == 12 and len({r['identity'] for r in records}) == 12
    assert all(len(r['query_pairs']) == 2 for r in records)
    assert all(r['current_status'] is None for r in records)
    assert request_identity(urls[0]+'#a', 'GET') == request_identity(urls[0]+'#b', 'GET')
    candidates = prioritize(scanner.store, PrioritySettings())
    assert all(c['representative'] for c in candidates)  # distinct values/contexts stay visible


@pytest.mark.parametrize('status', [401, 403])
def test_restricted_surface_is_review_interest_not_access_failure(scanner, status):
    url = response(scanner, '/api/admin/users', '{"error":"authorization required"}', status=status, mime='application/json')
    row = ranked(scanner)[url]
    assert row['reachability'] == 'restricted' and row['tier'] in {'high-interest', 'manual-review'}
    assert row['vulnerability_severity'] == 'unassessed'
    assert 'not an access-control failure' in row['next_check']
    assert not any('access-control-failure' in f['rule'] for f in scanner.store.rows('findings'))


def test_soft404_generic_pages_conflicting_results_and_truncation(scanner):
    response(scanner, '/__reconmap_missing_fixture', '<title>Application</title><p>default fallback</p>')
    soft = response(scanner, '/admin/login', '<title>Application</title><p>default fallback</p>')
    generic = response(scanner, '/api/users', '<title>404 Not Found</title>')
    conflict = response(scanner, '/management/roles', '<title>Roles</title>')
    response(scanner, '/management/roles', '<title>Roles</title>', status=404)
    rows = ranked(scanner)
    assert rows[soft]['score'] <= 5 and rows[soft]['evidence_confidence'] == 'low'
    assert rows[generic]['tier'] == 'inventory'
    assert 'conflicting-observations' in rows[conflict]['signals']
    assert rows[conflict]['tier'] != 'high-interest'


def test_js_api_survives_static_bundle_suppression_and_remains_inferred(scanner):
    bundle = response(scanner, '/assets/app.abc12345.js', 'fetch("/api/admin/users"); fetch(`/api/${who}/admin`);', mime='application/javascript')
    rows = ranked(scanner)
    route = rows['https://example.com/api/admin/users']
    assert rows[bundle]['tier'] == 'inventory'
    assert route['reachability'] == 'inferred-only'
    assert route['tier'] == 'manual-review' and route['current_status'] is None
    assert route['inferred_endpoints'][0]['hash'] == rows[bundle]['body_hash']
    assert not any('${' in r['url'] for r in rows.values())


def test_parent_observation_does_not_claim_fresh_reachability(scanner):
    url = response(scanner, '/admin/login', '<title>Login</title>')
    scanner.store.execute("UPDATE observations SET source='parent:native' WHERE kind='http'")
    scanner.store.execute("UPDATE urls SET source='parent:native'")
    row = ranked(scanner)[url]
    assert row['current_status'] is None and row['reachability'] == 'previously-observed'
    assert row['prior_http'][0]['status'] == 200
    assert row['tier'] != 'high-interest'


def test_report_has_four_views_and_complete_machine_evidence(scanner):
    from reconmap.reporting import generate_report
    response(scanner, '/admin/login', '<form><input type="password"></form>')
    response(scanner, '/assets/css/adminlte.min.css', 'ordinary css', mime='text/css')
    generate_report(scanner.run, scanner.store)
    page = (scanner.run/'reports/index.html').read_text()
    for label in ['Live Assets', 'Interesting Endpoints', 'Potential Exposures', 'All Results']:
        assert '<h2>'+label in page
    assert 'Next check:' in page and 'Supporting evidence' in page
    report = json.loads((scanner.run/'reports/investigation.json').read_text())
    assert report['summary']['high_interest'] == 1
    assert len(report['shortlist']) == 1 and len(report['all_results']) >= 2
    assert (scanner.run/'normalized/normalized_records.jsonl').is_file()
    assert "connect-src 'none'" in page and 'http://cdn' not in page


def test_methodless_tool_duplicates_do_not_create_another_review_card(scanner):
    url = response(scanner, '/api/admin/users', '{"users":[]}', mime='application/json')
    for method in ['GET', 'UNKNOWN', 'POST']:
        scanner.store.observed(url, 'inferred_endpoint', {'method': method, 'hash': 'a'*64}, 'jsluice')
    candidates = prioritize(scanner.store, PrioritySettings())
    assert len(candidates) == 3
    assert {c['method'] for c in candidates if c['representative']} == {'GET', 'POST'}
    assert next(c for c in candidates if c['method'] == 'UNKNOWN')['current_status'] is None
    assert next(c for c in candidates if c['method'] == 'POST')['current_status'] is None


def test_framework_signatures_inside_static_files_do_not_raise_exposure_priority(scanner):
    url = response(scanner, '/admin.js', 'const product = "swagger-ui";', mime='application/javascript')
    row = ranked(scanner)[url]
    assert row['classification'] == 'static' and row['tier'] == 'inventory'


def test_generated_documentation_and_generic_debug_markers_require_review(scanner):
    docs = response(scanner, '/openapi.json', '{"openapi":"3.0.0","info":{},"paths":{}}', mime='application/json')
    marker = response(scanner, '/about', '<p>Werkzeug Debugger documentation example</p>')
    rows = ranked(scanner)
    assert rows[docs]['classification'] == 'documentation'
    assert rows[docs]['score'] <= 25 and rows[docs]['tier'] != 'high-interest'
    assert rows[marker]['score'] <= 55 and rows[marker]['evidence_confidence'] != 'high'


def test_methodless_correlation_keeps_other_unobserved_family_members_visible(scanner):
    observed = response(scanner, '/api/users/1', '{"users":[]}', mime='application/json')
    other = 'https://example.com/api/users/2'
    scanner.add_url(other, 'jsluice', fetch=False)
    for url in [observed, other]:
        scanner.store.observed(url, 'inferred_endpoint', {'method': 'UNKNOWN'}, 'jsluice')
    candidates = prioritize(scanner.store, PrioritySettings())
    assert {(c['url'], c['method']) for c in candidates if c['representative']} == {(observed, 'GET'), (other, 'UNKNOWN')}


@pytest.mark.parametrize('method,expected', [('M-SEARCH', 'M-SEARCH'), ('GET', 'GET'), ('BAD METHOD', 'UNKNOWN'), (42, 'UNKNOWN'), (0, 'UNKNOWN'), (False, 'UNKNOWN'), (None, 'UNKNOWN')])
def test_normalization_retains_evidence_for_extension_and_invalid_methods(scanner, method, expected):
    url = 'https://example.com/api/extension'
    scanner.add_url(url, 'fixture', fetch=False)
    scanner.store.observed(url, 'inferred_endpoint', {'method': method, 'hash': 'a'*64}, 'jsluice')
    record, = normalize_evidence(scanner.store)
    assert record['method'] == expected
    assert record['inferred_endpoints'][0]['method'] == method
    assert any(e['kind'] == 'inferred_endpoint' for e in record['evidence'])
    assert record['current_status'] is None and not scanner.store.rows('jobs')


def test_structured_authorization_context_keeps_evidence_and_canonical_identity(scanner):
    url = 'https://example.com/api/users'
    scanner.add_url(url, 'fixture', fetch=False)
    for context in [{'role': 'analyst', 'tenant': 'one'}, {'tenant': 'one', 'role': 'analyst'}, {'tenant': 'two', 'role': 'analyst'}]:
        scanner.store.observed(url, 'inferred_endpoint', {'method': 'GET', 'authorization_context': context}, 'fixture')
    records = normalize_evidence(scanner.store)
    assert len(records) == 2
    assert sorted(len(r['inferred_endpoints']) for r in records) == [1, 2]
    assert all(r['current_status'] is None for r in records)


@pytest.mark.parametrize('mime', ['Image/PNG', ' IMAGE/PNG ; charset=binary', 'Application/JavaScript', 'TEXT/CSS'])
def test_case_insensitive_mime_never_promotes_static_route_names(scanner, mime):
    url = response(scanner, '/api/admin/users', 'ordinary static content', mime=mime)
    row = ranked(scanner)[url]
    assert row['classification'] == 'static' and row['tier'] == 'inventory'


def test_parent_soft404_does_not_suppress_fresh_login_evidence(scanner):
    response(scanner, '/__reconmap_missing_fixture', '<title>Missing</title>old fallback')
    url = response(scanner, '/admin/login', '<title>Missing</title>old fallback')
    scanner.correlate()
    assert 'soft-404' in ranked(scanner)[url]['signals']
    scanner.store.execute("UPDATE observations SET source='parent:' || source")
    response(scanner, '/admin/login', '<title>Sign in</title><form><input type="password"></form>')
    row = ranked(scanner)[url]
    assert 'soft-404' not in row['signals']
    assert row['tier'] == 'high-interest'
    assert any(e['kind'] == 'soft-error-similarity' for e in row['evidence'])


def test_case_insensitive_response_mime_still_extracts_scripts_and_forms(scanner):
    bundle = response(scanner, '/assets/bundle', 'fetch("/api/from-mixed-case-mime");', mime='Application/JavaScript ; charset=utf-8')
    login = response(scanner, '/sign-in', '<form><input type="password"></form>', mime='TEXT/HTML ; charset=utf-8')
    rows = ranked(scanner)
    assert rows[bundle]['classification'] == 'static'
    assert rows['https://example.com/api/from-mixed-case-mime']['inferred_endpoints']
    assert rows[login]['classification'] == 'authentication'
    assert rows[login]['tier'] == 'high-interest'


@pytest.mark.parametrize('extension', ['.JS', '.mjs', '.MAP'])
def test_script_and_source_map_extensions_keep_case_sensitive_urls(scanner, extension):
    body = json.dumps({'version': 3, 'sources': ['original.js'], 'sourcesContent': ['fetch("/api/from-extension");'], 'mappings': ''}) if extension == '.MAP' else 'fetch("/api/from-extension");'
    url = response(scanner, '/assets/bundle' + extension, body, mime='text/plain')
    rows = ranked(scanner)
    assert url.endswith(extension)
    assert rows['https://example.com/api/from-extension']['inferred_endpoints']


def test_soft404_from_an_older_response_does_not_apply_to_new_body(scanner):
    response(scanner, '/__reconmap_missing_fixture', '<title>Missing</title>old fallback')
    url = response(scanner, '/admin/login', '<title>Missing</title>old fallback')
    scanner.correlate()
    # Legacy soft-error records stored the body hash in the identity only.
    scanner.store.execute("UPDATE observations SET data='{}' WHERE kind='soft-error-similarity'")
    assert 'soft-404' in ranked(scanner)[url]['signals']
    response(scanner, '/admin/login', '<title>Sign in</title><form><input type="password"></form>')
    row = ranked(scanner)[url]
    assert 'soft-404' not in row['signals']
    assert 'conflicting-observations' in row['signals']
