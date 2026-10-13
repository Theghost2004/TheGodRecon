from __future__ import annotations

import json
from .engine import Response


def fixtures() -> dict[str, Response]:
    def page(text: str, status: int = 200, headers: dict | None = None) -> Response:
        return Response(status, {"content-type":"text/html", **(headers or {})}, text.encode())

    script = '''// SYNTHETIC DEMO: no real credentials.
fetch('/api/account?expand=profile');
const dynamic = `/api/${userId}/upload`;
const config = { publicClientId: "demo-public-client", token: "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8" };
fetch('/api/invite', {method: 'POST', body: JSON.stringify({email: email})});
//# sourceMappingURL=app.js.map
'''
    return {
        "https://example.com/": page('''<title>Reconmap Demo</title><h1>Offline fixture</h1>
<a href="/account">Account</a><a href="/restricted">Restricted</a><a href="/redirect">Redirect</a><a href="/missing">Missing</a><a href="/logout">Logout</a>
<a href="https://example.com.attacker.test/">External reference</a>
<script src="/app.js"></script><script src="/duplicate.js"></script>
<script>fetch('/api/export?format=csv');</script>
<form action="/upload" method="POST"><input name="file"><input name="csrf_token"></form>
<!-- embedded public config, not proof of a secret -->'''),
        "https://example.com/account": page('<title>Account</title><a href="/api/account?expand=profile">API</a>'),
        "https://example.com/restricted": page('<title>Forbidden</title>',403),
        "https://example.com/redirect": page('',302,{"location":"https://external.test/outside"}),
        "https://example.com/api/account?expand=profile": Response(200,{"content-type":"application/json"},b'{"demo":true,"account":"synthetic"}'),
        "https://example.com/api/export?format=csv": Response(401,{"content-type":"application/json"},b'{"error":"auth required"}'),
        "https://example.com/app.js": Response(200,{"content-type":"application/javascript"},script.encode()),
        "https://example.com/duplicate.js": Response(200,{"content-type":"application/javascript"},script.encode()),
        "https://example.com/app.js.map": Response(200,{"content-type":"application/json"},json.dumps({"version":3,"sources":["../../unsafe.js"],"sourcesContent":["fetch('/api/import');"],"mappings":""}).encode()),
        "https://example.com/duplicate.js.map": Response(200,{"content-type":"application/json"},b'{"version":3,"sources":["duplicate"],"sourcesContent":[],"mappings":""}'),
        "https://example.com/.git/HEAD": Response(200,{"content-type":"text/plain"},b'ref: refs/heads/demo\n'),
        "https://example.com/.env": Response(404,{"content-type":"text/plain"},b'not found'),
        "https://example.com/openapi.json": Response(200,{"content-type":"application/json"},b'{"openapi":"3.0.0","info":{"title":"demo","version":"1"},"paths":{"/api/import":{}}}'),
        "https://example.com/swagger.json": Response(404,{"content-type":"text/plain"},b'not found'),
        "https://example.com/robots.txt": Response(200,{"content-type":"text/plain"},b'User-agent: *\nDisallow: /admin\nSitemap: https://example.com/sitemap.xml\n'),
        "https://example.com/sitemap.xml": Response(200,{"content-type":"application/xml"},b'<urlset><url><loc>https://example.com/account</loc></url></urlset>'),
    }
