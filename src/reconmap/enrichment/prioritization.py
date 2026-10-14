"""Versioned, configurable review priority; never vulnerability severity."""
import json
import re
from urllib.parse import urlsplit

CATEGORIES = (
    ("authentication", r"(?:^|/)(?:auth|login|signin|oauth|sso|identity|reset-password)(?:/|$)"),
    ("authorization", r"(?:^|/)(?:permissions|roles|access|acl)(?:/|$)"),
    ("account", r"(?:^|/)(?:account|profile|users|invite)(?:/|$)"),
    ("administration", r"(?:^|/)(?:admin|management|console)(?:/|$)"),
    ("api", r"(?:^|/)(?:api|graphql)(?:/|$)"),
    ("files", r"(?:^|/)(?:upload|download|import|export|files)(?:/|$)"),
    ("payments", r"(?:^|/)(?:payment|payments|billing|checkout)(?:/|$)"),
    ("debug", r"(?:^|/)(?:debug|dev|test|phpinfo)(?:[./]|$)"),
    ("documentation", r"(?:^|/)(?:docs|swagger|openapi)(?:[./]|$)"),
    ("static", r"\.(?:js|css|png|jpg|woff2?|ico|svg)$"),
)


def source_family(source):
    while source.startswith('parent:'):
        source = source.removeprefix('parent:')
    if source == 'parent-candidate':
        return None  # copied evidence is not an independent discovery
    if source in {'seed','link','script','redirect','bounded-baseline','exposure-profile-v1','form-action','robots-sitemap','sitemap'}:
        return 'native-collection'
    if source in {'inferred_endpoint','inferred_endpoint_non_get','tree-sitter','jsluice','source_map'}:
        return 'static-analysis'
    return source


def prioritize(store, settings):
    sources, inferred, findings, parameters = {}, set(), set(), set()
    for row in store.rows("observations"):
        if row["kind"] == "discovery":
            family = source_family(row["source"])
            if family: sources.setdefault(row["subject"], set()).add(family)
        if row["kind"] == "inferred_endpoint": inferred.add(row["subject"])
    for row in store.rows("findings"):
        # A sensitive route name alone is not evidence-backed exposure.
        if row["rule"] not in {"route-lead", "inferred-route-lead"}: findings.add(row["subject"])
    for row in store.rows("parameters"): parameters.add(row["url"])
    tech = {r["subject"] for r in store.rows("technologies")}
    members = {}
    for row in store.rows("url_group_members"): members.setdefault(row["group_id"], set()).add(row["url"])
    duplicates = set().union(*(urls for urls in members.values() if len(urls) > 1)) if members else set()
    weights = settings.weights
    with store.conn:
        store.conn.execute("DELETE FROM endpoint_priority")
        for row in store.rows("urls"):
            url = row["url"]
            path = urlsplit(url).path.lower()
            category = next((name for name, pattern in CATEGORIES if re.search(pattern, path)), "javascript-derived" if url in inferred else "other")
            factors = {"base": 1, "route": int(category not in {"other", "static"}), "observed": int(row["status"] is not None), "restricted": int(row["status"] in {401, 403}), "sources": min(1, max(0, len(sources.get(url, set()))-1)), "parameters": int(url in parameters), "technology": int(url in tech), "finding": int(url in findings), "duplicate_penalty": -int(url in duplicates or category == "static")}
            components = {k: value*weights[k] for k, value in factors.items() if value}
            score = max(0, min(100, sum(components.values())))
            if row["status"] is None:
                score = min(score, 35)
            if row["state"] == "external-reference":
                score = 0
            confidence = "high" if row["status"] is not None else "low" if url in inferred else "unknown"
            reasons = [f"{key}: {value:+d}" for key, value in components.items()]
            if row["status"] is None: reasons.append("Current liveness unverified; score capped at 35")
            if url in duplicates: reasons.append("Analytical duplicate candidate; exact evidence and scheduling retained")
            store.conn.execute("INSERT INTO endpoint_priority VALUES(?,?,?,?,?,?,?)", (url, category, score, confidence, json.dumps(reasons), json.dumps({"components": components, "weights": weights, "interpretation": "review priority, not vulnerability severity"}), settings.version))
    store.stage("priority", "completed", "Explainable version-1 review scores; reachability and detector confidence remain separate")
