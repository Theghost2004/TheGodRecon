"""Versioned, configurable review priority; never vulnerability severity."""
import json
import hashlib
import re
from urllib.parse import urlsplit, unquote

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

STATIC_EXTENSIONS = re.compile(r"\.(?:css|less|scss|woff2?|ttf|otf|eot|png|jpe?g|gif|webp|avif|ico|svg|mp[34]|webm|pdf|zip|gz|js|mjs|map)$", re.I)


def classify_route(url, mime=""):
    """Paths carry route semantics; filenames and query text do not grant them."""
    path = unquote(urlsplit(url).path).lower()
    mime = mime.split(';', 1)[0].strip().lower()
    static = bool(STATIC_EXTENSIONS.search(path) or mime in {
        "text/css", "application/javascript", "text/javascript", "application/pdf",
        "application/octet-stream"} or mime.startswith(("image/", "font/", "audio/", "video/")))
    if static:
        return "static", True
    if re.search(r"(?:^|/)(?:analytics|telemetry|tracking|beacon|pixel)(?:/|$)", path):
        return "tracking", False
    return next((name for name, pattern in CATEGORIES if re.search(pattern, path)), "other"), False


def source_family(source):
    while source.startswith('parent:'):
        source = source.removeprefix('parent:')
    if source.startswith('wordlist:'):
        return 'dictionary-proposal'
    if source == 'observed-api-prefix':
        return 'evidence-supplement'
    if source == 'parent-candidate':
        return None  # copied evidence is not an independent discovery
    if source in {'seed','link','script','redirect','bounded-baseline','exposure-profile-v1','form-action','robots-sitemap','sitemap'}:
        return 'native-collection'
    if source in {'inferred_endpoint','inferred_endpoint_non_get','tree-sitter','jsluice','source_map'}:
        return 'static-analysis'
    return source


SIGNATURE_RULES = {"git-head", "environment-config", "directory-index", "debug-surface", "api-docs"}


def prioritize(store, settings):
    from ..normalization import normalize_evidence, decode
    from ..config import GroupingSettings
    from .grouping import signature
    from collections import defaultdict
    records = normalize_evidence(store)
    findings = {f["fingerprint"]: f for f in store.rows("findings")}
    candidates = []
    weights = settings.weights
    grouping = GroupingSettings.model_validate(store.meta("config", {}).get("grouping", {}))
    for record in records:
        url = record["url"]
        status = record["current_status"]
        category, static = classify_route(url, record["content_type"])
        observed = status is not None
        successful = observed and (200 <= status < 300 or status in {401, 403})
        signals = set(record["signals"])
        reasons, penalties = [], []
        strong = []
        for key in record["finding_ids"]:
            finding = findings.get(key)
            if not finding or finding["rule"] not in SIGNATURE_RULES or finding["validation"] == "dismissed":
                continue
            evidence = decode(finding["evidence"])
            if static and finding["rule"] not in {"git-head", "environment-config"}:
                continue
            if status == 200 and evidence.get("hash") == record["body_hash"] and evidence.get("status") == status:
                strong.append(finding)
        replies = record["current_http"]
        last = max(replies, key=lambda r: (r["time"], r["observation_id"]), default={})
        password_form = last.get("response_features", {}).get("password_form", False) and successful
        families = {f for s in record["discovery_sources"] if (f := source_family(s))}
        meaningful = category not in {"other", "static", "tracking", "documentation"}
        if password_form and not static:
            category, meaningful = "authentication", True
        if strong:
            category = "potential-exposure"
        specific_exposure = any(f["rule"] in {"git-head", "environment-config"} for f in strong)
        documentation = bool(strong) and all(f["rule"] == "api-docs" or (f["rule"] == "debug-surface" and "swagger-ui" in decode(f["evidence"]).get("excerpt", "").lower()) for f in strong)
        if documentation:
            category = "documentation"
        inferred = bool(record["inferred_endpoints"])
        if category == "other" and inferred:
            category = "javascript-derived"
        factors = {"base": 1, "route": int(meaningful), "observed": int(observed),
                   "restricted": int(status in {401,403} and meaningful),
                   "sources": int(len(families) > 1 and (meaningful or bool(strong))),
                   "parameters": int(bool(record["parameters"]) and meaningful),
                   "technology": int(meaningful and any(t["confidence"] == "high" for t in record["technologies"])),
                   "finding": int(bool(strong) or password_form), "duplicate_penalty": -int(static and not strong)}
        components = {k: n*weights[k] for k, n in factors.items() if n}
        labels = {"base": "Inventory lead", "route": "Exact path segments describe application functionality",
                  "observed": "Current HTTP response recorded", "restricted": "Restricted application surface; access control is not proven broken",
                  "sources": "Corroborated across independent source families (one capped contribution)",
                  "parameters": "Associated parameter names retained", "technology": "High-confidence relevant technology context",
                  "finding": "Current bounded response signature" if strong else "Observed password form", "duplicate_penalty": "Low-value static inventory"}
        reasons += [f"{labels[k]} ({v:+d})" for k,v in components.items()]
        score = sum(components.values())
        if strong:
            # Evidence specificity outranks names even on otherwise static paths.
            evidence_boost = 25 if any(f["rule"] in {"git-head", "environment-config"} for f in strong) else 10
            score += evidence_boost
            components["response_signature"] = evidence_boost
            reasons.append("Preserved matching body: " + ", ".join(sorted({f["rule"] for f in strong})))
            if documentation:
                score = min(score, 25)
                penalties.append("Published documentation needs business context; no sensitive disclosure established")
            elif not specific_exposure and not password_form:
                score = min(score, 55)
                penalties.append("General response marker requires manual validation of actual functionality")
        if static and not strong:
            penalties.append("Static asset; filename keywords are not application functionality")
            score = min(score, 10)
        if category in {"tracking", "documentation"} and not strong:
            penalties.append("Tracking/documentation inventory; limited immediate investigation value")
            score = min(score, 20)
        path = urlsplit(url).path
        if re.search(r"(?:^|/)(?:vendor|node_modules|dist|build)(?:/|$)|[.-][0-9a-f]{8,}[.-]", path, re.I) and not strong:
            penalties.append("Library or generated build asset")
            score = min(score, 15)
        if observed and 300 <= status < 400:
            penalties.append("Redirect response only; destination status is separate")
            score = min(score, 20 if meaningful and record["final_observed_destination"] else 10)
        if observed and status >= 400 and status not in {401,403}:
            penalties.append("HTTP error response does not demonstrate intended functionality")
            score = min(score, 10)
        generic_title = re.fullmatch(r"\s*(?:404(?: not found)?|not found|page not found|missing(?: page)?|error|internal server error|welcome to nginx[!]?|default page)\s*", record["title"], re.I)
        if "soft-404" in signals or generic_title:
            penalties.append("Soft 404 or generic fallback/error page")
            signals.add("generic-error")
            score = min(score, 5)
        if record["body_bytes"] == 0 and status not in {401,403} and not strong:
            penalties.append("Empty response has little supporting context")
            score = min(score, 15)
        if not observed:
            penalties.append("Current reachability unverified: " + record["reachability"])
            score = min(score, 30 if inferred else 20)
        dictionary_only = bool(families) and families <= {'dictionary-proposal','evidence-supplement'} and not inferred and not record['historical'] and not record['prior_http']
        if not observed and dictionary_only:
            penalties.append("Untested dictionary/prefix proposal; names alone do not justify analyst shortlist placement")
            score = min(score, 5)
        if "conflicting-observations" in signals or "truncated" in signals:
            penalties.append("Conflicting or incomplete responses require manual comparison")
            score = min(score, 40)
        if record["synthetic"]:
            penalties.append("Synthetic/demo evidence")
            score = min(score, 5)
        if not record["allowed"]:
            penalties.append("Outside current scope; no active follow-up authorized")
            score = 0
        # Coarse bands avoid implying a calibrated vulnerability probability.
        score = max(0, min(100, 5 * (score // 5)))
        confidence = "high" if record["current_http"] and successful and (specific_exposure or password_form) else "medium" if observed else "low" if inferred or record["historical"] or record["prior_http"] else "unknown"
        if signals & {"soft-404", "generic-error", "conflicting-observations", "truncated"} or record["synthetic"]:
            confidence = "low"
        tier = "high-interest" if score >= 60 and confidence in {"high", "medium"} and successful and (meaningful or strong) else "manual-review" if score >= 20 and (meaningful or inferred or strong or category == "documentation") else "inventory"
        family = signature(url, grouping, record["method"], record["authorization_context"])[0]
        next_check = "Inspect the saved response and scope before any permitted manual request."
        if strong:
            next_check = "Inspect the exact saved signature and intended publication; validate impact manually without downloading further sensitive files."
        elif status in {401,403}:
            next_check = "Review expected access requirements and authorized roles; the denial itself is not an access-control failure."
        elif inferred:
            next_check = "Inspect the JavaScript source location and request method; validate reachability only within authorized scope."
        elif record["reachability"] in {"historical-only", "previously-observed"}:
            next_check = "Review the original collection date; obtain fresh authorized evidence before treating this as live."
        candidate = {**record, "classification": category, "score": score, "review_priority": "High" if tier == "high-interest" else "Review" if tier == "manual-review" else "Low",
            "tier": tier, "evidence_confidence": confidence, "endpoint_interest": "meaningful" if meaningful or strong else "low",
            "potential_impact": "requires manual assessment" if strong else "unassessed", "vulnerability_severity": "unassessed",
            "reasons": reasons + penalties, "score_components": components, "noise_reasons": penalties,
            "next_check": next_check, "rule_version": 2, "route_family": family, "content_group": None,
            "group_id": record["identity"], "group_size": 1, "group_members": [record["identity"]], "representative": True}
        candidates.append(candidate)
    # Content groups describe exact bytes only. They do not imply equivalent
    # authorization, request parameters, methods or application operations.
    content_groups = defaultdict(list)
    for candidate in candidates:
        if candidate["body_hash"]:
            key = json.dumps([candidate["scheme"], candidate["host"], candidate["port"], candidate["explicit_port"], candidate["method"], candidate["authorization_context"], candidate["current_status"], candidate["body_hash"]])
            candidate["content_group"] = hashlib.sha256(key.encode()).hexdigest()
            content_groups[candidate["content_group"]].append(candidate["identity"])
    groups = defaultdict(list)
    known_methods = defaultdict(list)
    for c in candidates:
        if c["method"] != "UNKNOWN":
            known_methods[(c["url"], c["authorization_context"])].append(c)
    for candidate in candidates:
        content_members = content_groups.get(candidate["content_group"], [])
        candidate["content_group_size"] = len(content_members)
        candidate["content_members"] = content_members if content_members and candidate["identity"] == content_members[0] else []
        if candidate["method"] == "UNKNOWN" and known_methods.get((candidate["url"], candidate["authorization_context"])):
            candidate.update(representative=False, group_members=[])
            continue
        # Hide repeated family cards, not request identities. Different query
        # values/methods/contexts/statuses and evidence signatures remain separate.
        key = [candidate["route_family"], candidate["query"], candidate["authorization_context"], candidate["current_status"], candidate["classification"], candidate["tier"],
               candidate["body_hash"] if candidate["classification"] == "potential-exposure" else None]
        groups[json.dumps(key)].append(candidate)
    for key, members in groups.items():
        members.sort(key=lambda r: (-r["score"], r["url"], r["identity"]))
        group_id = hashlib.sha256(key.encode()).hexdigest()
        for member in members:
            member.update(group_id=group_id, group_size=len(members), group_members=[r["identity"] for r in members] if member is members[0] else [], representative=member is members[0])
    # Some tools emit both a concrete request and a methodless string literal.
    # Keep the UNKNOWN identity and evidence, but do not make it a second card
    # alongside the known method(s). Distinct known methods remain independent.
    representatives = {c["group_id"]: c for c in candidates if c["representative"]}
    for c in candidates:
        related = known_methods.get((c["url"], c["authorization_context"]), [])
        if c["method"] == "UNKNOWN" and related:
            best = min(related, key=lambda r: (-r["score"], r["identity"]))
            representative = representatives[best["group_id"]]
            c.update(group_id=representative["group_id"], representative=False, related_request_identities=sorted(r["identity"] for r in related))
            representative["group_members"].append(c["identity"])
            representative["group_size"] += 1
            c["reasons"].append("Methodless evidence correlated with known requests; exact identity retained")
    for c in candidates:
        c["group_size"] = representatives[c["group_id"]]["group_size"]
    with store.conn:
        store.conn.execute("DELETE FROM investigation_candidates")
        store.conn.execute("DELETE FROM endpoint_priority")
        for c in sorted(candidates, key=lambda r: (-r["score"], r["url"], r["identity"])):
            store.conn.execute("INSERT INTO investigation_candidates VALUES(?,?,?,?,?,?)", (c["identity"], c["url"], c["classification"], c["score"], c["tier"], json.dumps(c)))
            # Legacy URL-level export remains a compatibility summary; request
            # methods/contexts live in the normalized and candidate exports.
            store.conn.execute("INSERT OR IGNORE INTO endpoint_priority VALUES(?,?,?,?,?,?,?)", (c["url"], c["classification"], c["score"], c["evidence_confidence"], json.dumps(c["reasons"]), json.dumps({"components": c["score_components"], "weights": weights, "tier": c["tier"], "interpretation": "manual review priority, never severity"}), 2))
    store.stage("priority", "completed", "Evidence-aware rule version 2; coarse review bands, preserved exact members and separate reachability/confidence/severity")
    return candidates
