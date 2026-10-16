"""One derived request inventory; original evidence and identities stay intact.

HTTP observation data, never archive status or a detector label, establishes a
current response. Reused parent observations retain their original timestamps.
"""
import hashlib
import json
import re
from collections import defaultdict
from urllib.parse import parse_qsl, urljoin, urlsplit

from .config import normalize_url, request_url, ScanConfig
from .scope import ScopePolicy


def request_identity(url, method="UNKNOWN", context="unauthenticated"):
    return hashlib.sha256(json.dumps([request_url(url), method.upper(), context], ensure_ascii=True).encode()).hexdigest()


def observation_request(kind, data):
    """Use the same identity rules when collecting and attaching evidence."""
    method = data.get("method", "GET" if kind == "http" else "UNKNOWN")
    # RFC method tokens can contain punctuation (for example M-SEARCH).
    # Invalid metadata stays attached to UNKNOWN; raw data is never discarded.
    if not isinstance(method, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}", method):
        method = "UNKNOWN"
    context = data.get("authorization_context", "unauthenticated")
    if not isinstance(context, str):
        context = json.dumps(context, sort_keys=True)
    return method.upper(), context


def decode(value):
    try:
        result = json.loads(value)
        return result if isinstance(result, dict) else {}
    except (ValueError, TypeError):
        return {}


def normalize_evidence(store):
    urls = {r["url"]: r for r in store.rows("urls")}
    observations = defaultdict(list)
    histories = defaultdict(list)
    parameters = defaultdict(list)
    findings = defaultdict(list)
    dns = defaultdict(list)
    infra = defaultdict(list)
    technologies = defaultdict(list)
    artifacts = {r["hash"]: r for r in store.rows("artifacts")}
    for row in store.rows("observations"):
        try:
            key = request_url(row["subject"])
        except ValueError:
            continue
        # A host-only DNS/provider observation is not a fabricated HTTPS endpoint.
        if not row["subject"].startswith(("http://", "https://")):
            continue
        observations[key].append((row, decode(row["data"])))
    for row in store.rows("historical_urls"):
        try:
            histories[request_url(row["url"])].append(row)
        except ValueError:
            continue
    for row in store.rows("parameters"):
        parameters[row["url"]].append(row)
    for row in store.rows("findings"):
        findings[row["subject"]].append(row["fingerprint"])
    for row in store.rows("dns"):
        dns[row["host"]].append(row)
    for row in store.rows("infrastructure"):
        infra[row["host"]].append(row)
    for row in store.rows("technologies"):
        technologies[row["subject"]].append({k: row[k] for k in ("identity", "name", "version", "confidence")})
    policy = ScopePolicy(ScanConfig.model_validate(store.meta("config")).scope) if store.meta("config") else None
    synthetic = store.meta("synthetic", False) or (store.meta("config", {}).get("mode") == "demo")
    # Exact wire requests can have several fragment/original spellings; retain all.
    grouped = defaultdict(list)
    for row in urls.values():
        try:
            grouped[request_url(row["url"])].append(row)
        except ValueError:
            continue
    normalized = []
    for url, rows in sorted(grouped.items()):
        parsed = urlsplit(url)
        evidence = observations[url]
        identities = set()
        for obs, data in evidence:
            if obs["kind"] in {"http", "inferred_endpoint", "form"}:
                identities.add(observation_request(obs["kind"], data))
        if any(r["status"] is not None for r in rows) and not any(o["kind"] == "http" for o, _ in evidence):
            identities.add(("GET", "unauthenticated"))
        if not identities:
            identities.add(("UNKNOWN", "unauthenticated"))
        for method, context in sorted(identities):
            refs, current, prior, errors, inferred, redirects, soft_errors = [], [], [], [], [], [], []
            originals = {r["url"] for r in rows}
            sources = {r["source"] for r in rows}
            discovery_sources = set(sources)
            signals = set()
            for obs, data in evidence:
                if obs["kind"] in {"http", "inferred_endpoint", "form"} and observation_request(obs["kind"], data) != (method, context):
                    continue
                ref = {"table": "observations", "id": obs["id"], "source": obs["source"], "kind": obs["kind"], "time": obs["time"]}
                if data.get("hash"):
                    ref["hash"] = data["hash"]
                    if data["hash"] in artifacts:
                        ref["artifact"] = artifacts[data["hash"]]["path"]
                if data.get("artifact"):
                    ref["tool_capture"] = data["artifact"]
                refs.append(ref)
                sources.add(obs["source"])
                if obs["kind"] in {"discovery", "inferred_endpoint", "historical-discovery"}:
                    discovery_sources.add(obs["source"])
                if isinstance(data.get("original_url"), str):
                    originals.add(data["original_url"])
                if obs["kind"] == "http" and type(data.get("status")) is int and 100 <= data["status"] <= 599:
                    observed = {"status": data["status"], "hash": data.get("hash"), "bytes": data.get("bytes"),
                        "truncated": bool(data.get("truncated")), "time": obs["time"], "source": obs["source"],
                        "observation_id": obs["id"], "content_type": data.get("headers", {}).get("content-type", "").split(";", 1)[0].strip().lower(),
                        "location": data.get("headers", {}).get("location"), "response_features": data.get("response_features", {})}
                    (prior if obs["source"].startswith("parent:") else current).append(observed)
                if obs["kind"] in {"request_error", "parse_error", "invalid_reference"}:
                    errors.append({"id": obs["id"], **data})
                if obs["kind"] == "inferred_endpoint":
                    inferred.append({"id": obs["id"], **data})
                if obs["kind"] == "soft-error-similarity":
                    soft_errors.append((obs, data))
                if obs["kind"] == "historical-discovery":
                    signals.add("historical")
                if obs["kind"] == "unresolved_expression":
                    signals.add("unresolved")
            latest = max(current, key=lambda r: (r["time"], r["observation_id"]), default=None)
            prior_latest = max(prior, key=lambda r: (r["time"], r["observation_id"]), default=None)
            for obs, data in soft_errors:
                # Older records encoded the body hash only in their identity.
                digest = data.get("hash") or (obs.get("identity") or "").rsplit(":", 1)[-1]
                if latest and not obs["source"].startswith("parent:") and re.fullmatch(r"[0-9a-f]{64}", str(digest)) and digest == latest["hash"]:
                    signals.add("soft-404")
            legacy = None
            if not current and not prior and method == "GET" and context == "unauthenticated":
                summary = next((r for r in rows if r["status"] is not None), None)
                if summary:
                    legacy = {"status": summary["status"], "hash": summary["hash"], "bytes": summary["bytes"], "time": summary["time"], "content_type": summary["content_type"], "source": summary["source"]}
                    if summary["source"].startswith("parent:"):
                        prior_latest, legacy = legacy, None
            current_summary = latest or legacy
            status = current_summary["status"] if current_summary else None
            title = next((r["title"] for r in rows if r["title"] and (current_summary or prior_latest) and r["hash"] == (current_summary or prior_latest).get("hash")), "")
            content_type = (current_summary or prior_latest or {}).get("content_type") or ""
            allowed, reason = policy.decision(url) if policy else (all(r["state"] != "external-reference" for r in rows), "saved inventory scope")
            historical = histories[url]
            if historical:
                signals.add("historical")
            if status is None:
                reachability = "previously-observed" if prior_latest else "historical-only" if "historical" in signals else "inferred-only" if inferred else "unobserved"
            else:
                reachability = "restricted" if status in {401, 403} else "redirect-only" if 300 <= status < 400 else "error-response" if status >= 400 else "observed"
            if not allowed:
                reachability = "out-of-scope"
            if current_summary and current_summary.get("truncated"):
                signals.add("truncated")
            if len({(r["status"], r["hash"]) for r in current}) > 1:
                signals.add("conflicting-observations")
            body_hash = (current_summary or prior_latest or {}).get("hash")
            normalized.append({
                "identity": request_identity(url, method, context), "url": url, "original_urls": sorted(originals),
                "host": parsed.hostname, "scheme": parsed.scheme, "port": parsed.port or (443 if parsed.scheme == "https" else 80),
                "explicit_port": parsed.port is not None, "path": parsed.path, "query": parsed.query,
                "query_pairs": parse_qsl(parsed.query, keep_blank_values=True), "method": method, "authorization_context": context,
                "sources": sorted(sources), "discovery_sources": sorted(discovery_sources), "allowed": allowed, "scope_reason": reason, "current_status": status,
                "reachability": reachability, "current_http": current, "prior_http": prior, "legacy_summary": legacy,
                "historical": historical, "historical_statuses": sorted({r["archive_status"] for r in historical}),
                "title": title, "content_type": content_type, "body_hash": body_hash,
                "body_bytes": (current_summary or prior_latest or {}).get("bytes"), "observed_at": (current_summary or prior_latest or {}).get("time"),
                "redirect_chain": redirects, "final_observed_destination": None, "evidence": refs,
                "parameters": [p for r in rows for p in parameters[r["url"]]], "inferred_endpoints": inferred,
                "dns": dns[parsed.hostname], "infrastructure": infra[parsed.hostname], "technologies": technologies[url],
                "finding_ids": sorted({f for r in rows for f in findings[r["url"]]}),
                "signals": sorted(signals), "errors": errors, "synthetic": synthetic,
                "validation_state": "observed" if latest else "legacy-summary" if legacy else "unvalidated",
                "potential_impact": "unassessed", "vulnerability_severity": "unassessed",
            })
    # Follow recorded redirect observations only. Never transfer destination status
    # to the origin, and never resolve/fetch a URL while processing evidence.
    lookup = {(r["url"], r["method"], r["authorization_context"]): r for r in normalized}
    for record in normalized:
        current = record
        seen = set()
        for _ in range(20):
            replies = current["current_http"]
            last = max(replies, key=lambda r: (r["time"], r["observation_id"]), default=None)
            if not last or not 300 <= last["status"] < 400 or not last["location"] or current["url"] in seen:
                break
            seen.add(current["url"])
            try:
                destination = normalize_url(urljoin(current["url"], last["location"]))
            except ValueError:
                record["signals"] = sorted(set(record["signals"]) | {"invalid-redirect"})
                break
            permitted = policy.decision(destination)[0] if policy else False
            record["redirect_chain"].append({"url": current["url"], "status": last["status"], "destination": destination, "allowed": permitted, "observation_id": last["observation_id"]})
            if not permitted:
                record["signals"] = sorted(set(record["signals"]) | {"out-of-scope-redirect"})
                break
            current = lookup.get((request_url(destination), "GET", record["authorization_context"]))
            if not current or current["current_status"] is None:
                break
            if not 300 <= current["current_status"] < 400:
                record["final_observed_destination"] = {"url": current["url"], "status": current["current_status"], "time": current["observed_at"]}
                break
    with store.conn:
        store.conn.execute("DELETE FROM normalized_records")
        store.conn.executemany("INSERT INTO normalized_records VALUES(?,?,?,?,?)", [(r["identity"], r["url"], r["method"], r["authorization_context"], json.dumps(r)) for r in normalized])
    store.stage("normalization", "completed", "Request identities, original evidence, methods, contexts and historical/current observations remain separate")
    return normalized
