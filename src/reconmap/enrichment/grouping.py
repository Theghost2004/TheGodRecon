"""Analytical route families never substitute for exact request identities."""
import hashlib
import json
import re
from collections import Counter
from urllib.parse import parse_qsl, urlsplit


def signature(url, settings, method="UNKNOWN"):
    parsed = urlsplit(url)
    segments = parsed.path.split("/")
    for index, segment in enumerate(segments):
        if settings.numeric_segments and re.fullmatch(r"[0-9]+", segment):
            segments[index] = "{integer}"
        elif settings.uuid_segments and re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", segment):
            segments[index] = "{uuid}"
    family = "/".join(segments)
    # Repeated parameter names/counts remain significant. Query ordering/values,
    # fragments, explicit ports, path case and encoding remain in exact URLs.
    names = sorted(Counter(k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)).items())
    query = names if settings.query_names else parsed.query
    data = [parsed.scheme, parsed.netloc, family, query, method]
    return json.dumps(data, ensure_ascii=True), family, names


def group_urls(store, settings):
    methods = {}
    sources = {}
    for row in store.rows("observations"):
        if row["kind"] == "inferred_endpoint":
            method = json.loads(row["data"]).get("method") or "UNKNOWN"
            methods.setdefault(row["subject"], set()).add(method)
        if row["kind"] == "discovery":
            sources.setdefault(row["subject"], set()).add(row["source"])
    with store.conn:
        store.conn.execute("DELETE FROM url_group_members")
        store.conn.execute("DELETE FROM url_groups")
        for row in store.rows("urls"):
            known = methods.get(row["url"], set())
            if row["status"] is not None:
                known = known | {"GET"}
            for method in sorted(known or {"UNKNOWN"}):
                key, family, names = signature(row["url"], settings, method)
                group_id = hashlib.sha256(key.encode()).hexdigest()
                store.conn.execute("INSERT OR IGNORE INTO url_groups VALUES(?,?,?,?,?,?)", (group_id, key, family, json.dumps(names), method, 1))
                for source in sorted(sources.get(row["url"], {row["source"]})):
                    store.conn.execute("INSERT OR IGNORE INTO url_group_members VALUES(?,?,?)", (group_id, row["url"], source))
    store.stage("dedup", "completed", "Exact scheduling identities preserved; numeric/UUID route families and parameter multiplicity are analytical only")
