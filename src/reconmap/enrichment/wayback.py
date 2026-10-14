"""Bounded CDX metadata collection; never downloads archived content."""
import hashlib
import json
from urllib.parse import urlencode

import aiohttp

from .providers import ProviderClient
from ..config import normalize_url
from ..security import redact
from ..storage import timestamp


def parse_cdx(text):
    decoder = json.JSONDecoder()
    data, end = decoder.raw_decode(text.lstrip())
    tail = text.lstrip()[end:].strip()
    if data == [] and not tail:
        return [], ""
    if not isinstance(data, list) or not data or data[0] != ["timestamp", "original", "statuscode", "mimetype", "digest"]:
        raise ValueError("Unexpected CDX JSON columns")
    records = []
    for row in data[1:]:
        if row == []:
            continue
        if isinstance(row, list) and len(row) == 1 and isinstance(row[0], str):
            if tail:
                raise ValueError("Multiple CDX resume keys")
            tail = row[0]
            continue
        if not isinstance(row, list) or len(row) != 5 or not all(isinstance(v, str) for v in row):
            raise ValueError("Malformed CDX metadata row")
        records.append(dict(zip(data[0], row)))
    if len(tail) > 2048 or any(ord(c) < 32 for c in tail):
        raise ValueError("Invalid CDX pagination token")
    return records, tail


async def collect_wayback(scanner):
    if scanner.config.mode in {"demo", "offline"} or scanner.config.scope.lab:
        scanner.store.stage("wayback", "skipped", "No archive-provider access in demo/offline/loopback lab")
        return
    host = scanner.manifest["host"]
    cursor = scanner.store.meta("wayback:cursor", "")
    completed = scanner.store.meta("wayback:completed", False)
    if completed:
        return
    seen = set()
    count = int(scanner.store.meta("wayback:records", 0))
    scanner.store.stage("wayback", "running", "CDX historical metadata only")
    try:
        async with ProviderClient(scanner) as client:
            for _ in range(scanner.config.providers.wayback_pages):
                query = {"url": host, "matchType": "host", "output": "json", "fl": "timestamp,original,statuscode,mimetype,digest", "collapse": "urlkey", "showResumeKey": "true", "limit": str(min(scanner.config.providers.page_size, scanner.config.budgets.provider_results-count))}
                if count >= scanner.config.budgets.provider_results:
                    scanner.limit("Wayback result cap reached")
                    break
                if cursor:
                    query["resumeKey"] = cursor
                text, collected, cached = await client.get("https://web.archive.org/cdx/search/cdx?" + urlencode(query))
                records, next_cursor = parse_cdx(text)
                for record in records:
                    if count >= scanner.config.budgets.provider_results:
                        scanner.limit("Wayback result cap reached")
                        break
                    original = record["original"]
                    try:
                        url = normalize_url(original)
                        allowed, reason = scanner.policy.decision(url)
                    except ValueError:
                        url, allowed, reason = original[:8192], False, "Malformed historical URL"
                    identity = hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()
                    scanner.store.execute("INSERT OR IGNORE INTO historical_urls VALUES(?,?,?,?,?,?,?,?,?,?,?)", (identity, url, original[:8192], record["timestamp"], record["statuscode"], record["mimetype"], record["digest"], "wayback-cdx", int(allowed), reason, str(collected)))
                    scanner.store.observed(url, "historical-discovery", {"archived_at": record["timestamp"], "current_liveness": "untested", "allowed": allowed, "reason": reason, "cached": cached}, "wayback-cdx", identity="wayback:" + identity)
                    # Even excluded records are retained as provenance; add_url
                    # alone owns request eligibility and all target reservations.
                    scanner.add_url(original, "wayback-cdx")
                    count += 1
                scanner.store.set_meta("wayback:records", count)
                scanner.store.set_meta("wayback:cursor", next_cursor)
                if not next_cursor:
                    scanner.store.set_meta("wayback:completed", True)
                    scanner.store.stage("wayback", "completed", f"{count} historical rows; current liveness remains independent")
                    return
                if next_cursor in seen or next_cursor == cursor:
                    raise ValueError("CDX repeated pagination token")
                seen.add(next_cursor); cursor = next_cursor
        scanner.store.stage("wayback", "partial", "Bounded page/result limit reached; metadata checkpoint retained")
    except (aiohttp.ClientError, OSError, ValueError, TimeoutError, RecursionError) as exc:
        scanner.store.stage("wayback", "partial", redact(f"{type(exc).__name__}: {exc}"))
