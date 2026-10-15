"""Separate, pinned provider GET path; never broadens target authorization."""
import asyncio
import hashlib
import json
import socket
import time
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit

import aiohttp
from aiohttp.abc import AbstractResolver

from ..config import Scope
from ..scope import ScopePolicy

ALLOWED = {
    "web.archive.org": {"/cdx/search/cdx"},
    "stat.ripe.net": {"/data/network-info/data.json", "/data/as-overview/data.json"},
}


def validate_provider_url(url):
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.username is not None or parsed.password is not None or parsed.port not in (None, 443) or parsed.fragment or parsed.path not in ALLOWED.get(parsed.hostname, set()):
        raise ValueError("Provider URL is outside the reviewed HTTPS endpoint allowlist")
    return parsed


class ProviderResolver(AbstractResolver):
    async def resolve(self, host, port=443, family=socket.AF_INET):
        if host not in ALLOWED or port != 443:
            raise OSError("Provider destination denied")
        answers = await asyncio.get_running_loop().getaddrinfo(host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
        policy = ScopePolicy(Scope(hosts=[host]))
        if not answers or any(not policy.ip_allowed(a[4][0]) for a in answers):
            raise OSError("Provider DNS resolved to a prohibited address")
        return [{"hostname": host, "host": a[4][0], "port": port, "family": a[0], "proto": a[2], "flags": socket.AI_NUMERICHOST} for a in answers]

    async def close(self):
        pass


class ProviderClient:
    def __init__(self, scanner):
        self.scanner = scanner
        self.session = None

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(resolver=ProviderResolver(), use_dns_cache=False, force_close=True, limit=1)
        self.session = aiohttp.ClientSession(connector=connector, auto_decompress=False, trust_env=False, cookie_jar=aiohttp.DummyCookieJar(),
                                           headers={"User-Agent": "reconmap/3 metadata-only", "Accept-Encoding": "identity"})
        return self

    async def __aexit__(self, *unused):
        await self.session.close()

    async def get(self, url):
        from ..engine import BudgetStop, bounded_response
        scanner = self.scanner
        validate_provider_url(url)
        if scanner.config.mode in {"demo", "offline"}:
            raise ValueError("Provider traffic is disabled in demo/offline execution")
        key = hashlib.sha256(url.encode()).hexdigest()
        cached = scanner.store.conn.execute("SELECT * FROM provider_cache WHERE key=?", (key,)).fetchone()
        if cached and scanner.config.providers.cache_seconds > 0 and min(cached["expires"], cached["collected"] + scanner.config.providers.cache_seconds) > time.time():
            return json.loads(cached["data"]), cached["collected"], True
        for attempt in range(scanner.config.budgets.retries + 1):
            scanner.scheduler.check_time()
            scanner.check_disk_budget(scanner.config.budgets.response_bytes)
            count = int(scanner.store.meta("provider_requests", 0))
            if count >= scanner.config.providers.requests:
                raise BudgetStop("owned provider request cap reached")
            delay = max(0.0, float(scanner.store.meta("provider_next_wall", 0)) - time.time())
            if delay >= scanner.scheduler.remaining():
                raise BudgetStop("Provider rate/Retry-After wait exceeds remaining time")
            if delay:
                await asyncio.sleep(delay)
            scanner.store.set_meta("provider_requests", count + 1)
            scanner.store.set_meta("provider_next_wall", time.time() + 1/scanner.config.providers.rps)
            timeout = min(scanner.config.budgets.timeout, scanner.config.budgets.provider_seconds, scanner.scheduler.remaining())
            if timeout <= 0:
                raise BudgetStop("run time cap reached")
            async with self.session.get(url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
                if response.status in {429, 500, 502, 503, 504}:
                    wait = min(60, 2**(attempt + 1))
                    retry = response.headers.get("Retry-After", "")
                    if retry.isdigit():
                        wait = max(wait, int(retry))
                    elif retry:
                        try: wait = max(wait, parsedate_to_datetime(retry).timestamp()-time.time())
                        except (ValueError, OverflowError, TypeError): pass
                    scanner.store.set_meta("provider_next_wall", time.time() + wait)
                    if attempt < scanner.config.budgets.retries:
                        continue
                if response.status != 200:
                    raise ValueError(f"Provider returned HTTP {response.status}; redirects are not followed")
                result = await bounded_response(response, scanner.config.budgets.response_bytes)
                if result.truncated:
                    raise ValueError("Provider response exceeds bounded output cap")
                text = result.body.decode("utf-8")
                collected = time.time()
                scanner.store.execute("INSERT OR REPLACE INTO provider_cache VALUES(?,?,?,?,?)", (key, urlsplit(url).hostname, collected, collected + scanner.config.providers.cache_seconds, json.dumps(text)))
                return text, collected, False
        raise ValueError("Provider retry limit reached")
