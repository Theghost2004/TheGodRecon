"""RIPE Stat observations from already observed public addresses only."""
import ipaddress
import json
from urllib.parse import urlencode

import aiohttp

from .providers import ProviderClient
from ..security import redact
from ..storage import timestamp


def parse_network(text, address):
    data = json.loads(text)
    if not isinstance(data, dict) or data.get("status") != "ok" or not isinstance(data.get("data"), dict):
        raise ValueError("Invalid RIPE Stat response")
    payload = data["data"]
    prefix = ipaddress.ip_network(payload.get("prefix", ""))
    if ipaddress.ip_address(address) not in prefix:
        raise ValueError("RIPE prefix does not contain the observed address")
    asns = payload.get("asns")
    if not isinstance(asns, list) or len(asns) > 100 or any(not str(v).isdigit() or not 1 <= int(v) <= 4294967295 for v in asns):
        raise ValueError("Invalid ASN list")
    return str(prefix), [str(v) for v in asns]


def parse_organization(text, asn):
    data = json.loads(text)
    payload = data.get("data") if isinstance(data, dict) else None
    if not isinstance(data, dict) or data.get("status") != "ok" or not isinstance(payload, dict) or str(payload.get("resource", "")).upper().removeprefix("AS") != asn or not isinstance(payload.get("holder"), str):
        raise ValueError("Invalid RIPE AS overview identity")
    return payload["holder"][:1000]


async def enrich_asn(scanner):
    if scanner.config.mode in {"demo", "offline"} or scanner.config.scope.lab:
        scanner.store.stage("asn", "skipped", "Public-IP provider enrichment is disabled in demo/offline/loopback lab")
        return
    addresses = {}
    for row in scanner.store.rows("dns"):
        if row["kind"] not in {"A", "AAAA"} or not scanner.policy.host_allowed(row["host"]):
            continue
        try:
            if scanner.policy.ip_allowed(row["address"]):
                addresses.setdefault(row["address"], set()).add(row["host"])
        except ValueError:
            continue
    if not addresses:
        scanner.store.stage("asn", "partial", "No observed authorized public A/AAAA addresses; passive intelligence does not trigger target DNS")
        return
    failures = []
    organizations = {}
    scanner.store.stage("asn", "running", "RIPE Stat metadata; ASN relationships never grant scope")
    async with ProviderClient(scanner) as client:
        for address, hosts in sorted(addresses.items())[:scanner.config.budgets.provider_results]:
            for host in hosts:
                scanner.store.execute("INSERT OR IGNORE INTO infrastructure VALUES(?,?,?,?,?,?,?,?,?)", (host, address, "", "", "", "", "high", "native-dns-observation", timestamp()))
            try:
                text, collected, cached = await client.get("https://stat.ripe.net/data/network-info/data.json?" + urlencode({"resource": address}))
                prefix, asns = parse_network(text, address)
                for asn in asns:
                    if asn not in organizations:
                        overview, _, _ = await client.get("https://stat.ripe.net/data/as-overview/data.json?" + urlencode({"resource": "AS" + asn}))
                        organizations[asn] = parse_organization(overview, asn)
                    organization = organizations[asn]
                    hint = next((label for marker, label in (("AMAZON", "AWS"), ("GOOGLE", "Google Cloud"), ("MICROSOFT", "Azure"), ("CLOUDFLARE", "Cloudflare")) if marker in organization.upper()), "")
                    for host in sorted(hosts):
                        scanner.store.execute("INSERT OR REPLACE INTO infrastructure VALUES(?,?,?,?,?,?,?,?,?)", (host, address, asn, organization, prefix, hint, "medium", "ripe-stat", str(collected)))
                        scanner.store.relate(host, "AS" + asn, "observed-infrastructure-not-authorization", "ripe-stat")
            except (aiohttp.ClientError, OSError, ValueError, TimeoutError, RecursionError) as exc:
                failures.append(redact(f"{address}: {type(exc).__name__}: {exc}"))
    if len(addresses) > scanner.config.budgets.provider_results:
        failures.append("ASN address result cap reached")
    scanner.store.stage("asn", "partial" if failures else "completed", "; ".join(failures[:20]) or "Observed public infrastructure enriched; no scope expansion")
