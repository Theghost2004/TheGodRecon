"""Permanent tool IDs and reviewed execution boundaries."""
from dataclasses import dataclass


@dataclass(frozen=True)
class ToolSpec:
    id: int
    name: str
    version: str
    capability: str
    risk: str
    dependencies: tuple[str, ...] = ()
    fallback: tuple[str, ...] = ()
    policy_reason: str = ""


REGISTRY = (
    ToolSpec(1, "subfinder", "2.17.0", "passive host discovery", "provider"),
    ToolSpec(2, "urlfinder", "0.0.3", "historical URL discovery", "provider"),
    ToolSpec(3, "dnsx", "1.3.1", "DNS record enrichment", "active", ("discovery",), ("dns",),
             "Independent resolver retries/queries cannot be reserved in the shared DNS budget or restricted by a verified cross-platform egress sandbox"),
    ToolSpec(4, "httpx", "1.12.0", "HTTP service probing", "active", ("dns",), ("http",),
             "Independent DNS/connections bypass pinned public addresses and shared request/response limits; an HTTPS CONNECT proxy cannot enforce excluded paths"),
    ToolSpec(5, "katana", "1.8.0", "bounded web crawling", "active", ("http",), ("http", "crawl"),
             "Crawler subrequests cannot jointly enforce GET-only actions, excluded HTTPS paths, DNS pinning and shared remaining budgets without verified egress isolation"),
    ToolSpec(6, "jsluice", "0ddfab153e060a9eeaded4d8669233f7c071e7e4", "local JavaScript analysis", "offline", ("artifacts",), ("analysis",)),
    ToolSpec(7, "gitleaks", "8.30.1", "local redacted secret detection", "offline", ("artifacts",), ("analysis",)),
    ToolSpec(8, "nuclei", "3.11.1", "reviewed exposure checks", "active", ("http",), ("http", "checks"),
             "Template allowlisting alone cannot pin subprocess destinations or account for every request, redirect and decompressed response; only native reviewed GET checks execute"),
)
BY_NAME = {tool.name: tool for tool in REGISTRY}
BY_ID = {tool.id: tool for tool in REGISTRY}
PRESETS = {"quad": (1, 2, 3, 4), "passive": (1, 2), "offline": (6, 7), "web": (4, 5), "all": tuple(BY_ID)}
ENRICHMENTS = ("asn", "wayback", "tech", "dedup", "priority")


def execution_status(info) -> str:
    if BY_NAME[info.name].policy_reason:
        return "blocked-by-policy"
    if not info.available:
        return "unavailable"
    return "ready" if info.supported else "incompatible"


NATIVE_COVERAGE = {
    "subfinder": "Seed and captured-reference inventory only; no equivalent passive native subdomain enumeration",
    "urlfinder": "Explicit Wayback/CDX enrichment can supply history; archived URLs are not current observations",
    "dnsx": "Bounded native address resolution and DNS observations; no full dnsx record-enumeration parity",
    "httpx": "Scoped GET requests, response headers/body/title, pinned destinations; no extra port or protocol sweep",
    "katana": "HTML/base links, scripts, sitemap indexes and code-derived GET routes; no browser or scripted actions",
    "jsluice": "Tree-sitter literal routes, methods and embedded source maps; dynamic expressions remain unresolved",
    "gitleaks": "Local secret syntax patterns; fewer rules than Gitleaks and no credential validation",
    "nuclei": "Two extra GET probes (.git/HEAD and .env), plus bounded signatures on captured responses; no Nuclei templates or exploitation",
}
