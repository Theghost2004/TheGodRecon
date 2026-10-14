"""Dependency ordering, pure plan preview, and shared native execution."""
from dataclasses import asdict, dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit

import aiohttp

from .config import ConfigError, normalize_url
from .scope import ScopePolicy
from .tool_registry import BY_NAME, REGISTRY, execution_status


@dataclass(frozen=True)
class Stage:
    name: str
    dependencies: tuple[str, ...]
    risk: str


GRAPH = (
    Stage("discovery", (), "local"),
    Stage("passive-tools", ("discovery",), "provider"),
    Stage("wayback", ("passive-tools",), "provider"),
    Stage("local-inputs", ("discovery",), "offline"),
    Stage("dns", ("passive-tools", "wayback"), "active"),
    Stage("native-web", ("dns", "local-inputs"), "active"),
    Stage("offline-tools", ("native-web", "local-inputs"), "offline"),
    Stage("asn", ("dns", "native-web"), "provider"),
    Stage("normalization", ("offline-tools", "asn"), "offline"),
)


def stage_order(stages=GRAPH):
    pending = list(stages)
    ordered = []
    done = set()
    while pending:
        ready = next((s for s in pending if set(s.dependencies) <= done), None)
        if ready is None:
            raise ConfigError("Workflow has a cycle or missing dependency")
        ordered.append(ready); done.add(ready.name); pending.remove(ready)
    return ordered


def selected_names(config):
    return [t.name for t in REGISTRY if t.name in config.modules]


def phase_plan(config):
    providers = config.mode not in {"demo", "offline"} and not config.scope.lab
    active = config.mode not in {"passive", "offline", "demo"}
    enabled = {
        "discovery": True,
        "passive-tools": providers and bool({"subfinder", "urlfinder"} & set(config.modules)),
        "wayback": providers and "wayback" in config.enrichments,
        "local-inputs": bool(config.local_inputs) or "analysis" in config.modules,
        "dns": active and bool({"dns", "http"} & set(config.modules)),
        "native-web": config.mode not in {"passive", "offline"} and "http" in config.modules,
        "offline-tools": bool({"jsluice", "gitleaks"} & set(config.modules)),
        "asn": providers and "asn" in config.enrichments,
        "normalization": bool({"tech", "dedup", "priority"} & set(config.enrichments)),
    }
    return [{**asdict(stage), "enabled": enabled[stage.name], "effective_risk": "offline-fixtures" if config.mode == "demo" and stage.risk == "active" else stage.risk} for stage in stage_order()]


def build_plan(config, target, tools):
    target = normalize_url(target)
    allowed, reason = ScopePolicy(config.scope).decision(target)
    if not allowed:
        raise ConfigError("Seed denied by scope: " + reason)
    records = []
    for name in selected_names(config):
        spec = BY_NAME[name]
        info = tools[name]
        status = execution_status(info)
        if (config.mode in {"demo", "offline"} or config.scope.lab) and spec.risk == "provider":
            status = "skipped"
        elif config.mode == "passive" and spec.risk == "active":
            status = "blocked-by-policy"
        records.append({**info.record(), "status": status, "dependencies": list(spec.dependencies), "policy_reason": spec.policy_reason})
    issues = [r for r in records if r["status"] not in {"ready", "skipped"}]
    provider_stages = [n for n in config.enrichments if n in {"asn", "wayback"}]
    return {
        "target": target, "mode": config.mode, "profile": config.profile,
        "selected_tools": records, "execution_order": phase_plan(config),
        "native_modules": [m for m in config.modules if m not in BY_NAME],
        "enrichments": config.enrichments, "scope": config.scope.model_dump(),
        "budgets": config.budgets.model_dump(), "provider_budgets": config.providers.model_dump(),
        "provider_access": provider_stages, "fully_supported": not issues,
        "safe_to_execute": not (config.strict_tools and issues),
        "security": "Direct active subprocesses are blocked. Native fallbacks alone own target requests; provider APIs have a separate pinned allowlist and budget.",
        "input_guidance": "Offline tools require captured/local artifacts; absent inputs are explicitly skipped. No external dependency tool is automatically selected.",
    }


def print_plan(plan):
    print(f"Target: {plan['target']} | mode: {plan['mode']} | safe to execute: {plan['safe_to_execute']}")
    for tool in plan["selected_tools"]:
        print(f"{tool['id']} {tool['name']}: {tool['status']} ({tool['risk']}); {tool['policy_reason'] or tool['reason']}")
    print("Order: " + " -> ".join(s["name"] for s in plan["execution_order"] if s["enabled"]))
    print("Native modules: " + ",".join(plan["native_modules"]))
    print("Enrichments: " + ",".join(plan["enrichments"]))
    import json
    print("Scope: " + json.dumps(plan["scope"], sort_keys=True))
    print("Budgets: " + json.dumps(plan["budgets"], sort_keys=True))
    print("Provider budgets: " + json.dumps(plan["provider_budgets"], sort_keys=True))
    print(plan["input_guidance"])


async def native_web(scanner):
    from .engine import SafeResolver
    if scanner.config.mode in {"passive", "offline"} or "http" not in scanner.config.modules:
        scanner.store.stage("http", "skipped", "No target HTTP in this execution")
        return
    seed = urlsplit(scanner.manifest["target"])
    origin = urlunsplit(seed._replace(path="/", query="", fragment=""))
    if "crawl" in scanner.config.modules:
        import hashlib
        for path in ("robots.txt", "sitemap.xml", "__reconmap_missing_" + hashlib.sha256(scanner.manifest["target"].encode()).hexdigest()[:12]):
            scanner.add_url(urljoin(origin, path), "bounded-baseline")
    if "checks" in scanner.config.modules:
        paths = (".git/HEAD", ".env") if "nuclei" in scanner.config.modules else (".git/HEAD", ".env", "openapi.json", "swagger.json")
        for path in paths:
            scanner.add_url(urljoin(origin, path), "exposure-profile-v1")
    connector = aiohttp.TCPConnector(resolver=SafeResolver(scanner.policy, scanner.config, scanner.store), ttl_dns_cache=0, force_close=True, limit=1)
    async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=scanner.config.budgets.timeout), auto_decompress=False, trust_env=False,
                                    headers={"User-Agent": "reconmap/2 authorized-recon", "Accept-Encoding": "identity"}, cookie_jar=aiohttp.DummyCookieJar()) as session:
        scanner.session = session
        # SQLite is the bounded durable producer-consumer queue. The host, depth,
        # request, time and disk caps are checked before work enters/consumes it.
        while True:
            await scanner.crawl()
            await scanner.local_tools()
            if not scanner.store.conn.execute("SELECT 1 FROM jobs WHERE state='queued' LIMIT 1").fetchone():
                break


def initialize_tools(scanner):
    from .storage import timestamp
    for name in selected_names(scanner.config):
        info = scanner.tools[name]
        scanner.store.register_tool(info)
        spec = BY_NAME[name]
        if spec.policy_reason:
            scanner.store.stage(name, "blocked-by-policy", spec.policy_reason + "; native fallback: " + ",".join(spec.fallback))


async def run_pipeline(scanner):
    from .dnschecks import observe_dns
    from .enrichment.asn import enrich_asn
    from .enrichment.wayback import collect_wayback
    initialize_tools(scanner)
    enabled = {row["name"]: row["enabled"] for row in phase_plan(scanner.config)}
    for stage in stage_order():
        scanner.scheduler.check_time()
        scanner.store.stage("workflow:" + stage.name, "running", "Dependencies: " + ",".join(stage.dependencies))
        if stage.name == "discovery":
            scanner.add_url(scanner.manifest["target"], "seed")
            for url in scanner.store.meta("rerun_targets", []):
                scanner.add_url(url, "parent-candidate")
        elif stage.name == "passive-tools":
            await scanner.collect_passive()
        elif stage.name == "wayback" and "wayback" in scanner.config.enrichments:
            await collect_wayback(scanner)
        elif stage.name == "local-inputs":
            from .reruns import analyze_reused
            analyze_reused(scanner)
            scanner.local_inputs()
        elif stage.name == "dns" and ({"dns", "http"} & set(scanner.config.modules)):
            await observe_dns(scanner)
            if "dns" in scanner.config.modules and "http" not in scanner.config.modules and scanner.config.mode not in {"demo", "offline", "passive"}:
                from .engine import SafeResolver
                import asyncio
                resolver = SafeResolver(scanner.policy, scanner.config, scanner.store)
                failures = []
                for host in scanner.store.rows("hosts"):
                    if not scanner.policy.host_allowed(host["host"]):
                        continue
                    scanner.scheduler.check_time()
                    try:
                        await asyncio.wait_for(resolver.resolve(host["host"], scanner.config.scope.ports[0]), min(scanner.config.budgets.timeout, scanner.scheduler.remaining()))
                    except (OSError, ValueError, TimeoutError) as exc:
                        failures.append(type(exc).__name__)
                if failures:
                    scanner.store.stage("dns", "partial", "Some native A/AAAA resolutions failed or returned prohibited addresses")
        elif stage.name == "native-web":
            await native_web(scanner)
        elif stage.name == "offline-tools":
            await scanner.local_tools()
        elif stage.name == "asn" and "asn" in scanner.config.enrichments:
            await enrich_asn(scanner)
        elif stage.name == "normalization":
            finalize_enrichments(scanner)
        scanner.store.stage("workflow:" + stage.name, "completed" if enabled[stage.name] else "skipped", "Dependency phase finalized; component statuses record skipped/partial/blocked coverage")


def finalize_enrichments(scanner):
    from .enrichment.grouping import group_urls
    from .enrichment.prioritization import prioritize
    from .enrichment.technology import analyze_captured
    if "tech" in scanner.config.enrichments:
        analyze_captured(scanner)
    if "dedup" in scanner.config.enrichments:
        group_urls(scanner.store, scanner.config.grouping)
    if "priority" in scanner.config.enrichments:
        prioritize(scanner.store, scanner.config.priority)
