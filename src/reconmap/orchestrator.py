"""Dependency ordering, pure plan preview, and shared native execution."""
from dataclasses import asdict, dataclass, field
import json
import time
from contextlib import contextmanager
from urllib.parse import urljoin, urlsplit, urlunsplit

import aiohttp

from .config import ConfigError, normalize_url
from .scope import ScopePolicy
from .selectors import capability_enabled
from .tool_registry import BY_NAME, REGISTRY, execution_status


STAGE_NAMES = {"subfinder": "subdomain-discovery", "urlfinder": "historical-discovery",
               "dnsx": "dns-enumeration", "httpx": "http-probing", "katana": "web-crawling",
               "jsluice": "javascript-analysis", "gitleaks": "secret-detection", "nuclei": "exposure-checks"}
NATIVE_ENGINES = {"dnsx": "native-dns", "httpx": "native-aiohttp", "katana": "native-html",
                  "nuclei": "native-reviewed-checks", "jsluice": "native-tree-sitter", "gitleaks": "native-secret-patterns"}


@dataclass
class StageResult:
    stage: str
    selected_primary_tool: str | None
    tool_identity: dict = field(default_factory=dict)
    actual_execution_engines: list[str] = field(default_factory=list)
    status: str = "pending"
    primary_status: str = "not-selected"
    failure_reason: str = ""
    input_artifacts: list[str] = field(default_factory=list)
    output_artifacts: list[str] = field(default_factory=list)
    request_accounting: dict = field(default_factory=dict)
    discovered_records: int = 0
    fallback_used: bool = False
    coverage_limitations: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    started: str | None = None
    finished: str | None = None
    process_executions: list[dict] = field(default_factory=list)


def record_execution(scanner, name, *, engine=None, state="completed", reason="", fallback=False,
                     inputs=(), outputs=(), count=0, seconds=0.0, accounting=None, limitations=(), process=None):
    """One durable result per capability; repeated waves accumulate actual work."""
    from .storage import timestamp
    from .security import redact
    stage = STAGE_NAMES.get(name, name)
    row = scanner.store.conn.execute("SELECT result_json FROM stage_results WHERE name=?", (stage,)).fetchone()
    selected = name if name in selected_names(scanner.config) else None
    result = StageResult(**json.loads(row[0])) if row else StageResult(stage, selected,
                         scanner.tools[name].record() if selected else {})
    primary_attempt = engine == name
    if primary_attempt and state not in {"running", "pending"} and not scanner.store.meta("executed:"+name, False):
        # A failed spawn/identity check is not successful process execution.
        result.actual_execution_engines = [e for e in result.actual_execution_engines if e != name]
        engine = None
    if engine and engine not in result.actual_execution_engines:
        result.actual_execution_engines.append(engine)
    native_selected = scanner.config.execution_engines.get(name) == "native"
    result.fallback_used |= fallback and engine is not None and not native_selected
    if primary_attempt or (engine is None and selected):
        if result.primary_status in {"failed", "partial", "unavailable", "incompatible", "blocked-by-policy"} and state in {"completed", "running"}:
            pass  # another successful input does not erase failed primary coverage
        else:
            result.primary_status = state
    if state == "completed" and not result.errors and not result.coverage_limitations:
        result.failure_reason = ""
    if reason and state not in {"completed", "running"}:
        result.failure_reason = redact(reason)
        if state in {"failed", "partial", "interrupted"} and redact(reason) not in result.errors:
            result.errors.append(redact(reason))
    for target, values in ((result.input_artifacts, inputs), (result.output_artifacts, outputs),
                           (result.coverage_limitations, limitations)):
        target[:] = sorted(set(target) | {str(v) for v in values})
    if native_selected:
        result.primary_status = "native-selected"
    result.discovered_records += count
    result.duration_seconds = round(result.duration_seconds + seconds, 6)
    result.request_accounting.update(accounting or {})
    if process is not None:
        result.process_executions.append(process)
    result.status = state
    if state == "completed" and (result.coverage_limitations or result.primary_status in {"unavailable", "incompatible", "blocked-by-policy", "failed", "partial"}):
        result.status = "partial"
    if engine and result.started is None:
        result.started = timestamp()
    result.finished = None if state == "running" else timestamp()
    scanner.store.execute("INSERT OR REPLACE INTO stage_results VALUES(?,?)", (stage, json.dumps(asdict(result))))


def fallback_allowed(scanner, name):
    """A missing containment capability is distinct from denied target actions."""
    if scanner.config.strict_tools and name in selected_names(scanner.config):
        return False
    scanner.scheduler.check_time()
    scanner.check_disk_budget()
    if BY_NAME[name].risk == "active":
        counter,ceiling=('dns_operations',scanner.config.budgets.dns_queries) if name=='dnsx' else ('requests',scanner.config.budgets.requests)
        if scanner.store.meta(counter,0)>=ceiling:
            return False
        return scanner.config.mode not in {"offline", "passive"} and scanner.policy.decision(scanner.manifest["target"])[0]
    return True


def native_counts(scanner):
    observations = scanner.store.rows("observations")
    findings = scanner.store.rows("findings")
    check_rules = {"git-head", "environment-config", "directory-index", "debug-surface", "api-docs", "route-lead"}
    return {"dnsx": len(scanner.store.rows("dns")), "katana": len(scanner.store.rows("urls")),
            "httpx": sum(r["kind"] == "http" for r in observations),
            "jsluice": sum(r["kind"] == "inferred_endpoint" for r in observations),
            "gitleaks": sum(r["subject"].startswith("artifact:") and r["source"] in {"native", "native-fallback", "local-input"} for r in findings),
            "nuclei": sum(r["rule"] in check_rules and r["source"] == "native" for r in findings)}


@contextmanager
def native_execution(scanner, names, accounting_group):
    started = time.monotonic()
    for name in names:
        record_execution(scanner, name, engine=NATIVE_ENGINES[name], state="running")
    counts = native_counts(scanner)
    state, reason = "completed", ""
    try:
        yield
    except BaseException as exc:
        state, reason = "partial", type(exc).__name__ + ": " + str(exc)
        raise
    finally:
        for name in names:
            selected = name in selected_names(scanner.config)
            component = {"dnsx": "dns", "httpx": "http", "katana": "crawl", "nuclei": "checks", "jsluice": "analysis", "gitleaks": "analysis"}[name]
            prior = scanner.store.conn.execute("SELECT state,detail FROM stages WHERE name=?", (component,)).fetchone()
            effective_state = "partial" if scanner.limits or (prior and prior[0] in {"failed", "partial"}) else state
            new_count = native_counts(scanner)[name]
            record_execution(scanner, name, engine=NATIVE_ENGINES[name], state=effective_state, reason=reason or (prior[1] if prior and prior[0] in {"failed", "partial"} else ""), fallback=selected,
                count=max(0, new_count-counts[name]),
                seconds=time.monotonic()-started,
                inputs=["recon.sqlite:artifacts" if name in {"jsluice", "gitleaks"} else "recon.sqlite:jobs" if name != "dnsx" else "recon.sqlite:hosts"],
                outputs=["recon.sqlite:observations", "recon.sqlite:dns"],
                accounting={"group": accounting_group, "shared_counters_not_additive": True,
                    "target_requests": scanner.store.meta("requests", 0), "dns_operations": scanner.store.meta("dns_operations", 0)},
                limitations=[])


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
    Stage("wordlist-hosts", ("local-inputs",), "local"),
    Stage("dns", ("passive-tools", "wayback", "wordlist-hosts"), "active"),
    Stage("native-web", ("dns", "local-inputs"), "active"),
    Stage("content-discovery", ("native-web",), "active"),
    Stage("offline-tools", ("content-discovery", "local-inputs"), "offline"),
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
        "wordlist-hosts": config.discovery.god_mode,
        "content-discovery": config.discovery.enabled,
        "dns": active and (capability_enabled(config, "dnsx") or config.selected_tools is None and "http" in config.modules),
        "native-web": config.mode not in {"passive", "offline"} and "http" in config.modules,
        "offline-tools": bool({"jsluice", "gitleaks"} & set(config.modules)),
        "asn": providers and "asn" in config.enrichments,
        "normalization": True,
    }
    return [{**asdict(stage), "enabled": enabled[stage.name], "effective_risk": "offline-fixtures" if config.mode == "demo" and stage.risk == "active" else stage.risk} for stage in stage_order()]


def build_plan(config, target, tools):
    target = normalize_url(target)
    allowed, reason = ScopePolicy(config.scope).decision(target)
    if not allowed:
        raise ConfigError("Seed denied by scope: " + reason)
    from .execution_boundary import ACTIVE_TOOLS, execution_requirement, probe_boundary
    boundary = probe_boundary() if any(n in ACTIVE_TOOLS and tools[n].supported for n in selected_names(config)) else None
    records = []
    for name in selected_names(config):
        spec = BY_NAME[name]
        info = tools[name]
        reason = execution_requirement(config,name,info,boundary,target)
        status = execution_status(info) if not reason or not info.supported else 'blocked-by-policy'
        records.append({**info.record(), "status": status, "dependencies": list(spec.dependencies), "policy_reason": reason})
    issues = [r for r in records if r["status"] != "ready"]
    provider_stages = [n for n in config.enrichments if n in {"asn", "wayback"}]
    return {
        "target": target, "mode": config.mode, "profile": config.profile,
        "selected_tools": records, "execution_order": phase_plan(config),
        "native_modules": [m for m in config.modules if m not in BY_NAME],
        "enrichments": config.enrichments, "scope": config.scope.model_dump(),
        "discovery": config.discovery.model_dump(),
        "budgets": config.budgets.model_dump(), "provider_budgets": config.providers.model_dump(),
        "provider_access": provider_stages, "fully_supported": not issues,
        "safe_to_execute": not (config.strict_tools and issues),
        "security": "Active executables require a verified isolated Linux backend. The HTTP/DNS broker owns target requests, decrypted-path checks and shared budgets. Strict mode never substitutes native engines.",
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


async def native_web(scanner, capabilities=None):
    if scanner.config.mode in {"passive", "offline"} or "http" not in scanner.config.modules:
        scanner.store.stage("http", "skipped", "No target HTTP in this execution")
        return
    names = capabilities if capabilities is not None else ["httpx"] + (["katana"] if "crawl" in scanner.config.modules else []) + (["nuclei"] if "checks" in scanner.config.modules else [])
    if scanner.config.strict_tools and set(names) & set(selected_names(scanner.config)):
        raise ConfigError('Strict external execution refuses native substitution')
    if 'nuclei' in names:
        scanner.native_checks_enabled = True
        # Reuse bodies already collected by successful tools before a fallback.
        from .analysis import basic_checks
        from .storage import artifact_path
        for row in scanner.store.rows('observations'):
            if row['kind']!='http': continue
            data=json.loads(row['data'])
            body=scanner.store.conn.execute('SELECT path FROM artifacts WHERE hash=?',(data.get('hash'),)).fetchone()
            if body:
                basic_checks(scanner.store,row['subject'],artifact_path(scanner.run,body[0]).read_text(encoding='utf-8',errors='replace'),data.get('headers',{}),data['hash'],data['status'])
    if "analysis" in scanner.config.modules:
        names += [n for n in ("jsluice", "gitleaks") if capability_enabled(scanner.config, n) and n not in scanner.config.modules]
    with native_execution(scanner, names, "shared-native-web"):
        await _native_web(scanner, names)


async def _native_web(scanner, capabilities=None):
    from .engine import SafeResolver
    if scanner.config.mode in {"passive", "offline"} or "http" not in scanner.config.modules:
        scanner.store.stage("http", "skipped", "No target HTTP in this execution")
        return
    seed = urlsplit(scanner.manifest["target"])
    origin = urlunsplit(seed._replace(path="/", query="", fragment=""))
    if "crawl" in scanner.config.modules and (capabilities is None or 'katana' in capabilities):
        import hashlib
        for path in ("robots.txt", "sitemap.xml", "__reconmap_missing_" + hashlib.sha256(scanner.manifest["target"].encode()).hexdigest()[:12]):
            scanner.add_url(urljoin(origin, path), "bounded-baseline")
    if "checks" in scanner.config.modules and (capabilities is None or 'nuclei' in capabilities):
        paths = (".git/HEAD", ".env") if "nuclei" in scanner.config.modules else (".git/HEAD", ".env", "openapi.json", "swagger.json")
        for path in paths:
            scanner.add_url(urljoin(origin, path), "exposure-profile-v1")
    connector = aiohttp.TCPConnector(resolver=SafeResolver(scanner.policy, scanner.config, scanner.store), ttl_dns_cache=0, force_close=True, limit=1)
    async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=scanner.config.budgets.timeout), auto_decompress=False, trust_env=False,
                                    headers={"User-Agent": "reconmap/3 authorized-recon", "Accept-Encoding": "identity"}, cookie_jar=aiohttp.DummyCookieJar()) as session:
        scanner.session = session
        # SQLite is the bounded durable producer-consumer queue. The host, depth,
        # request, time and disk caps are checked before work enters/consumes it.
        while True:
            count = scanner.store.conn.execute("SELECT COUNT(*) FROM jobs WHERE state='queued'").fetchone()[0]
            await scanner.crawl(max_jobs=None if capabilities is None or 'katana' in capabilities else count)
            await scanner.local_tools()
            if capabilities is not None and 'katana' not in capabilities:
                break
            if not scanner.store.conn.execute("SELECT 1 FROM jobs WHERE state='queued' LIMIT 1").fetchone():
                break


def initialize_tools(scanner):
    from .storage import timestamp
    from .execution_boundary import ACTIVE_TOOLS, execution_requirement, probe_boundary
    scanner.boundary = probe_boundary() if any(n in ACTIVE_TOOLS and scanner.tools[n].supported for n in selected_names(scanner.config)) else None
    requirements={}
    for name in selected_names(scanner.config):
        info = scanner.tools[name]
        scanner.store.register_tool(info)
        spec = BY_NAME[name]
        if not scanner.store.conn.execute("SELECT 1 FROM stage_results WHERE name=?", (STAGE_NAMES[name],)).fetchone():
            record_execution(scanner, name, state="pending")
        reason=execution_requirement(scanner.config,name,info,scanner.boundary,scanner.manifest['target'])
        requirements[name]={'permitted':not reason,'reason':reason}
        if scanner.config.execution_engines.get(name)=='native' and not scanner.config.strict_tools:
            scanner.store.stage(name,'skipped','Native implementation explicitly selected')
            continue
        if reason and spec.risk=='active':
            state=execution_status(info) if not info.supported else 'blocked-by-policy'
            scanner.store.stage(name,state,reason)
            record_execution(scanner,name,state=state,reason=reason,limitations=[reason])
    scanner.store.set_meta('execution_requirements',requirements)
    if scanner.config.strict_tools and any(r['reason'] for r in requirements.values()):
        raise ConfigError('Strict external preflight failed: '+'; '.join(n+': '+r['reason'] for n,r in requirements.items() if r['reason']))


async def web_workflow(scanner):
    from .active_tools import run_active
    if not set(selected_names(scanner.config)) & {'httpx','katana','nuclei'}:
        return await native_web(scanner)
    if scanner.config.mode in {'offline','passive'} or 'http' not in scanner.config.modules:
        return
    # New JS/content candidates return to the same queue. Successful requests and
    # completed external inputs are reused; no independent tool traffic exists.
    while True:
        before=tuple((r['url'],r['state']) for r in scanner.store.rows('jobs'))
        for name in ('httpx','katana'):
            if name not in selected_names(scanner.config): continue
            completed=await run_active(scanner,name)
            if not completed and fallback_allowed(scanner,name):
                await native_web(scanner,[name])
        await scanner.local_tools()
        after=tuple((r['url'],r['state']) for r in scanner.store.rows('jobs'))
        if before==after or not any(state=='queued' for _,state in after): break
    if 'nuclei' in selected_names(scanner.config):
        completed=await run_active(scanner,'nuclei')
        if not completed and fallback_allowed(scanner,'nuclei'):
            await native_web(scanner,['nuclei'])


async def run_pipeline(scanner):
    from .dnschecks import observe_dns
    from .enrichment.asn import enrich_asn
    from .enrichment.wayback import collect_wayback
    initialize_tools(scanner)
    enabled = {row["name"]: row["enabled"] for row in phase_plan(scanner.config)}
    if "http" not in scanner.config.modules:
        for name in ("katana", "nuclei"):
            if name in selected_names(scanner.config):
                record_execution(scanner, name, state="skipped", reason="HTTP collection prerequisite not selected; no active fallback executed", limitations=["Select httpx with this capability to collect fresh authorized HTTP evidence"])
                scanner.store.stage(name, "skipped", "HTTP collection prerequisite not selected")
                scanner.limit(name + ": HTTP collection prerequisite not selected; coverage incomplete")
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
            primary = scanner.store.conn.execute("SELECT state FROM stages WHERE name='urlfinder'").fetchone()
            if primary and primary[0] == "completed":
                scanner.store.stage("wayback", "skipped", "URLFinder completed; no redundant historical enumeration")
            elif not (scanner.config.strict_tools and 'urlfinder' in selected_names(scanner.config)):
                started = time.monotonic()
                await collect_wayback(scanner)
                if "urlfinder" in scanner.config.modules:
                    status = scanner.store.conn.execute("SELECT state,detail FROM stages WHERE name='wayback'").fetchone()
                    record_execution(scanner, "urlfinder", engine="native-cdx" if status[0] != "skipped" else None,
                        state=status[0], reason=status[1], fallback=status[0] != "skipped", seconds=time.monotonic()-started,
                        count=len(scanner.store.rows("historical_urls")), accounting={"target_requests": 0, "owned_provider_requests": scanner.store.meta("provider_requests", 0)})
        elif stage.name == "local-inputs":
            from .reruns import analyze_reused
            names = [n for n in ("jsluice", "gitleaks") if capability_enabled(scanner.config, n) and "analysis" in scanner.config.modules and n not in scanner.config.modules]
            with native_execution(scanner, names, "shared-native-local-inputs"):
                analyze_reused(scanner)
                scanner.local_inputs()
            await scanner.local_tools()
        elif stage.name == "wordlist-hosts" and scanner.config.discovery.god_mode:
            from .content_discovery import prepare_hosts
            prepare_hosts(scanner)
        elif stage.name == "content-discovery" and scanner.config.discovery.enabled:
            from .content_discovery import run as discover_content
            await discover_content(scanner)
        elif stage.name == "dns" and enabled["dns"]:
            if scanner.config.mode not in {"demo", "offline", "passive"}:
                from .active_tools import run_active
                if 'dnsx' in selected_names(scanner.config):
                    completed=await run_active(scanner,'dnsx')
                    if completed or not fallback_allowed(scanner,'dnsx'):
                        scanner.store.stage('workflow:dns','completed' if completed else 'partial','External DNS execution evaluated')
                        continue
                with native_execution(scanner, ["dnsx"], "native-dns"):
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
            await web_workflow(scanner)
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
    scanner.correlate()
    if "tech" in scanner.config.enrichments:
        analyze_captured(scanner)
    prioritize(scanner.store, scanner.config.priority)
    group_urls(scanner.store, scanner.config.grouping)
