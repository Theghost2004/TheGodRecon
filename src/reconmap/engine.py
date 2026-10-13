from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import re
import socket
import time
import uuid
import zlib
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

import aiohttp
from aiohttp.abc import AbstractResolver

from .adapters import CAPABILITIES, ToolInfo, capture, command, doctor, execute, parse_records
from .analysis import PageParser, analyze_js, analyze_map, basic_checks, js_strings, secrets
from .config import ScanConfig, normalize_url, request_url
from .scope import ScopePolicy
from .security import redact, redact_data
from .storage import POLICY_REVISION, SCHEMA, RunLock, Store, allocate_run, artifact_path, atomic_json, read_manifest, timestamp


class BudgetStop(Exception):
    pass


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes
    truncated: bool = False


class Scheduler:
    def __init__(self, config: ScanConfig, store: Store):
        self.config = config
        self.store = store
        self.started = time.monotonic()
        self.elapsed = float(store.meta("elapsed_seconds", 0))
        self.next_global = 0.0
        self.next_host: dict[str, float] = {}
        self.retry_at: dict[str, float] = {}

    def check_time(self) -> None:
        if self.remaining() <= 0:
            raise BudgetStop("run time cap reached")

    def remaining(self) -> float:
        return max(0.0, self.config.budgets.minutes * 60 - self.elapsed - (time.monotonic() - self.started))

    async def reserve(self, url: str, offline: bool = False) -> None:
        self.check_time()
        count = int(self.store.meta("requests", 0))
        if count >= self.config.budgets.requests:
            raise BudgetStop("target request cap reached")
        host = urlsplit(url).hostname
        delay = max(self.next_global, self.next_host.get(host, 0), self.retry_at.get(host, 0)) - time.monotonic()
        if delay > 0 and not offline:
            if self.elapsed + time.monotonic() - self.started + delay >= self.config.budgets.minutes * 60:
                raise BudgetStop("Retry-After/rate wait exceeds remaining run time")
            await asyncio.sleep(delay)
        self.check_time()
        # Persist before sending, so a killed process cannot forget a consumed request.
        self.store.set_meta("requests", count + 1)
        self.next_global = time.monotonic() + 1 / self.config.budgets.overall_rps
        self.next_host[host] = time.monotonic() + 1 / self.config.budgets.per_host_rps

    def throttle(self, url: str, status: int, headers: dict[str, str]) -> None:
        if status not in {429, 500, 502, 503, 504}:
            return
        host = urlsplit(url).hostname
        key = "errors:" + host
        errors = int(self.store.meta(key, 0)) + 1
        self.store.set_meta(key, errors)
        delay = min(60, 2**min(errors, 6))
        retry = headers.get("retry-after", "")
        if retry.isdigit():
            delay = max(delay, int(retry))
        elif retry:
            try:
                delay = max(delay, parsedate_to_datetime(retry).timestamp() - time.time())
            except (ValueError, TypeError, OverflowError):
                pass
        self.retry_at[host] = time.monotonic() + delay
        self.store.observed(url, "throttle", {"status": status, "delay_seconds": delay}, "scheduler")

    def checkpoint(self) -> None:
        self.store.set_meta("elapsed_seconds", self.elapsed + time.monotonic() - self.started)


class SafeResolver(AbstractResolver):
    """Check all resolved addresses, then give those exact addresses to aiohttp."""
    def __init__(self, policy: ScopePolicy, config: ScanConfig, store: Store):
        self.policy, self.config, self.store = policy, config, store

    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_INET) -> list[dict]:
        if not self.policy.host_allowed(host):
            raise OSError("DNS hostname outside scope")
        count = int(self.store.meta("dns_operations", 0))
        if count >= self.config.budgets.dns_queries:
            raise BudgetStop("DNS operation cap reached")
        self.store.set_meta("dns_operations", count + 1)
        result = await asyncio.get_running_loop().getaddrinfo(host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM, flags=socket.AI_CANONNAME)
        addresses = {item[4][0] for item in result}
        for address in addresses:
            self.store.execute("INSERT INTO dns(host,address,kind,time,source) VALUES(?,?,?,?,?)", (host, address, "AAAA" if ":" in address else "A", timestamp(), "system-resolver"))
        if not addresses or any(not self.policy.ip_allowed(a) for a in addresses):
            raise OSError("DNS resolved to a prohibited private, loopback, link-local or reserved address")
        for item in result:
            if item[3] and item[3] != host:
                self.store.observed(host, "dns-canonical-name", {"name": item[3], "note": "resolver hint, not proof of a CNAME; no authorization transferred"}, "system-resolver")
        return [{"hostname": host, "host": item[4][0], "port": port, "family": item[0], "proto": item[2], "flags": socket.AI_NUMERICHOST} for item in result]

    async def close(self) -> None:
        pass


async def bounded_response(response: aiohttp.ClientResponse, cap: int) -> Response:
    headers = {k.lower(): v for k, v in response.headers.items()}
    encoding = headers.get("content-encoding", "identity").lower()
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS if encoding == "gzip" else zlib.MAX_WBITS) if encoding in {"gzip", "deflate"} else None
    if encoding not in {"identity", "", "gzip", "deflate"}:
        raise ValueError(f"Unsupported content encoding {encoding}")
    body = bytearray()
    wire_bytes = 0
    truncated = False
    async for chunk in response.content.iter_chunked(16384):
        available = cap - wire_bytes
        wire_bytes += len(chunk)
        if wire_bytes > cap:
            truncated = True
            chunk = chunk[:available]
        remaining = cap - len(body)
        decoded = decoder.decompress(chunk, remaining + 1) if decoder else chunk
        body.extend(decoded[:remaining])
        if len(decoded) > remaining:
            truncated = True
        if truncated:
            break
    if decoder and not truncated and not decoder.eof:
        raise ValueError("Incomplete compressed response body")
    return Response(response.status, headers, bytes(body), truncated)


def restrict_directory(run: Path) -> None:
    if os.name == "nt":
        import subprocess
        user = subprocess.check_output(["whoami"], text=True).strip()
        subprocess.run(["icacls", str(run), "/inheritance:r", "/grant:r", f"{user}:(OI)(CI)F"], check=True, capture_output=True)
    else:
        run.chmod(0o700)


def prepare_run(config: ScanConfig, target: str | None, root: Path, resume: Path | None = None, baseline: Path | None = None) -> tuple[Path, dict]:
    if resume:
        manifest = read_manifest(resume)
        if manifest.get("policy_revision") != POLICY_REVISION:
            raise ValueError("Execution policy changed after a security fix. Start a new run; old reports remain readable")
        if manifest["config_digest"] != config.digest():
            raise ValueError("Scope, mode, tools or configuration changed. Start a new run; completed work would be invalidated")
        if target is not None and normalize_url(target) != manifest["target"]:
            raise ValueError("Resume target differs from manifest")
        if baseline is not None and str(baseline.absolute()) != manifest.get("baseline"):
            raise ValueError("Resume baseline differs; create a new run")
        return resume.absolute(), manifest
    if target is None:
        raise ValueError("A new scan requires --target")
    normalized = normalize_url(target)
    allowed, reason = ScopePolicy(config.scope).decision(normalized)
    if not allowed:
        raise ValueError(f"Seed denied by scope: {reason}")
    run = allocate_run(root, target)
    restrict_directory(run)
    for name in ("raw", "normalized", "assets/js", "assets/maps", "assets/content", "evidence", "logs", "checkpoints", "reports", "diff", "tmp"):
        (run / name).mkdir(parents=True, exist_ok=True)
    manifest = {"schema": SCHEMA, "run_id": uuid.uuid4().hex, "original_target": target, "target": normalized, "host": urlsplit(normalized).hostname, "created": timestamp(), "state": "created", "config_digest": config.digest(), "baseline": str(baseline.absolute()) if baseline else None, "engine": "reconmap-0.1.0", "transport": "offline-fixtures" if config.mode == "demo" else "native-http"}
    manifest["policy_revision"] = POLICY_REVISION
    atomic_json(run / "manifest.json", manifest)
    atomic_json(run / "config.effective.json", config.model_dump())
    store = Store(run)
    store.set_meta("config", config.model_dump())
    store.execute("INSERT INTO runs VALUES(?,?,?,?,?,?,?)", (manifest["run_id"],normalized,target,"created",manifest["created"],manifest["created"],json.dumps(config.model_dump())))
    store.close()
    return run, manifest


class Scanner:
    def __init__(self, run: Path, manifest: dict, config: ScanConfig, tools: dict[str, ToolInfo], fixtures: dict[str, Response] | None = None):
        self.run, self.manifest, self.config, self.tools = run, manifest, config, tools
        self.store = Store(run)
        self.policy = ScopePolicy(config.scope)
        self.scheduler = Scheduler(config, self.store)
        self.fixtures = fixtures
        self.limits: list[str] = list(self.store.meta("limits", []))
        self.session: aiohttp.ClientSession | None = None

    def limit(self, reason: str) -> None:
        if reason not in self.limits:
            self.limits.append(reason)
            self.store.set_meta("limits", self.limits)

    def check_disk_budget(self, reserve: int = 0) -> None:
        total = sum(p.stat().st_size for p in self.run.rglob("*") if p.is_file() and not p.is_symlink())
        metadata = self.store.conn.execute("SELECT COALESCE(SUM(length(data)+length(subject)+200),0) FROM observations").fetchone()[0]
        metadata += self.store.conn.execute("SELECT COALESCE(SUM(length(evidence)+length(subject)+length(title)+500),0) FROM findings").fetchone()[0]
        metadata += sum(self.store.conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]*1000 for t in ("urls","relationships","jobs","parameters","artifacts"))
        # Redundant JSON/HTML exports expand metadata; leave a conservative reserve.
        finalization = 128 * 1024 + 12 * metadata
        if total + reserve + finalization >= self.config.budgets.artifact_bytes:
            raise BudgetStop("scan-artifact disk cap reached (final report space reserved)")

    def add_url(self, candidate: str, source: str, parent: str = "", depth: int = 0, fetch: bool = True) -> None:
        self.check_disk_budget(65536)
        try:
            url = normalize_url(candidate)
        except ValueError as exc:
            self.store.observed(parent, "invalid_reference", {"value": redact(candidate[:1000]), "reason": str(exc)}, source)
            return
        allowed, reason = self.policy.decision(url)
        host = urlsplit(url).hostname
        state = "historical-only" if self.config.mode == "passive" else "untested"
        if not allowed:
            state = "external-reference"
        self.store.execute("INSERT OR IGNORE INTO urls(url,grouping_key,source,state,depth) VALUES(?,?,?,?,?)", (url, url, source, state, depth))
        self.store.observed(url, "discovery", {"allowed": allowed, "reason": reason, "parent": parent}, source, identity=hashlib.sha256(f"{url}:{source}:{parent}".encode()).hexdigest())
        if parent:
            self.store.relate(parent, url, source, source)
        for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            self.store.execute("INSERT OR IGNORE INTO parameters VALUES(?,?,?,?)", (url, name, "query", source))
        if not allowed:
            return
        self.store.execute("INSERT OR IGNORE INTO hosts VALUES(?,?,?)", (host, "untested", timestamp()))
        if not fetch or self.config.mode == "passive" or "http" not in self.config.modules:
            return
        if depth > self.config.budgets.depth:
            if not self.store.conn.execute("SELECT 1 FROM jobs WHERE url=?", (request_url(url),)).fetchone():
                self.limit("crawl depth cap reached")
            return
        wire_url = request_url(url)
        host_count = sum(urlsplit(row[0]).hostname == host for row in self.store.conn.execute("SELECT url FROM jobs"))
        if host_count >= self.config.budgets.urls_per_host and not self.store.conn.execute("SELECT 1 FROM jobs WHERE url=?", (wire_url,)).fetchone():
            self.limit("per-host URL cap reached")
            return
        if re.search(r"\.(?:png|jpg|jpeg|gif|webp|mp4|mp3|woff2?|ico|pdf|zip|tar|gz)(?:$|\?)", wire_url, re.I):
            self.store.observed(url, "scheduling-filter", {"reason": "static/bulk media; preserved as observation"}, "scheduler")
            return
        self.store.execute("INSERT OR IGNORE INTO jobs(url,depth,source,state) VALUES(?,?,?,'queued')", (wire_url, depth, source))

    def add_reference(self, base: str, reference: str, source: str, depth: int) -> None:
        try:
            candidate = urljoin(base, reference)
        except ValueError:
            self.store.observed(base, "invalid_reference", {"value": redact(reference[:1000]), "reason": "Malformed URL reference"}, source)
            return
        self.add_url(candidate, source, base, depth)

    def save_artifact(self, body: bytes, kind: str, url: str) -> str:
        digest = hashlib.sha256(body).hexdigest()
        existing = self.store.conn.execute("SELECT path FROM artifacts WHERE hash=?", (digest,)).fetchone()
        if not existing:
            self.check_disk_budget(len(body))
            used = int(self.store.meta("artifact_bytes", 0))
            if used + len(body) > self.config.budgets.artifact_bytes:
                raise BudgetStop("scan content artifact cap reached")
            folder = "js" if kind == "js" else "maps" if kind == "map" else "content"
            relative = f"assets/{folder}/{digest}.{'js' if kind == 'js' else 'json' if kind == 'map' else 'bin'}"
            path = self.run / relative
            # Atomic replace only for a content-derived path inside our run.
            temp = self.run / "tmp" / (uuid.uuid4().hex + ".body")
            temp.write_bytes(body)
            temp.chmod(0o600)
            os.replace(temp, path)
            self.store.execute("INSERT INTO artifacts(hash,path,kind,bytes) VALUES(?,?,?,?)", (digest, relative, kind, len(body)))
            self.store.set_meta("artifact_bytes", used + len(body))
        self.store.relate(url, "artifact:" + digest, "response_body", "native")
        return digest

    async def request(self, url: str) -> Response:
        allowed, reason = self.policy.decision(url)
        if not allowed:
            raise ValueError("Request denied: " + reason)
        # Literal addresses bypass aiohttp's resolver, so check them explicitly above.
        await self.scheduler.reserve(url, offline=self.fixtures is not None)
        if self.fixtures is not None:
            return self.fixtures.get(url, Response(200, {"content-type": "text/html"}, b"<title>Missing page</title><p>demo soft 404</p>"))
        remaining = self.scheduler.remaining()
        if remaining <= 0:
            raise BudgetStop("run time cap reached")
        async with self.session.get(url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=min(self.config.budgets.timeout, remaining))) as response:
            cap = min(4096,self.config.budgets.response_bytes) if urlsplit(url).path in {"/.git/HEAD","/.env"} else self.config.budgets.response_bytes
            return await bounded_response(response, cap)

    def process_response(self, url: str, response: Response, depth: int, attempt: int) -> None:
        content_type = response.headers.get("content-type", "").split(";",1)[0]
        text = response.body.decode("utf-8", errors="replace")
        kind = "map" if urlsplit(url).path.endswith(".map") else "js" if "javascript" in content_type or urlsplit(url).path.endswith(".js") else "content"
        digest = self.save_artifact(response.body, kind, url)
        parser = PageParser()
        if "html" in content_type:
            parser.feed(text)
            if parser.truncated:
                self.limit("HTML reference/form/comment parser cap reached")
        state = "restricted" if response.status in {401,403} else "redirected" if 300 <= response.status < 400 else "reachable"
        self.store.execute("UPDATE urls SET state=?,status=?,title=?,content_type=?,hash=?,bytes=?,time=? WHERE url=?", (state, response.status, redact(parser.title[:500]), content_type, digest, len(response.body), timestamp(), url))
        origin = urlunsplit(urlsplit(url)._replace(path="",query="",fragment=""))
        self.store.execute("INSERT OR REPLACE INTO origins VALUES(?,?,?,?)", (origin, state, response.status, timestamp()))
        self.store.execute("UPDATE hosts SET state=? WHERE host=?", (state, urlsplit(url).hostname))
        self.store.observed(url, "http", {"status": response.status, "headers": redact_data(response.headers), "hash": digest, "bytes": len(response.body), "truncated": response.truncated, "attempt": attempt, "technology_hints": {k:v for k,v in response.headers.items() if k in {"server","x-powered-by"}}}, "native", identity=f"http:{url}:{attempt}")
        if response.truncated:
            self.limit("response body/decompression cap reached")
        if response.headers.get("location") and 300 <= response.status < 400:
            self.add_reference(url, response.headers["location"], "redirect", depth+1)
        if "checks" in self.config.modules:
            basic_checks(self.store, url, text, response.headers, digest, response.status)
        if "analysis" in self.config.modules:
            secrets(self.store, text, digest, "native", self.config.mode == "demo")
            refs = analyze_js(self.store, text, url, digest, self.config.mode == "demo") if kind == "js" else analyze_map(self.store, text, url, digest, self.config.budgets.response_bytes, self.config.mode == "demo") if kind == "map" else []
            for candidate, provenance in refs:
                self.add_url(candidate, provenance, "artifact:" + digest, depth+1, fetch=provenance != "inferred_endpoint_non_get")
            for inline in parser.inline:
                inline_hash = self.save_artifact(inline.encode(), "js", url)
                for candidate, provenance in analyze_js(self.store, inline, url, inline_hash, self.config.mode == "demo"):
                    self.add_url(candidate, provenance, "artifact:" + inline_hash, depth+1, fetch=provenance != "inferred_endpoint_non_get")
            for comment in parser.comments:
                self.store.observed(url, "html-comment", {"excerpt": redact(comment[:1000]), "hash": digest}, "native")
            self.store.execute("UPDATE artifacts SET analyzed=1 WHERE hash=?", (digest,))
        for form in parser.forms:
            try:
                action = normalize_url(urljoin(url, form["action"]))
            except ValueError:
                self.store.observed(url, "invalid_reference", {"reason": "Malformed form action"}, "native")
                continue
            self.store.observed(action, "form", form, "native")
            self.add_url(action, "form-action", url, depth+1, fetch=False)
            for name in form["parameters"]:
                self.store.execute("INSERT OR IGNORE INTO parameters VALUES(?,?,?,?)", (action, name, "form", "native"))
        if "crawl" in self.config.modules:
            for candidate, provenance in parser.references:
                self.add_reference(url, candidate, provenance, depth+1)
            if urlsplit(url).path == "/robots.txt":
                for line in text.splitlines():
                    if line.lower().startswith("sitemap:"):
                        self.add_reference(url, line.split(":",1)[1].strip(), "robots-sitemap", depth+1)
            if urlsplit(url).path.endswith(".xml") and "<urlset" in text:
                import xml.etree.ElementTree as ET
                try:
                    root = ET.fromstring(text)
                    for node in root.iter():
                        if node.tag.rsplit("}",1)[-1] == "loc" and node.text:
                            self.add_url(node.text.strip(), "sitemap", url, depth+1)
                except ET.ParseError as exc:
                    self.store.observed(url, "parse_error", {"error": str(exc)}, "sitemap")
        # A bounded 200 baseline gives a similarity hint, never erases observations.
        if urlsplit(url).path.startswith("/__reconmap_missing_"):
            self.store.set_meta("baseline:" + origin, {"hash": digest, "text": text[:20000], "status": response.status})

    async def collect_passive(self) -> None:
        for name in ("subfinder", "urlfinder"):
            if name not in self.config.modules:
                continue
            previous = self.store.conn.execute("SELECT state FROM stages WHERE name=?", (name,)).fetchone()
            if previous and previous[0] == "completed":
                continue
            info = self.tools[name]
            if self.config.mode == "demo":
                self.store.stage(name, "skipped", "Demo does not contact discovery providers")
                continue
            if not info.supported:
                self.store.stage(name, "degraded", info.reason)
                continue
            cwd = self.run / "raw" / name
            cwd.mkdir(exist_ok=True)
            try:
                self.scheduler.check_time()
                argv = command(info, self.manifest["host"], cwd, self.config.budgets.provider_seconds, sources=self.config.provider_sources.get(name))
                provider_file = os.environ.get("RECONMAP_" + name.upper() + "_PROVIDER_CONFIG")
                if provider_file:
                    argv.extend(["-pc", str(Path(provider_file).absolute())])
                self.check_disk_budget(self.config.budgets.response_bytes*2)
                result = await execute(argv, cwd, min(self.config.budgets.provider_seconds, self.scheduler.remaining()), limit=min(self.config.budgets.response_bytes, self.config.budgets.artifact_bytes))
                capture(result, cwd)
                records, errors = parse_records(name, result.stdout)
                if result.code != 0:
                    self.store.stage(name, "failed", f"Execution exit {result.code}; any valid partial records retained")
                elif errors or re.search(r"(?i)\b(error|failed|timeout|denied|forbidden)\b",result.stderr):
                    self.store.stage(name, "partial", "; ".join(errors[:20]) or "Provider reported errors; see redacted raw stderr")
                else:
                    self.store.stage(name, "completed", f"{len(records)} parsed records; provider network requests are not measured")
                if len(records) > self.config.budgets.provider_results:
                    self.limit("provider result cap reached")
                for record in records[:self.config.budgets.provider_results]:
                    candidate = record["host"] if name == "subfinder" else record["url"]
                    self.store.observed(candidate, "provider", redact_data(record), name)
                    if name == "subfinder":
                        candidate = "https://" + candidate
                    self.add_url(candidate, name)
            except (OSError, ValueError, TimeoutError) as exc:
                self.store.stage(name, "failed", str(exc))

    def local_inputs(self) -> None:
        for value in self.config.local_inputs:
            path = Path(value)
            key = "local-input:" + str(path.absolute())
            if self.store.meta(key):
                continue
            try:
                if not path.is_file():
                    raise ValueError("Local input must be a regular file")
                if path.stat().st_size > self.config.budgets.response_bytes:
                    raise ValueError("Local input exceeds body cap")
                with path.open('rb') as stream:
                    body = stream.read(self.config.budgets.response_bytes + 1)
                if len(body) > self.config.budgets.response_bytes:
                    raise ValueError("Local input exceeds body cap")
                kind = "map" if path.suffix == ".map" else "js" if path.suffix == ".js" else "content"
                digest = self.save_artifact(body, kind, "local-input")
                text = body.decode(errors="replace")
                secrets(self.store, text, digest, "local-input", self.config.mode == "demo")
                if kind == "js":
                    for url, provenance in analyze_js(self.store, text, self.manifest["target"], digest, self.config.mode == "demo"):
                        self.add_url(url, provenance, "artifact:" + digest, fetch=provenance != "inferred_endpoint_non_get")
                elif kind == "map":
                    for url, provenance in analyze_map(self.store, text, self.manifest["target"], digest, self.config.budgets.response_bytes):
                        self.add_url(url, provenance, "artifact:" + digest, fetch=provenance != "inferred_endpoint_non_get")
                self.store.set_meta(key, digest)
            except (OSError, ValueError) as exc:
                self.store.stage("local-inputs", "partial", str(exc))

    async def local_tools(self) -> None:
        for name in ("gitleaks", "jsluice"):
            if name not in self.config.modules:
                continue
            info = self.tools[name]
            if not info.supported:
                self.store.stage(name, "degraded", info.reason)
                continue
            cwd = self.run / "raw" / name
            cwd.mkdir(exist_ok=True)
            artifacts = self.store.rows("artifacts")
            identity = info.sha256 + ":" + ":".join(sorted(a["hash"] for a in artifacts))
            if self.store.meta("adapter:" + name) == identity:
                continue
            files = [self.run / "assets"] if name == "gitleaks" else [self.run / a["path"] for a in artifacts if a["kind"] == "js"]
            state = "completed"
            details = []
            for path in files:
                try:
                    self.scheduler.check_time()
                    self.check_disk_budget(self.config.budgets.response_bytes*2)
                    capture_dir = cwd / path.stem if name == "jsluice" else cwd
                    capture_dir.mkdir(exist_ok=True)
                    result = await execute(command(info, self.manifest["host"], capture_dir, self.config.budgets.provider_seconds, path), capture_dir, min(self.config.budgets.provider_seconds, self.scheduler.remaining()), limit=self.config.budgets.response_bytes)
                    capture(result, capture_dir)
                    if result.code not in ({0,10} if name == "gitleaks" else {0}):
                        raise ValueError(f"Execution exit {result.code}; findings exit for Gitleaks is 10")
                    if name == "gitleaks" and (cwd / "findings.json").stat().st_size > self.config.budgets.response_bytes:
                        raise ValueError("Gitleaks findings report exceeds tool output cap")
                    text = (cwd / "findings.json").read_text(encoding="utf-8") if name == "gitleaks" else result.stdout
                    records, errors = parse_records(name, text)
                    if errors:
                        state = "partial"
                        details.extend(errors)
                    non_get_urls = {r.get("url") for r in records if r.get("method", "").upper() not in {"", "GET"}}
                    if name == "jsluice":
                        # jsluice labels dynamic fetch options GET. The stricter
                        # native parser must veto those before any scheduling,
                        # including when the analysis module is disabled.
                        routes, _, _ = js_strings(path.read_text(encoding="utf-8", errors="replace"))
                        non_get_urls.update(r["value"] for r in routes if r["method"] not in {None, "GET"})
                    for record in records:
                        if name == "gitleaks":
                            source_file = Path(record.get("File", ""))
                            match = next((a for a in artifacts if source_file.name == Path(a["path"]).name), None)
                            self.store.finding("gitleaks:" + record["RuleID"], "artifact:" + (match["hash"] if match else hashlib.sha256(str(source_file).encode()).hexdigest()), "Potential secret material (offline Gitleaks)", {"hash": match["hash"] if match else None, "line": record.get("StartLine"), "excerpt": "[REDACTED]", "synthetic": self.config.mode == "demo", "next_check": "Review context locally; credential validity is untested"}, priority=5 if self.config.mode == "demo" else 80, source="gitleaks")
                        else:
                            self.store.observed("artifact:" + path.stem, "jsluice-endpoint", redact_data(record), "jsluice")
                            if "EXPR" not in record["url"] and "${" not in record["url"]:
                                bases = [r[0] for r in self.store.conn.execute("SELECT parent FROM relationships WHERE child=? AND kind='response_body'", ("artifact:" + path.stem,)) if r[0].startswith(("http://","https://"))] or [self.manifest["target"]]
                                for base in bases:
                                    self.add_url(urljoin(base, record["url"]), "jsluice", "artifact:" + path.stem, fetch=record["url"] not in non_get_urls)
                except (OSError, ValueError, TimeoutError) as exc:
                    state = "failed"
                    details.append(str(exc))
            self.store.stage(name, state, "; ".join(details[:20]) or "Offline local artifacts processed")
            if state == "completed":
                self.store.set_meta("adapter:" + name, identity)

    def correlate(self) -> None:
        import difflib
        urls = self.store.rows("urls")
        for row in urls:
            origin = urlunsplit(urlsplit(row["url"])._replace(path="",query="",fragment=""))
            baseline = self.store.meta("baseline:" + origin)
            if baseline and row["status"] == baseline["status"] == 200 and not urlsplit(row["url"]).path.startswith("/__reconmap_missing_"):
                artifact = self.store.conn.execute("SELECT path FROM artifacts WHERE hash=?", (row["hash"],)).fetchone()
                if artifact and row["content_type"] == "text/html":
                    text = artifact_path(self.run, artifact[0]).read_text(encoding="utf-8",errors="replace")[:20000]
                    ratio = difflib.SequenceMatcher(None, baseline["text"], text, autojunk=True).ratio()
                    if ratio >= 0.9:
                        self.store.observed(row["url"], "soft-error-similarity", {"ratio": round(ratio,3), "hint": "similar to bounded missing-path baseline; manual review required"}, "native", identity="soft:" + row["url"] + ":" + row["hash"])
            if row["hash"]:
                self.store.relate(row["url"], "content-group:" + row["hash"], "exact_response_group", "native")

    async def crawl(self) -> None:
        while job := self.store.conn.execute("SELECT * FROM jobs WHERE state='queued' ORDER BY depth,rowid LIMIT 1").fetchone():
            self.scheduler.check_time()
            self.check_disk_budget()
            url, depth = job["url"], job["depth"]
            self.store.execute("UPDATE jobs SET state='running' WHERE url=?", (url,))
            for retry in range(self.config.budgets.retries+1):
                attempt = self.store.conn.execute("SELECT attempts FROM jobs WHERE url=?", (url,)).fetchone()[0] + 1
                self.store.execute("UPDATE jobs SET attempts=? WHERE url=?", (attempt, url))
                try:
                    response = await self.request(url)
                    self.process_response(url, response, depth, attempt)
                    self.scheduler.throttle(url, response.status, response.headers)
                    if response.status in {429,500,502,503,504}:
                        if retry < self.config.budgets.retries:
                            continue
                        self.store.stage("http", "partial", "Retry limit reached for throttled/server-error responses; see HTTP observations")
                    self.store.execute("UPDATE jobs SET state='completed' WHERE url=?", (url,))
                    break
                except (aiohttp.ClientError, OSError, ValueError, TimeoutError, zlib.error) as exc:
                    self.store.observed(url, "request_error", {"error": redact(str(exc)), "attempt": attempt}, "native", identity=f"error:{url}:{attempt}")
                    if retry == self.config.budgets.retries:
                        self.store.execute("UPDATE jobs SET state='failed' WHERE url=?", (url,))
                        self.store.execute("UPDATE urls SET state='failed',time=? WHERE url=?", (timestamp(),url))
                        self.store.stage("http", "partial", "Some requests failed; see observations")
            self.scheduler.checkpoint()
            atomic_json(self.run / "checkpoints" / "state.json", {"requests": self.store.meta("requests",0), "last_job": url, "time": timestamp()})

    async def run_scan(self) -> str:
        state = "completed"
        self.manifest.update({"state":"running","updated":timestamp()})
        atomic_json(self.run / "manifest.json", self.manifest)
        self.store.execute("UPDATE jobs SET state='queued' WHERE state='running'")
        self.store.stage("core", "running", "Native sequential scheduler")
        try:
            self.add_url(self.manifest["target"], "seed")
            await self.collect_passive()
            self.local_inputs()
            if "http" in self.config.modules:
                from .dnschecks import observe_dns
                await observe_dns(self)
            for name in ("dnsx","httpx","katana","nuclei"):
                if name in self.config.modules:
                    self.store.stage(name,"degraded", CAPABILITIES[name])
            if self.config.mode != "passive" and "http" in self.config.modules:
                seed = urlsplit(self.manifest["target"])
                origin = urlunsplit(seed._replace(path="/", query="", fragment=""))
                if "crawl" in self.config.modules:
                    for path in ("robots.txt","sitemap.xml","__reconmap_missing_" + hashlib.sha256(self.manifest["target"].encode()).hexdigest()[:12]):
                        self.add_url(urljoin(origin,path),"bounded-baseline",depth=0)
                if "checks" in self.config.modules:
                    for path in (".git/HEAD",".env","openapi.json","swagger.json"):
                        self.add_url(urljoin(origin,path),"exposure-profile-v1",depth=0)
                connector = aiohttp.TCPConnector(resolver=SafeResolver(self.policy,self.config,self.store), ttl_dns_cache=0, force_close=True, limit=1)
                async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=self.config.budgets.timeout), auto_decompress=False, trust_env=False, headers={"User-Agent":"reconmap/0.1 authorized-recon", "Accept-Encoding":"identity"}, cookie_jar=aiohttp.DummyCookieJar()) as session:
                    self.session = session
                    while True:
                        await self.crawl()
                        await self.local_tools()
                        # New assets from inferred endpoints must also reach the
                        # selected offline adapters, under the same shared caps.
                        if not self.store.conn.execute("SELECT 1 FROM jobs WHERE state='queued' LIMIT 1").fetchone():
                            break
            else:
                self.store.stage("http","skipped","Passive mode or HTTP module disabled: no target HTTP/TLS")
                await self.local_tools()
            self.correlate()
            self.scheduler.check_time()
            for module in ("http","crawl","analysis","checks"):
                if module not in self.config.modules:
                    continue
                previous = self.store.conn.execute("SELECT state FROM stages WHERE name=?", (module,)).fetchone()
                if self.config.mode == "passive" and module in {"http","crawl","checks"}:
                    self.store.stage(module,"skipped","Passive mode makes no target HTTP/TLS requests")
                elif not previous or previous[0] not in {"partial","failed"}:
                    self.store.stage(module,"partial" if self.limits else "completed",f"Native {module}; scope and budgets retained")
            if self.limits or any(s["state"] in {"partial","failed","degraded"} for s in self.store.rows("stages")):
                state = "partial"
        except BudgetStop as exc:
            self.limit(str(exc))
            state = "partial"
        except (asyncio.CancelledError, KeyboardInterrupt):
            state = "interrupted"
        except Exception as exc:
            self.store.stage("core-error","failed",redact(f"{type(exc).__name__}: {exc}"))
            state = "partial"
        finally:
            self.scheduler.checkpoint()
            self.store.execute("UPDATE jobs SET state='queued' WHERE state='running'")
            self.store.stage("core",state,"; ".join(self.limits))
            self.manifest.update({"state":state,"updated":timestamp(),"requests":self.store.meta("requests",0),"limits":self.limits})
            self.store.execute("UPDATE runs SET state=?,updated=? WHERE run_id=?",(state,self.manifest["updated"],self.manifest["run_id"]))
            atomic_json(self.run / "manifest.json",self.manifest)
            atomic_json(self.run / "checkpoints" / "state.json", {"state":state,"requests":self.store.meta("requests",0),"pending":self.store.conn.execute("SELECT COUNT(*) FROM jobs WHERE state='queued'").fetchone()[0],"time":timestamp()})
            from .reporting import generate_report, compare_runs
            if self.manifest.get("baseline"):
                diff = compare_runs(Path(self.manifest["baseline"]),self.run)
                atomic_json(self.run / "diff" / "comparison.json",diff)
            generate_report(self.run,self.store)
            with (self.run/"logs"/"events.jsonl").open("w",encoding="utf-8") as log:
                for row in self.store.rows("observations"):
                    log.write(json.dumps(redact_data(row),ensure_ascii=True)+"\n")
            (self.run/"logs"/"run.log").write_text(f"{timestamp()} state={state} requests={self.store.meta('requests',0)}\n"+"\n".join(redact(reason) for reason in self.limits)+"\n",encoding="utf-8")
            self.store.close()
        return state
