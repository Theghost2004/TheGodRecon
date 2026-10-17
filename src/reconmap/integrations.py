"""Primary-first adapters, durable input checkpoints and policy-bound fallbacks."""
import asyncio
import hashlib
import json
import os
import re
import time
from pathlib import Path
from urllib.parse import urljoin

from .adapters import capture, command, execute, parse_records, ProcessResult
from .analysis import analyze_js, analyze_map, js_strings, secrets, source_maps
from .security import redact, redact_data
from .storage import artifact_path
from .tool_registry import execution_status
from .orchestrator import fallback_allowed, record_execution, NATIVE_ENGINES


async def invoke(scanner, info, cwd, input_path=None):
    scanner.scheduler.check_time()
    scanner.check_disk_budget(scanner.config.budgets.response_bytes * 2)
    argv = command(info, scanner.manifest["host"], cwd, scanner.config.budgets.provider_seconds,
                   input_path, sources=scanner.config.provider_sources.get(info.name))
    if info.name in {"subfinder", "urlfinder"}:
        provider_file = os.environ.get("RECONMAP_" + info.name.upper() + "_PROVIDER_CONFIG")
        if provider_file:
            argv.extend(["-pc", str(Path(provider_file).absolute())])
    try:
        result = await execute(argv, cwd, min(scanner.config.budgets.provider_seconds, scanner.scheduler.remaining()),
                               limit=scanner.config.budgets.response_bytes, expected_sha=info.sha256,
                               output_files=(cwd / "findings.json",) if info.name == "gitleaks" else ())
        error = ""
    except asyncio.CancelledError as exc:
        if hasattr(exc, "result"):
            scanner.store.set_meta("executed:"+info.name, True)
            capture(exc.result, cwd)
        raise
    except (TimeoutError, ValueError) as exc:
        if not hasattr(exc, "result"):
            raise
        result, error = exc.result, str(exc)
    scanner.store.set_meta("executed:"+info.name, True)
    capture(result, cwd)
    return result, error


def invocation_directory(scanner, name, suffix=""):
    number = int(scanner.store.meta("invocations:" + name, 0)) + 1
    scanner.store.set_meta("invocations:" + name, number)
    directory = scanner.run / "raw" / name / (f"{number:04d}" + ("_" + suffix if suffix else ""))
    directory.mkdir(parents=True)
    return directory


async def _collect_passive(scanner, names):
    for name in names:
        if name not in scanner.config.modules:
            continue
        previous = scanner.store.conn.execute("SELECT state FROM stages WHERE name=?", (name,)).fetchone()
        if previous and previous[0] == "completed":
            continue
        info = scanner.tools[name]
        if scanner.config.mode in {"demo", "offline"} or scanner.config.scope.lab:
            reason = "Demo/offline/loopback lab does not contact discovery providers"
            scanner.store.stage(name, "skipped", reason)
            record_execution(scanner, name, state="skipped", reason=reason)
            continue
        limitation = "No native subdomain enumerator; seed/reference inventory only" if name == "subfinder" else "CDX fallback requires explicit Wayback enrichment; historical records are not live evidence"
        if not info.supported:
            scanner.store.stage(name, execution_status(info), info.reason)
            record_execution(scanner, name, state=execution_status(info), reason=info.reason, limitations=[limitation])
            continue
        started = time.monotonic()
        cwd = None
        count = 0
        state, detail = "failed", ""
        try:
            if not scanner.policy.host_allowed(scanner.manifest["host"]):
                raise ValueError("Passive seed hostname is outside scope")
            scanner.store.stage(name, "running", "Reviewed providers; all returned candidates re-enter scope policy")
            record_execution(scanner, name, engine=name, state="running")
            cwd = invocation_directory(scanner, name)
            result, error = await invoke(scanner, info, cwd)
            records, errors = parse_records(name, result.stdout)
            state = "failed" if result.code != 0 or error else "partial" if errors or re.search(r"(?i)\b(error|failed|timeout|denied|forbidden)\b", result.stderr) else "completed"
            detail = error or "; ".join(errors[:20]) or (f"Exit {result.code}; valid partial records retained" if result.code else "Provider requests are not measured")
            if len(records) > scanner.config.budgets.provider_results:
                scanner.limit("provider result cap reached")
                state = "partial"
            for record in records[:scanner.config.budgets.provider_results]:
                candidate = record["host"] if name == "subfinder" else record["url"]
                scanner.store.observed(candidate, "provider", redact_data(record), name,
                    identity=hashlib.sha256(f"{name}:{record}".encode()).hexdigest())
                if name == "subfinder":
                    candidate = "https://" + candidate
                else:
                    scanner.store.observed(candidate, "historical-discovery", {"current_liveness": "untested", "artifact": str(cwd.relative_to(scanner.run))}, name,
                                           identity="urlfinder-history:" + hashlib.sha256(candidate.encode()).hexdigest())
                scanner.add_url(candidate, name)
                count += 1
        except (OSError, ValueError, TimeoutError) as exc:
            detail = redact(str(exc))
        finally:
            # Cancellation escapes; a running primary is finalized as interrupted by the engine.
            if not asyncio.current_task().cancelling():
                scanner.store.stage(name, state, detail)
                record_execution(scanner, name, engine=name, state=state, reason=detail, count=count,
                    seconds=time.monotonic()-started, outputs=[str(cwd.relative_to(scanner.run))] if cwd else [],
                    accounting={"target_requests": 0, "provider_requests": None},
                    limitations=[limitation] if state != "completed" else [])


def artifact_bases(scanner, artifact):
    return sorted({r[0] for r in scanner.store.conn.execute(
        "SELECT parent FROM relationships WHERE child=? AND kind='response_body'", ("artifact:" + artifact["hash"],))
        if r[0].startswith(("http://", "https://"))}) or [scanner.manifest["target"]]


def artifact_depth(scanner, base):
    row = scanner.store.conn.execute("SELECT depth FROM jobs WHERE url=?", (base,)).fetchone()
    return (row[0] if row else 0) + 1


def emit_js(scanner, artifact, text, records, bases, capture_ref):
    # Method/option analysis is a safety veto, not a second discovery engine.
    routes, unresolved, _ = js_strings(text)
    denied = {r["value"]: r["method"] for r in routes if r["method"] not in {None, "GET"}}
    for expression in unresolved:
        scanner.store.observed("artifact:" + artifact["hash"], "unresolved_expression", {"expression": expression, "hash": artifact["hash"]}, "js-safety",
                               identity=hashlib.sha256(f"{artifact['hash']}:{expression}".encode()).hexdigest())
    for record in records:
        scanner.store.observed("artifact:" + artifact["hash"], "jsluice-endpoint", redact_data(record), "jsluice",
                               identity=hashlib.sha256(f"jsluice:{artifact['hash']}:{record}".encode()).hexdigest())
        if "EXPR" in record["url"] or "${" in record["url"]:
            continue
        method = record.get("method", "").upper() or "UNKNOWN"
        method_restricted = record["url"] in denied
        for base in bases:
            try:
                url = urljoin(base, record["url"])
                scanner.store.observed(url, "inferred_endpoint", {**redact_data(record), "method": method, "hash": artifact["hash"], "artifact": capture_ref,
                    "state": "inferred from code; never confirms execution", "source_url": base}, "jsluice",
                    identity=hashlib.sha256(f"{base}:{artifact['hash']}:{record}".encode()).hexdigest())
                scanner.add_url(url, "jsluice", "artifact:" + artifact["hash"], depth=artifact_depth(scanner, base), fetch=method == "GET" and not method_restricted)
                for location, key in (("query", "queryParams"), ("body-inferred", "bodyParams")):
                    for param in record.get(key, []) if isinstance(record.get(key, []), list) else []:
                        if isinstance(param, str):
                            scanner.store.execute("INSERT OR IGNORE INTO parameters VALUES(?,?,?,?)", (url, param, location, "jsluice"))
            except ValueError as exc:
                scanner.store.observed(base, "invalid_reference", {"reason": str(exc)}, "jsluice")
    for base in bases:
        for candidate, provenance in source_maps(scanner.store, text, base):
            scanner.add_url(candidate, provenance, "artifact:" + artifact["hash"], depth=artifact_depth(scanner, base))


def native_artifact(scanner, name, artifact, text, bases):
    synthetic = scanner.config.mode == "demo" or scanner.manifest.get("synthetic", False)
    if name == "gitleaks":
        secrets(scanner.store, text, artifact["hash"], "native-fallback", synthetic)
        return
    for base in bases:
        refs = analyze_map(scanner.store, text, base, artifact["hash"], scanner.config.budgets.response_bytes, synthetic, scan_secrets=False) if artifact["kind"] == "map" else analyze_js(scanner.store, text, base, artifact["hash"], synthetic, scan_secrets=False)
        for candidate, provenance in refs:
            scanner.add_url(candidate, provenance, "artifact:" + artifact["hash"], depth=artifact_depth(scanner, base), fetch=provenance != "inferred_endpoint_non_get")


async def _local_tools(scanner, names):
    for name in names:
        if name not in scanner.config.modules:
            continue
        info = scanner.tools[name]
        artifacts = [a for a in scanner.store.rows("artifacts") if name == "gitleaks" or a["kind"] in {"js", "map"}]
        if not artifacts:
            scanner.store.stage(name, "skipped", "No suitable local artifacts")
            record_execution(scanner, name, state="skipped", reason="No suitable local artifacts")
            continue
        states, details = [], []
        for artifact in artifacts:
            scanner.scheduler.check_time()
            path = artifact_path(scanner.run, artifact["path"])
            with path.open('rb') as stream:
                body = stream.read(scanner.config.budgets.response_bytes + 1)
            if len(body) > scanner.config.budgets.response_bytes or hashlib.sha256(body).hexdigest() != artifact["hash"]:
                raise ValueError("Artifact size/hash verification failed before analysis")
            text = body.decode(errors="replace")
            bases = artifact_bases(scanner, artifact)
            key = f"v3-primary:{name}:{info.sha256}:{artifact['hash']}"
            work = scanner.store.meta(key)
            if work is None:
                started = time.monotonic()
                cwd = None
                records = []
                state, detail = execution_status(info), info.reason
                supplementary = name == "jsluice" and artifact["kind"] == "map"
                if supplementary:
                    state, detail = "skipped", "Embedded source maps require native parsing; jsluice accepts JavaScript"
                elif info.supported:
                    try:
                        scanner.store.stage(name, "running", "Local captured artifact only")
                        record_execution(scanner, name, engine=name, state="running", inputs=[artifact["path"]])
                        cwd = invocation_directory(scanner, name, artifact["hash"])
                        result, error = await invoke(scanner, info, cwd, path)
                        output = result.stdout
                        if name == "gitleaks":
                            report = cwd / "findings.json"
                            if report.exists():
                                with report.open('rb') as stream:
                                    content = stream.read(scanner.config.budgets.response_bytes + 1)
                                if len(content) > scanner.config.budgets.response_bytes:
                                    raise ValueError("Gitleaks report exceeds output cap")
                                output = content.decode(errors="replace")
                            else:
                                output, error = "[]", error or "Gitleaks report missing"
                        records, errors = parse_records(name, output)
                        state = "failed" if error or result.code not in ({0, 10} if name == "gitleaks" else {0}) else "partial" if errors else "completed"
                        detail = error or "; ".join(errors[:20]) or (f"Exit {result.code}; valid records retained" if state == "failed" else "Local artifact processed")
                    except (asyncio.CancelledError, KeyboardInterrupt):
                        record_execution(scanner, name, engine=name, state="interrupted", reason="Tool cancelled; bounded raw prefix retained where available", seconds=time.monotonic()-started,
                            inputs=[artifact["path"]], outputs=[str(cwd.relative_to(scanner.run))] if cwd else [])
                        raise
                    except (OSError, ValueError, TimeoutError) as exc:
                        state, detail = "failed", redact(str(exc))
                work = {"state": state, "detail": detail, "records": records, "capture": str(cwd.relative_to(scanner.run)) if cwd else "", "supplementary": supplementary}
                # Save parsed partial output before fallback; interrupted fallback does not restart primary.
                scanner.store.set_meta(key, work)
                if not supplementary:
                    record_execution(scanner, name, engine=name if cwd else None, state=state, reason=detail,
                        inputs=[artifact["path"]], outputs=[work["capture"]] if cwd else [], count=len(records),
                        seconds=time.monotonic()-started, accounting={"target_requests": 0, "provider_requests": 0},
                        limitations=[detail] if state not in {"completed", "skipped"} else [])
            states.append(work["state"])
            details.append(work["detail"])
            context_key = key + ":handled:" + hashlib.sha256(json.dumps(bases if name == "jsluice" else []).encode()).hexdigest()
            if scanner.store.meta(context_key):
                continue
            if name == "jsluice" and artifact["kind"] == "js":
                emit_js(scanner, artifact, text, work["records"], bases, work["capture"])
            elif name == "gitleaks":
                for record in work["records"]:
                    synthetic = scanner.config.mode == "demo" or scanner.manifest.get("synthetic", False)
                    scanner.store.finding("gitleaks:" + record["RuleID"], "artifact:" + artifact["hash"], "Potential secret material (offline Gitleaks)",
                        {"hash": artifact["hash"], "line": record.get("StartLine"), "excerpt": "[REDACTED]", "synthetic": synthetic, "artifact": work["capture"], "next_check": "Review context locally; credential validity is untested"}, priority=5 if synthetic else 80, source="gitleaks")
            empty_js = name == "jsluice" and work["state"] == "completed" and not work["records"]
            if (work["state"] != "completed" or empty_js) and fallback_allowed(scanner, name):
                started = time.monotonic()
                before = scanner.store.conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0] + scanner.store.conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
                native_artifact(scanner, name, artifact, text, bases)
                count = scanner.store.conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0] + scanner.store.conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] - before
                record_execution(scanner, name, engine=NATIVE_ENGINES[name], fallback=not work["supplementary"], count=count,
                    inputs=[artifact["path"]], seconds=time.monotonic()-started, accounting={"target_requests": 0, "provider_requests": 0},
                    limitations=[] if work["supplementary"] or empty_js else ["Native fallback has narrower coverage than the selected tool"])
            scanner.store.observed("artifact:"+artifact["hash"], "artifact-analysis", {
                "tool": name, "primary_status": work["state"], "primary_records": len(work["records"]),
                "fallback": work["state"] != "completed" or empty_js, "contexts": bases,
                "reason": "Primary returned zero leads; native AST analysis also applied" if empty_js else work["detail"],
                "hash": artifact["hash"], "artifact": work["capture"], "processed": True,
            }, name, identity="artifact-analysis:"+context_key)
            scanner.store.set_meta(context_key, True)
        state = next((s for s in ("failed", "partial", "incompatible", "unavailable", "blocked-by-policy") if s in states), "completed")
        scanner.store.stage(name, state, "; ".join(dict.fromkeys(details))[:4000])


async def _independent(scanner, names, worker):
    """At most two bounded subprocess consumers; HTTP stays on its own queue."""
    semaphore = asyncio.Semaphore(scanner.config.discovery.max_concurrent_jobs)
    async def one(name):
        async with semaphore:
            try:
                await worker(scanner, (name,))
            except (OSError, ValueError, TimeoutError) as exc:
                # Failed input/tool must not prevent the other local capability.
                scanner.store.stage(name, "partial", redact(str(exc)))
                record_execution(scanner, name, state="partial", reason=str(exc), limitations=["Some inputs unprocessed"])
    tasks = [asyncio.create_task(one(name)) for name in names if name in scanner.config.modules]
    try:
        await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            if not task.done(): task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def collect_passive(scanner):
    await _independent(scanner, ("subfinder", "urlfinder"), _collect_passive)


async def local_tools(scanner):
    await _independent(scanner, ("jsluice", "gitleaks"), _local_tools)
