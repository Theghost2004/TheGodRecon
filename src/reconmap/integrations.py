"""Reviewed passive and offline adapters under the shared orchestration policy."""
import asyncio
import hashlib
import json
import os
import re
from pathlib import Path
from urllib.parse import urljoin

from .adapters import capture, command, execute, parse_records
from .analysis import js_strings
from .security import redact, redact_data
from .tool_registry import BY_NAME, execution_status

async def collect_passive(self) -> None:
    for name in ("subfinder", "urlfinder"):
        if name not in self.config.modules:
            continue
        previous = self.store.conn.execute("SELECT state FROM stages WHERE name=?", (name,)).fetchone()
        if previous and previous[0] == "completed":
            continue
        info = self.tools[name]
        if self.config.mode in {"demo", "offline"} or self.config.scope.lab:
            self.store.stage(name, "skipped", "Demo/offline/loopback lab does not contact discovery providers")
            continue
        if not info.supported:
            self.store.stage(name, execution_status(info), info.reason)
            continue
        cwd = self.run / "raw" / name
        cwd.mkdir(exist_ok=True)
        try:
            if not self.policy.host_allowed(self.manifest["host"]):
                raise ValueError("Passive seed hostname is outside scope")
            self.store.stage(name, "running", "Reviewed provider allowlist; native scheduling validates every returned candidate")
            invocation = int(self.store.meta("invocations:" + name, 0)) + 1
            self.store.set_meta("invocations:" + name, invocation)
            cwd = cwd / f"{invocation:04d}"
            cwd.mkdir()
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
                state, detail = "failed", f"Execution exit {result.code}; any valid partial records retained"
            elif errors or re.search(r"(?i)\b(error|failed|timeout|denied|forbidden)\b",result.stderr):
                state, detail = "partial", "; ".join(errors[:20]) or "Provider reported errors; see redacted raw stderr"
            else:
                state, detail = "completed", f"{len(records)} parsed records; provider network requests are not measured"
            if len(records) > self.config.budgets.provider_results:
                self.limit("provider result cap reached")
            for record in records[:self.config.budgets.provider_results]:
                candidate = record["host"] if name == "subfinder" else record["url"]
                self.store.observed(candidate, "provider", redact_data(record), name, identity=hashlib.sha256(f"{name}:{record}".encode()).hexdigest())
                if name == "subfinder":
                    candidate = "https://" + candidate
                self.add_url(candidate, name)
            self.store.stage(name, state, detail)
        except (OSError, ValueError, TimeoutError) as exc:
            self.store.stage(name, "failed", str(exc))


async def local_tools(self) -> None:
    for name in ("jsluice", "gitleaks"):
        if name not in self.config.modules:
            continue
        info = self.tools[name]
        if not info.supported:
            self.store.stage(name, execution_status(info), info.reason)
            continue
        cwd = self.run / "raw" / name
        cwd.mkdir(exist_ok=True)
        artifacts = self.store.rows("artifacts")
        if not artifacts or (name == "jsluice" and not any(a["kind"] == "js" for a in artifacts)):
            self.store.stage(name, "skipped", "No suitable local artifacts; provide local_inputs or a captured parent run")
            continue
        identity = info.sha256 + ":" + ":".join(sorted(a["hash"] for a in artifacts))
        if self.store.meta("adapter:" + name) == identity:
            continue
        files = [self.run / "assets"] if name == "gitleaks" else [self.run / a["path"] for a in artifacts if a["kind"] == "js"]
        state = "completed"
        details = []
        for path in files:
            try:
                artifact_key = f"jsluice-artifact:{info.sha256}:{path.stem}"
                if name == "jsluice" and self.store.meta(artifact_key):
                    continue
                self.store.stage(name, "running", "Local captured artifacts only")
                self.scheduler.check_time()
                self.check_disk_budget(self.config.budgets.response_bytes*2)
                invocation = int(self.store.meta("invocations:" + name, 0)) + 1
                self.store.set_meta("invocations:" + name, invocation)
                input_key = path.stem if name == "jsluice" else hashlib.sha256(identity.encode()).hexdigest()
                capture_dir = cwd / f"{invocation:04d}_{input_key}"
                capture_dir.mkdir()
                result = await execute(command(info, self.manifest["host"], capture_dir, self.config.budgets.provider_seconds, path), capture_dir, min(self.config.budgets.provider_seconds, self.scheduler.remaining()), limit=self.config.budgets.response_bytes)
                capture(result, capture_dir)
                if result.code not in ({0,10} if name == "gitleaks" else {0}):
                    raise ValueError(f"Execution exit {result.code}; findings exit for Gitleaks is 10")
                if name == "gitleaks" and (capture_dir / "findings.json").stat().st_size > self.config.budgets.response_bytes:
                    raise ValueError("Gitleaks findings report exceeds tool output cap")
                text = (capture_dir / "findings.json").read_text(encoding="utf-8") if name == "gitleaks" else result.stdout
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
                        synthetic = self.config.mode == "demo" or self.manifest.get("synthetic", False)
                        self.store.finding("gitleaks:" + record["RuleID"], "artifact:" + (match["hash"] if match else hashlib.sha256(str(source_file).encode()).hexdigest()), "Potential secret material (offline Gitleaks)", {"hash": match["hash"] if match else None, "line": record.get("StartLine"), "excerpt": "[REDACTED]", "synthetic": synthetic, "next_check": "Review context locally; credential validity is untested"}, priority=5 if synthetic else 80, source="gitleaks")
                    else:
                        self.store.observed("artifact:" + path.stem, "jsluice-endpoint", redact_data(record), "jsluice", identity=hashlib.sha256(f"jsluice:{path.stem}:{record}".encode()).hexdigest())
                        if "EXPR" not in record["url"] and "${" not in record["url"]:
                            bases = [r[0] for r in self.store.conn.execute("SELECT parent FROM relationships WHERE child=? AND kind='response_body'", ("artifact:" + path.stem,)) if r[0].startswith(("http://","https://"))] or [self.manifest["target"]]
                            for base in bases:
                                self.add_url(urljoin(base, record["url"]), "jsluice", "artifact:" + path.stem, fetch=record["url"] not in non_get_urls)
                if name == "jsluice" and not errors:
                    self.store.set_meta(artifact_key, True)
            except (OSError, ValueError, TimeoutError) as exc:
                state = "failed"
                details.append(str(exc))
        self.store.stage(name, state, "; ".join(details[:20]) or "Offline local artifacts processed")
        if state == "completed":
            self.store.set_meta("adapter:" + name, identity)
