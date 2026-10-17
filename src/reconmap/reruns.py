"""Separate, immutable executions reusing verified copies of parent evidence."""
import hashlib
import json
import shutil
import os
import signal
import uuid
import time
from pathlib import Path

from .config import ConfigError, ScanConfig
from .scope import ScopePolicy
from .selectors import resolve_selection, select_tools
from .storage import Store, artifact_path, atomic_json, read_manifest, timestamp
from .tool_registry import BY_NAME


def verify_parent(parent, config):
    manifest = read_manifest(parent)
    if (parent / "run.lock").exists() or manifest["state"] in {"running", "created"}:
        raise ConfigError("Parent run must be stopped and unlocked before rerun; it is never modified by rerun")
    store = Store(parent, readonly=True)
    try:
        artifacts = store.rows("artifacts")
        if any(type(a["bytes"]) is not int or a["bytes"] < 0 or a["kind"] not in {"js", "map", "content"} for a in artifacts):
            raise ConfigError("Invalid artifact metadata in parent database")
        total = sum(a["bytes"] for a in artifacts)
        if total + 2*(parent/'recon.sqlite').stat().st_size + 128*1024 >= config.budgets.artifact_bytes:
            raise ConfigError("Reused artifacts/metadata exceed new run artifact budget")
        for artifact in artifacts:
            path = artifact_path(parent, artifact["path"])
            if path.stat().st_size != artifact["bytes"] or artifact["bytes"] > config.budgets.response_bytes:
                raise ConfigError("Parent artifact size is incompatible with saved metadata or new response cap")
            with path.open('rb') as content:
                if hashlib.file_digest(content, 'sha256').hexdigest() != artifact["hash"]:
                    raise ConfigError("Parent artifact content hash mismatch; preserve and investigate the original evidence")
        return manifest, artifacts
    finally:
        store.close()


def reuse_evidence(parent, child, manifest, config, artifacts):
    source = Store(parent, readonly=True)
    destination = Store(child)
    offline = config.mode == "offline"
    started = time.monotonic()
    elapsed = float(destination.meta("elapsed_seconds", 0))
    def checkpoint():
        from .engine import BudgetStop
        consumed = elapsed + time.monotonic() - started
        destination.set_meta("elapsed_seconds", consumed)
        if consumed >= config.budgets.minutes * 60:
            raise BudgetStop("rerun copy time cap reached")
    try:
        parent_manifest = read_manifest(parent)
        synthetic = parent_manifest.get("transport") == "offline-fixtures" or parent_manifest.get("synthetic", False)
        destination.set_meta("synthetic", synthetic)
        digest = hashlib.sha256(json.dumps(sorted(a["hash"] for a in artifacts)).encode()).hexdigest()
        manifest.update(synthetic=synthetic, lineage={"parent_run_id": parent_manifest["run_id"], "parent_path": str(parent.resolve()), "kind": "offline-reanalysis" if offline else "fresh-selected-recollection", "reused_artifact_count": len(artifacts), "parent_artifact_digest": digest, "parent_config_digest": parent_manifest["config_digest"], "parent_decisions_are_inherited": False, "initialization_pending": True})
        manifest["transport"] = "offline-reanalysis" if offline else "native-http"
        atomic_json(child / "manifest.json", manifest)
        for artifact in artifacts:
            checkpoint()
            original = artifact_path(parent, artifact["path"])
            target = artifact_path(child, artifact["path"])
            if target.exists():
                with target.open('rb') as content:
                    if hashlib.file_digest(content, 'sha256').hexdigest() != artifact["hash"]:
                        raise ConfigError("Previously copied child artifact changed; refusing overwrite")
            else:
                temporary = child / 'tmp' / (uuid.uuid4().hex + '.copy')
                try:
                    shutil.copyfile(original, temporary)
                    temporary.chmod(0o600)
                    with temporary.open('rb') as content:
                        if hashlib.file_digest(content, 'sha256').hexdigest() != artifact["hash"]:
                            raise ConfigError("Artifact changed while being copied; no altered evidence published")
                    os.replace(temporary, target)
                finally:
                    temporary.unlink(missing_ok=True)
            destination.execute("INSERT OR IGNORE INTO artifacts VALUES(?,?,?,?,0)", (artifact["hash"], artifact["path"], artifact["kind"], artifact["bytes"]))
        destination.set_meta("artifact_bytes", sum(a["bytes"] for a in artifacts))
        # Copy evidence, not work queues, caches of completed analysis, findings
        # or analyst decisions. Every selected analysis receives a fresh identity.
        for table in ("hosts", "dns", "origins", "urls", "parameters", "observations", "relationships", "technologies", "historical_urls", "provider_cache", "infrastructure"):
            checkpoint()
            columns = [r[1] for r in destination.conn.execute(f"PRAGMA table_info({table})")]
            placeholders = ','.join('?' for _ in columns)
            for row in source.rows(table):
                if "source" in row and table != "provider_cache":
                    row["source"] = "parent:" + row["source"]
                if table == "observations" and row.get("identity"):
                    # Fresh request attempt 1 must not collide with the parent's
                    # http:URL:1 observation and silently lose its new response.
                    row["identity"] = "parent:" + parent_manifest["run_id"] + ":" + row["identity"]
                if table == "urls" and not offline:
                    for name in ("status", "title", "content_type", "hash", "bytes", "time"):
                        row[name] = None
                    row["state"] = "untested"
                destination.conn.execute(f"INSERT OR IGNORE INTO {table}({','.join(columns)}) VALUES({placeholders})", tuple(row.get(c) for c in columns))
            destination.conn.commit()
        destination.set_meta("rerun_targets", [r["url"] for r in source.rows("urls")] if not offline and "http" in config.modules else [])
        parent_decisions = [{k: r[k] for k in ("fingerprint", "status", "note", "time")} for r in source.rows("analyst_actions")]
        metadata = {"parent_analyst_decisions": parent_decisions, "reused_observations": len(source.rows("observations")), "interpretation": "Reused HTTP observations refer to the parent collection timestamp; no new liveness is implied by offline analysis"}
        destination.execute("INSERT OR REPLACE INTO lineage VALUES(?,?,?,?,?,?,?,?,?)", (manifest["run_id"], parent_manifest["run_id"], str(parent.resolve()), manifest["lineage"]["kind"], json.dumps(config.selected_tools or []), config.digest(), timestamp(), json.dumps([a["hash"] for a in artifacts]), json.dumps(metadata)))
        destination.set_meta("reanalyze-artifacts", True)
        checkpoint()
        manifest["lineage"]["initialization_pending"] = False
        atomic_json(child / "manifest.json", manifest)
    finally:
        destination.set_meta("elapsed_seconds", elapsed + time.monotonic() - started)
        destination.close(); source.close()


def initialize_rerun(path, manifest, config, initialize=None):
    from .engine import BudgetStop
    previous = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM, lambda *unused: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        if initialize is not None:
            initialize(path, manifest)
        elif manifest.get("lineage", {}).get("initialization_pending"):
            parent = Path(manifest["lineage"]["parent_path"])
            original, artifacts = verify_parent(parent, config)
            digest = hashlib.sha256(json.dumps(sorted(a["hash"] for a in artifacts)).encode()).hexdigest()
            if original["run_id"] != manifest["lineage"]["parent_run_id"] or original["config_digest"] != manifest["lineage"]["parent_config_digest"] or digest != manifest["lineage"]["parent_artifact_digest"]:
                raise ConfigError("Pending rerun parent identity changed")
            reuse_evidence(parent, path, manifest, config, artifacts)
        store = Store(path)
        store.stage("rerun-initialization", "completed", "Verified evidence copies and lineage are ready")
        store.close()
        return None
    except (KeyboardInterrupt, BudgetStop) as exc:
        from .reporting import generate_report
        state = "interrupted" if isinstance(exc, KeyboardInterrupt) else "partial"
        manifest.update(state=state, updated=timestamp(), requests=0)
        atomic_json(path/'manifest.json', manifest)
        atomic_json(path/'checkpoints/state.json', {"state":state, "initialization_pending":True})
        store = Store(path)
        store.stage("rerun-initialization", state, "Evidence copy interrupted; resume verifies the same parent" if state == "interrupted" else str(exc))
        store.execute("UPDATE runs SET state=?,updated=? WHERE run_id=?", (state, manifest['updated'], manifest['run_id']))
        store.close()
        generate_report(path)
        return state
    finally:
        signal.signal(signal.SIGTERM, previous)


def analyze_reused(scanner):
    if not scanner.store.meta("reanalyze-artifacts") or "analysis" not in scanner.config.modules:
        return
    from .analysis import analyze_js, analyze_map, secrets
    from .selectors import capability_enabled
    synthetic = scanner.manifest.get("synthetic", False)
    for artifact in scanner.store.rows("artifacts"):
        if artifact["analyzed"]:
            continue
        with artifact_path(scanner.run, artifact["path"]).open('rb') as stream:
            body = stream.read(scanner.config.budgets.response_bytes + 1)
        if len(body) > scanner.config.budgets.response_bytes:
            raise ConfigError("Reused artifact exceeds analysis cap")
        text = body.decode(errors="replace")
        if capability_enabled(scanner.config, "gitleaks") and "gitleaks" not in scanner.config.modules:
            secrets(scanner.store, text, artifact["hash"], "reanalysis", synthetic)
        bases = [r[0] for r in scanner.store.conn.execute("SELECT parent FROM relationships WHERE child=? AND kind='response_body'", ("artifact:" + artifact["hash"],)) if r[0].startswith(("http://", "https://"))] or [scanner.manifest["target"]]
        for base in bases:
            if not capability_enabled(scanner.config, "jsluice") or "jsluice" in scanner.config.modules:
                continue
            refs = analyze_js(scanner.store, text, base, artifact["hash"], synthetic, scan_secrets=False) if artifact["kind"] == "js" else analyze_map(scanner.store, text, base, artifact["hash"], scanner.config.budgets.response_bytes, synthetic, scan_secrets=False) if artifact["kind"] == "map" else []
            for url, provenance in refs:
                scanner.add_url(url, provenance, "artifact:" + artifact["hash"], fetch=provenance != "inferred_endpoint_non_get")
        scanner.store.execute("UPDATE artifacts SET analyzed=1 WHERE hash=?", (artifact["hash"],))


def finalize_lineage(scanner, comparison=None):
    rows = scanner.store.rows("lineage")
    if not rows:
        return
    row = rows[0]
    metadata = json.loads(row["metadata"])
    reused = set(json.loads(row["reused_artifacts"]))
    metadata.update({
        "tool_versions": {name: info.record() for name, info in scanner.tools.items()},
        "completion": scanner.manifest["state"],
        "stage_completion": [{"name": s["name"], "state": s["state"], "detail": s["detail"]} for s in scanner.store.rows("stages")],
        "new_artifact_hashes": sorted(a["hash"] for a in scanner.store.rows("artifacts") if a["hash"] not in reused),
        "new_target_http_observations": sum(o["kind"] == "http" and o["source"] == "native" for o in scanner.store.rows("observations")),
        "new_target_requests_reserved": scanner.store.meta("requests", 0),
        "owned_provider_requests_reserved": scanner.store.meta("provider_requests", 0),
        "new_findings": [f["fingerprint"] for f in (comparison or {}).get("new_findings", [])],
        "findings_not_observed": [f["fingerprint"] for f in (comparison or {}).get("findings_not_observed", [])],
        "comparison_warnings": (comparison or {}).get("warnings", []),
    })
    scanner.store.execute("UPDATE lineage SET metadata=? WHERE run_id=?", (json.dumps(metadata), scanner.manifest["run_id"]))


def rerun(args):
    from .cli import effective_config, run
    parent = args.parent.absolute()
    parent_manifest = read_manifest(parent)
    parent = parent.resolve()
    if (args.target or args.target_pos) and (args.target or args.target_pos) != parent_manifest["target"]:
        raise ConfigError("Rerun keeps the parent seed; use scan for a different target")
    if args.tools is None and args.modules is None and args.profile is None and not args.all_tool and not args.god_mode:
        raise ConfigError("Rerun requires --tools, --modules or --profile; for local reanalysis use --tools offline")
    # Reuse the explicit saved authorization, unless a current YAML is supplied.
    args.resume = parent
    config = effective_config(args)
    if args.config is None:
        config.local_inputs = []
    if args.enrich is None and args.profile != "full" and not args.god_mode:
        config.enrichments = [name for name in config.enrichments if name not in {"asn", "wayback"}]
    if args.tools is not None and all(BY_NAME[n].risk == "offline" for n in select_tools(args.tools)) and args.mode is None:
        config = resolve_selection(config, tools=args.tools, mode="offline", enrich=args.enrich or (",".join(e for e in config.enrichments if e in {"tech","dedup","priority"}) or "none"))
    if config.mode == "demo":
        raise ConfigError("Fresh rerun uses --mode standard or offline; demo is a separate deterministic command")
    network_selected = (config.mode not in {"offline", "passive"} and bool({"http", "dns"} & set(config.modules))) or (config.mode != "offline" and bool({"subfinder", "urlfinder"} & set(config.modules) or {"asn", "wayback"} & set(config.enrichments)))
    if args.config is None and network_selected and (parent_manifest.get("transport") == "offline-fixtures" or parent_manifest.get("synthetic")):
        raise ConfigError("Synthetic fixture evidence does not authorize real recollection; supply a current --config or choose an offline rerun")
    if not ScopePolicy(config.scope).decision(parent_manifest["target"])[0]:
        raise ConfigError("Parent seed is denied by the current scope")
    parent_manifest, artifacts = verify_parent(parent, config)
    def initialize(child, manifest):
        reuse_evidence(parent, child, manifest, config, artifacts)
    return run(config, parent_manifest["target"], args.output_root or parent.parent, baseline=args.baseline or parent, initialize=initialize, no_progress=args.no_progress)
