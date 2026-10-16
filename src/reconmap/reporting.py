from __future__ import annotations

import csv
import base64
import hashlib
import html
import json
import sqlite3
from pathlib import Path

from .security import redact, redact_data
from .storage import Store, atomic_json, read_manifest, safe_csv
from .schema_v2 import V2_TABLES
from .schema_v3 import V3_TABLES


def readonly_rows(run: Path, table: str) -> list[dict]:
    if table not in {"urls","findings","artifacts","stages"} | V2_TABLES | V3_TABLES:
        raise ValueError("Invalid diff table")
    uri = (run / "recon.sqlite").resolve().as_uri() + "?mode=ro"
    wal = run / "recon.sqlite-wal"
    if not wal.exists() or wal.stat().st_size == 0:
        uri += "&immutable=1"
    with sqlite3.connect(uri, uri=True) as db:
        db.row_factory = sqlite3.Row
        if table in V2_TABLES and db.execute("PRAGMA user_version").fetchone()[0] < 2:
            return []
        if table in V3_TABLES and db.execute("PRAGMA user_version").fetchone()[0] < 3:
            return []
        return [dict(row) for row in db.execute(f"SELECT * FROM {table}")]


def compare_runs(baseline: Path, current: Path) -> dict:
    old_manifest, new_manifest = read_manifest(baseline), read_manifest(current)
    if (baseline / "run.lock").exists() or old_manifest["state"] == "running" or ((baseline / "recon.sqlite-wal").exists() and (baseline / "recon.sqlite-wal").stat().st_size):
        raise ValueError("Baseline must be stopped, unlocked and checkpointed before immutable comparison")
    old_config = json.loads((baseline/"config.effective.json").read_text(encoding="utf-8"))
    new_config = json.loads((current/"config.effective.json").read_text(encoding="utf-8"))
    compatible = old_config["scope"] == new_config["scope"] and old_manifest["host"] == new_manifest["host"]
    warnings = []
    if not compatible:
        warnings.append("Scope/seed differ; snapshots are not directly comparable")
    if old_config != new_config:
        warnings.append("Collection settings differ; absence may reflect different coverage")
    if old_manifest["state"] != "completed" or old_manifest.get("limits"):
        warnings.append("Baseline coverage is incomplete; additions may reflect newly collected coverage")
    if new_manifest["state"] != "completed" or new_manifest.get("limits"):
        warnings.append("Current coverage is incomplete; absence is not proof of unavailability")
    old = {r["url"]:r for r in readonly_rows(baseline,"urls")}
    new = {r["url"]:r for r in readonly_rows(current,"urls")}
    changed = [{"url":u,"before":{k:old[u][k] for k in ("state","status","hash")},"after":{k:new[u][k] for k in ("state","status","hash")}} for u in sorted(old.keys() & new.keys()) if any(old[u][k]!=new[u][k] for k in ("state","status","hash"))]
    old_findings = {f["fingerprint"]:f for f in readonly_rows(baseline,"findings")}
    new_findings = {f["fingerprint"]:f for f in readonly_rows(current,"findings")}
    return redact_data({"baseline":str(baseline.absolute()),"current":str(current.absolute()),"compatible":compatible,"warnings":warnings,"new_assets":sorted(new.keys()-old.keys()),"changed_assets":changed,"not_observed_this_time":sorted(old.keys()-new.keys()),"new_findings":[new_findings[k] for k in sorted(new_findings.keys()-old_findings.keys())],"findings_not_observed":[old_findings[k] for k in sorted(old_findings.keys()-new_findings.keys())],"confirmed_unavailable":[],"interpretation":"Failed, skipped or absent observations never establish confirmed unavailability"})


REPORT_SCRIPT = r'''
const records = JSON.parse(document.getElementById('data').textContent);
const input = document.getElementById('search'), select = document.getElementById('filter');
const statusFilter=document.getElementById('status'), confidenceFilter=document.getElementById('confidence'), sourceFilter=document.getElementById('source'), priorityFilter=document.getElementById('priority');
const sourceNames=record=>(Array.isArray(record.sources)?record.sources:[record.source]).filter(value=>typeof value==='string' && value);
for(const [element,key] of [[statusFilter,'status'],[confidenceFilter,'confidence']]) {
 for(const value of [...new Set(records.map(r=>r[key]).filter(v=>v!==undefined && v!==null))].sort()) {
  const option=document.createElement('option');option.value=String(value);option.textContent=String(value);element.appendChild(option);
 }
}
for(const value of [...new Set(records.flatMap(sourceNames))].sort()) {
 const option=document.createElement('option');option.value=value;option.textContent=value;sourceFilter.appendChild(option);
}
const openedByFilter=new Set();
function draw() {
 for(const group of openedByFilter) group.open=false;
 openedByFilter.clear();
 const q=input.value.trim().toLowerCase(), kind=select.value;
 const active=Boolean(q || kind || statusFilter.value || confidenceFilter.value || sourceFilter.value || priorityFilter.value);
 let matches=0;
 for(const row of document.querySelectorAll('[data-record]')) {
  const record=records[Number(row.dataset.record)];
  row.hidden=!(JSON.stringify(record).toLowerCase().includes(q) && (!kind || record.section===kind) && (!statusFilter.value || String(record.status)===statusFilter.value) && (!confidenceFilter.value || record.confidence===confidenceFilter.value) && (!sourceFilter.value || sourceNames(record).includes(sourceFilter.value)) && (!priorityFilter.value || (record.priority!==undefined && record.priority>=Number(priorityFilter.value))));
  if(!row.hidden) {
   matches++;
   if(active) for(let parent=row.parentElement;parent;parent=parent.parentElement) {
    if(parent.tagName==='DETAILS' && !parent.open) {parent.open=true;openedByFilter.add(parent);}
   }
  }
 }
 for(const view of document.querySelectorAll('[data-view], [data-collection-details]')) view.hidden=active && !view.querySelector('[data-record]:not([hidden])');
 document.getElementById('filter-summary').textContent=active?`${matches} matching record${matches===1?'':'s'}`:'Showing all records. Expand a view to inspect its evidence.';
}
input.addEventListener('input',draw); select.addEventListener('change',draw);
for(const element of [statusFilter,confidenceFilter,sourceFilter,priorityFilter]) element.addEventListener('input',draw);
for(const link of document.querySelectorAll('nav a')) link.addEventListener('click',()=>{select.value=link.textContent;draw();});
draw();
'''


def export_row(row):
    """Redact decoded JSON fields so masking cannot corrupt escaped JSON syntax."""
    structured = {"data", "result_json", "evidence", "reasons", "factors", "identity_json", "metrics_json", "metadata", "selected_tools", "reused_artifacts", "config_json", "parameter_names"}
    result = {}
    for key, value in row.items():
        if key in structured and isinstance(value, str):
            try:
                result[key] = json.dumps(redact_data(json.loads(value)), ensure_ascii=True)
                continue
            except ValueError:
                pass
        result[key] = redact_data(value)
    return result


def generate_report(run: Path, store: Store | None = None) -> None:
    manifest = redact_data(read_manifest(run))
    owned = store is None
    store = store or Store(run)
    try:
        config = redact_data(store.meta("config",{}))
        from .config import PrioritySettings
        from .enrichment.prioritization import prioritize
        prioritize(store, PrioritySettings.model_validate(store.meta("config", {}).get("priority", {})))
        data = {table:[export_row(r) for r in store.rows(table)] for table in ("runs","hosts","dns","origins","urls","parameters","observations","artifacts","relationships","findings","stages","jobs","analyst_actions","tool_executions","historical_urls","infrastructure","technologies","url_groups","url_group_members","endpoint_priority","lineage","stage_results","normalized_records","investigation_candidates")}
        for table, column in (("stage_results", "result_json"), ("normalized_records", "data"), ("investigation_candidates", "data")):
            data[table] = [json.loads(row[column]) for row in data[table]]
        candidates = sorted(data["investigation_candidates"], key=lambda c: (-c["score"], c["url"], c["identity"]))
        shortlist = [c for c in candidates if c["representative"] and c["tier"] != "inventory"]
        run_summary = {
            "selected_tools": [t["name"] for t in data["tool_executions"]],
            "executed_tools": [t["selected_primary_tool"] for t in data["stage_results"] if t["selected_primary_tool"] in t["actual_execution_engines"] and t["primary_status"] == "completed"],
            "native_fallbacks": [t["stage"] for t in data["stage_results"] if t["fallback_used"]],
            "partial_coverage": [{"stage": t["stage"], "status": t["status"], "reason": t["failure_reason"], "limitations": t["coverage_limitations"]} for t in data["stage_results"] if t["status"] != "completed"],
            "discovered_assets": len(data["urls"]), "currently_observed_assets": len({c["url"] for c in candidates if c["current_status"] is not None}),
            "high_interest": sum(c["tier"] == "high-interest" for c in shortlist), "manual_review": sum(c["tier"] == "manual-review" for c in shortlist),
            "duplicate_cards_suppressed": sum(not c["representative"] for c in candidates), "low_value_inventory": sum(c["tier"] == "inventory" for c in candidates),
            "target_requests": store.meta("requests", 0), "owned_provider_requests": store.meta("provider_requests", 0), "runtime_seconds": round(store.meta("elapsed_seconds", 0), 2),
        }
        reports = run/"reports"
        reports.mkdir(exist_ok=True)
        atomic_json(reports/"findings.json",data["findings"])
        atomic_json(reports/"investigation.json", {"summary": run_summary, "shortlist": shortlist, "all_results": candidates})
        atomic_json(reports/"stage-results.json", data["stage_results"])
        atomic_json(reports/"snapshot.json",{"manifest":manifest,"config":config,"summary":run_summary,**data})
        for table, rows in data.items():
            with (run/"normalized"/(table+".jsonl")).open("w",encoding="utf-8") as f:
                for row in rows:
                    f.write(json.dumps(row,ensure_ascii=True)+"\n")
        for table in ("findings","urls","parameters","historical_urls","infrastructure","technologies","url_groups","endpoint_priority","investigation_candidates","normalized_records","stage_results"):
            rows=data[table]
            keys=list(rows[0]) if rows else {"findings":["fingerprint","rule","subject","title","priority","confidence","severity","validation"],"urls":["url","state","status"],"parameters":["url","name","location","source"]}.get(table, ["No records"])
            with (reports/(table+".csv")).open("w",encoding="utf-8-sig",newline="") as f:
                writer=csv.writer(f)
                writer.writerow(keys)
                for row in rows:
                    writer.writerow([safe_csv(row.get(k)) for k in keys])
        findings=sorted(data["findings"],key=lambda f:(-f["priority"],f["fingerprint"]))
        summary = [f"# reconmap — {manifest['host']}","",f"State: {manifest['state']}",f"Transport: {manifest.get('transport')}",f"Requests reserved: {manifest.get('requests',0)} (offline fixture operations in demo)",f"URLs: {len(data['urls'])}; findings/leads: {len(findings)}", "", "Findings are investigation leads, not confirmed vulnerabilities. Priority is not exploit probability.", "", "## Scope", "", "```json",json.dumps(config.get("scope",{}),indent=2),"```","", "## Modules and coverage", ""]
        summary += [f"- {markdown_safe(s['name'])}: {markdown_safe(s['state'])} — {markdown_safe(s['detail'])}" for s in data["stages"]]
        summary += ["", f"Owned metadata-provider requests reserved: {manifest.get('owned_provider_requests',0)}. External Subfinder/URLFinder provider counts are unknown."]
        summary += ["", "## Investigation shortlist", "", f"High interest: {run_summary['high_interest']}; manual review: {run_summary['manual_review']}; grouped cards: {run_summary['duplicate_cards_suppressed']}; low-value inventory: {run_summary['low_value_inventory']}.", ""]
        summary += [f"- {c['review_priority']} / {c['evidence_confidence']} / {c['reachability']}: {markdown_safe(c['classification'])} — {markdown_safe(c['url'])} ({c['group_size']} group members). {markdown_safe(c['next_check'])}" for c in shortlist]
        if data["lineage"]:
            summary += ["", "## Rerun evidence", "", "Reused HTTP observations refer to the parent collection time. Offline reanalysis does not establish current liveness. Parent analyst decisions remain in the original run.", ""]
        summary += ["", "## Data handling", "", "Reports and normalized exports are pattern-redacted; review before sharing. Raw inputs under assets/ are restricted local evidence and may contain sensitive data. Delete the complete run directory for retention cleanup after closing scans/reports. No retention job runs automatically."]
        (reports/"summary.md").write_text("\n".join(summary)+"\n",encoding="utf-8")
        records=[]
        sections=[]
        diff_path=run/"diff"/"comparison.json"
        comparison=json.loads(diff_path.read_text(encoding="utf-8")) if diff_path.exists() else {}
        changes=[]
        for name in ("new_assets","changed_assets","not_observed_this_time","new_findings","findings_not_observed"):
            changes.extend({"change":name,**(item if isinstance(item,dict) else {"url":item})} for item in comparison.get(name,[]))
        data["changes"]=changes
        primary_views = {
            "Live Assets": [c for c in candidates if c["current_status"] is not None and c["allowed"]],
            "Interesting Endpoints": [c for c in shortlist if c["classification"] != "potential-exposure"],
            "Potential Exposures": [c for c in candidates if c["classification"] == "potential-exposure" and c["representative"]],
            "All Results": candidates,
        }
        # Secret detectors often report the same artifact. Show one evidence card
        # with every supporting finding, keeping original analyst decisions intact.
        secret_groups = {}
        for finding in findings:
            evidence = json.loads(finding["evidence"])
            if not finding["subject"].startswith("artifact:") or finding["validation"] == "dismissed":
                continue
            key = evidence.get("hash") or finding["subject"]
            secret_groups.setdefault(key, []).append(finding)
        for key, members in secret_groups.items():
            synthetic = any(json.loads(m["evidence"]).get("synthetic") for m in members)
            primary_views["Potential Exposures"].append({"url": "artifact:" + key, "classification": "potential-secret", "review_priority": "Low" if synthetic else "Review", "score": 5 if synthetic else 55,
                "evidence_confidence": "low" if synthetic else "medium", "reachability": "local evidence; credential validity untested", "method": "N/A", "sources": sorted({m["source"] for m in members}),
                "reasons": ["Recognized syntax in captured content; no provider validation", "Synthetic fixture" if synthetic else "Review ownership and intended publication"],
                "next_check": "Inspect the saved source context locally. Do not test credentials automatically.", "group_size": len(members), "evidence": members})
        for label, rows in primary_views.items():
            body = []
            for row in sorted(rows, key=lambda r: (-r["score"], r["url"])):
                index = len(records)
                records.append({"section": label, **row, "priority": row["score"], "confidence": row["evidence_confidence"], "source": ", ".join(row["sources"]), "status": row["reachability"]})
                facts = " · ".join([row["classification"], row.get("method", "UNKNOWN"), row["reachability"], "Confidence: " + row["evidence_confidence"], f"Group: {row['group_size']}"])
                why = "".join("<li>" + html.escape(reason) + "</li>" for reason in row["reasons"])
                body.append(f'<details data-record="{index}"><summary><strong>{html.escape(row["review_priority"])}</strong> · {html.escape(row.get("method", "UNKNOWN"))} {html.escape(row["url"])} <small>· {html.escape(row["reachability"])}</small></summary><p>{html.escape(facts)}</p><p>Sources: {html.escape(", ".join(row["sources"]))}</p><ul>{why}</ul><p><strong>Next check:</strong> {html.escape(row["next_check"])}</p><details><summary>Supporting evidence and preserved group members</summary><pre>{html.escape(json.dumps(row,indent=2,ensure_ascii=False))}</pre></details></details>')
            body_text = "".join(body) or "<p>No candidates in this view.</p>"
            anchor = label.lower().replace(" ", "-")
            if label in {"All Results", "Live Assets"}:
                description = "Open preserved inventory, including low-value observations" if label == "All Results" else "Inspect current HTTP observations, including restricted responses and redirects"
                sections.append(f'<section data-view="{label}" id="{anchor}"><h2>{label} ({len(rows)})</h2><details><summary>{description}</summary>{body_text}</details></section>')
            else:
                sections.append(f'<section data-view="{label}" id="{anchor}"><h2>{label} ({len(rows)})</h2>{body_text}</section>')
        views = ("tool_executions","stage_results","stages","historical_urls","infrastructure","technologies","url_groups","url_group_members","parameters","observations","findings","lineage","changes")
        secondary = []
        for section in views:
            body = []
            for row in data[section]:
                index = len(records)
                records.append({"section": section, **row})
                title = row.get("title") or row.get("url") or row.get("host") or row.get("name") or row.get("stage") or row.get("subject") or section
                body.append(f'<details data-record="{index}"><summary>{html.escape(str(title))}</summary><pre>{html.escape(json.dumps(row,indent=2,ensure_ascii=False))}</pre></details>')
            secondary.append(f'<details data-view="{section}"><summary>{section.replace("_", " ").title()} ({len(data[section])})</summary>{"".join(body)}</details>')
        sections.append('<details data-collection-details><summary>Collection details, original detector records and raw exports</summary>' + ''.join(secondary) + '</details>')
        relations="".join(f'<details><summary>{html.escape(r["parent"])}</summary><pre>{html.escape(json.dumps(r,indent=2))}</pre></details>' for r in data["relationships"])
        artifacts="".join(f'<li>{html.escape(a["hash"])} — {html.escape(a["path"])} ({a["bytes"]} bytes, restricted raw input)</li>' for a in data["artifacts"])
        # Evidence links point only to safely generated local hash files. No target URLs/resources load.
        artifacts="".join(f'<li><a href="../{html.escape(a["path"],quote=True)}" download>{html.escape(a["hash"])}</a> — restricted raw {html.escape(a["kind"])}</li>' for a in data["artifacts"] if re_safe_artifact(a["path"]))
        diff=html.escape(diff_path.read_text(encoding="utf-8")) if diff_path.exists() else "No baseline selected"
        payload=json.dumps(records,ensure_ascii=True).replace("<","\\u003c").replace(">","\\u003e").replace("&","\\u0026")
        script_hash = base64.b64encode(hashlib.sha256(REPORT_SCRIPT.encode()).digest()).decode()
        document=f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'sha256-{script_hash}'; style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; base-uri 'none'; form-action 'none'">
<title>reconmap {html.escape(manifest['host'])}</title>
<style>body{{font:16px system-ui;max-width:1100px;margin:2rem auto;padding:1rem;background:#101827;color:#e5ecfa;overflow-wrap:anywhere}}input,select{{padding:.6rem;margin:.3rem;max-width:100%;box-sizing:border-box}}label{{display:inline-block;max-width:100%}}details{{border:1px solid #43516b;margin:.4rem 0;padding:.5rem}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}a{{color:#9fccff}}[hidden]{{display:none}}small{{color:#bbcae0}}</style>
<h1>TheGodRecon V3: {html.escape(manifest['host'])}</h1><p>State: {html.escape(manifest['state'])} · Transport: {html.escape(manifest.get('transport',''))} · Requests reserved: {manifest.get('requests',0)}</p>
<p>Investigation leads require manual validation. Raw artifacts may contain sensitive content. No target resource is loaded by this report.</p>
<p>Historical URLs are archive metadata, not current liveness. Rerun observations may be reused from a parent's collection timestamp. Technology confidence does not confirm a software version or vulnerability.</p>
<details><summary>Effective scope and budgets</summary><pre>{html.escape(json.dumps(config,indent=2))}</pre></details>
<nav>{' · '.join(f'<a href="#{label.lower().replace(" ", "-")}">{label}</a>' for label in primary_views)}</nav>
<p><strong>{run_summary['high_interest']} high-interest · {run_summary['manual_review']} manual-review</strong> · {run_summary['currently_observed_assets']} currently observed / {run_summary['discovered_assets']} discovered · {run_summary['duplicate_cards_suppressed']} repeated cards grouped · {run_summary['low_value_inventory']} low-value records retained · {run_summary['runtime_seconds']}s runtime.</p>
<p>Selected tools: {html.escape(', '.join(run_summary['selected_tools']) or 'Native modules')}<br>Successfully executed: {html.escape(', '.join(run_summary['executed_tools']) or 'See native execution details')}<br>Native fallbacks: {html.escape(', '.join(s.replace('-', ' ') for s in run_summary['native_fallbacks']) or 'None')}</p>
<details><summary>Partial or missing coverage ({len(run_summary['partial_coverage'])})</summary><pre>{html.escape(json.dumps(run_summary['partial_coverage'],indent=2))}</pre></details>
<p><a href="investigation.json" download>Investigation export</a> · <a href="snapshot.json" download>Complete redacted snapshot</a> · <a href="stage-results.json" download>Execution accounting</a></p>
<label>Search <input id="search" type="search"></label><label>Section <select id="filter"><option value="">All</option>{''.join(f'<option>{s}</option>' for s in (*primary_views, *views))}</select></label>
<label>Status <select id="status"><option value="">All</option></select></label><label>Confidence <select id="confidence"><option value="">All</option></select></label><label>Source <select id="source"><option value="">All</option></select></label><label>Minimum priority <input id="priority" type="number" min="0" max="100" style="width:5rem"></label>
<p id="filter-summary" role="status" aria-live="polite"></p>
{''.join(sections)}<details><summary>Evidence relationships</summary>{relations}</details><details><summary>Restricted source artifacts</summary><ul>{artifacts}</ul></details><details><summary>Comparison</summary><pre>{diff}</pre></details>
<script id="data" type="application/json">{payload}</script><script>{REPORT_SCRIPT}</script></html>'''
        (reports/"index.html").write_text(document,encoding="utf-8")
    finally:
        if owned:
            store.close()


def re_safe_artifact(value: str) -> bool:
    import re
    return bool(re.fullmatch(r"assets/(?:js|maps|content)/[0-9a-f]{64}\.(?:js|json|bin)",value))


def markdown_safe(value: str) -> str:
    import re
    return re.sub(r"([\\`*_{}\[\]()#!|])",r"\\\1",html.escape(value.replace("\n"," ").replace("\r"," ")))
