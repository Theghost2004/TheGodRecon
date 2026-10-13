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


def readonly_rows(run: Path, table: str) -> list[dict]:
    if table not in {"urls","findings","artifacts","stages"}:
        raise ValueError("Invalid diff table")
    uri = (run / "recon.sqlite").resolve().as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True) as db:
        db.row_factory = sqlite3.Row
        return [dict(row) for row in db.execute(f"SELECT * FROM {table}")]


def compare_runs(baseline: Path, current: Path) -> dict:
    old_manifest, new_manifest = read_manifest(baseline), read_manifest(current)
    old_config = json.loads((baseline/"config.effective.json").read_text(encoding="utf-8"))
    new_config = json.loads((current/"config.effective.json").read_text(encoding="utf-8"))
    compatible = old_config["scope"] == new_config["scope"] and old_manifest["host"] == new_manifest["host"]
    warnings = []
    if not compatible:
        warnings.append("Scope/seed differ; snapshots are not directly comparable")
    if old_config != new_config:
        warnings.append("Collection settings differ; absence may reflect different coverage")
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
for(const [element,key] of [[statusFilter,'status'],[confidenceFilter,'confidence'],[sourceFilter,'source']]) {
 for(const value of [...new Set(records.map(r=>r[key]).filter(v=>v!==undefined && v!==null))].sort()) {
  const option=document.createElement('option');option.value=String(value);option.textContent=String(value);element.appendChild(option);
 }
}
function draw() {
 const q=input.value.toLowerCase(), kind=select.value;
 for(const row of document.querySelectorAll('[data-record]')) {
  const record=records[Number(row.dataset.record)];
  row.hidden=!(JSON.stringify(record).toLowerCase().includes(q) && (!kind || record.section===kind) && (!statusFilter.value || String(record.status)===statusFilter.value) && (!confidenceFilter.value || record.confidence===confidenceFilter.value) && (!sourceFilter.value || record.source===sourceFilter.value) && (!priorityFilter.value || (record.priority!==undefined && record.priority>=Number(priorityFilter.value))));
 }
}
input.addEventListener('input',draw); select.addEventListener('change',draw);
for(const element of [statusFilter,confidenceFilter,sourceFilter,priorityFilter]) element.addEventListener('input',draw);
'''


def generate_report(run: Path, store: Store | None = None) -> None:
    manifest = redact_data(read_manifest(run))
    owned = store is None
    store = store or Store(run)
    try:
        config = redact_data(store.meta("config",{}))
        data = {table:redact_data(store.rows(table)) for table in ("runs","hosts","dns","origins","urls","parameters","observations","artifacts","relationships","findings","stages","jobs","analyst_actions")}
        reports = run/"reports"
        reports.mkdir(exist_ok=True)
        atomic_json(reports/"findings.json",data["findings"])
        atomic_json(reports/"snapshot.json",{"manifest":manifest,"config":config,**data})
        for table, rows in data.items():
            with (run/"normalized"/(table+".jsonl")).open("w",encoding="utf-8") as f:
                for row in rows:
                    f.write(json.dumps(row,ensure_ascii=True)+"\n")
        for table in ("findings","urls","parameters"):
            rows=data[table]
            keys=list(rows[0]) if rows else {"findings":["fingerprint","rule","subject","title","priority","confidence","severity","validation"],"urls":["url","state","status"],"parameters":["url","name","location","source"]}[table]
            with (reports/(table+".csv")).open("w",encoding="utf-8-sig",newline="") as f:
                writer=csv.writer(f)
                writer.writerow(keys)
                for row in rows:
                    writer.writerow([safe_csv(row.get(k)) for k in keys])
        findings=sorted(data["findings"],key=lambda f:(-f["priority"],f["fingerprint"]))
        summary = [f"# reconmap — {manifest['host']}","",f"State: {manifest['state']}",f"Transport: {manifest.get('transport')}",f"Requests reserved: {manifest.get('requests',0)} (offline fixture operations in demo)",f"URLs: {len(data['urls'])}; findings/leads: {len(findings)}", "", "Findings are investigation leads, not confirmed vulnerabilities. Priority is not exploit probability.", "", "## Scope", "", "```json",json.dumps(config.get("scope",{}),indent=2),"```","", "## Modules and coverage", ""]
        summary += [f"- {markdown_safe(s['name'])}: {markdown_safe(s['state'])} — {markdown_safe(s['detail'])}" for s in data["stages"]]
        summary += ["", "## Prioritized leads", ""]
        summary += [f"- {f['priority']} / {f['confidence']} / {f['validation']}: {markdown_safe(f['title'])} — {markdown_safe(f['subject'])}" for f in findings]
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
        for section in ("hosts","origins","urls","findings","stages","parameters","observations","changes"):
            rows=findings if section=="findings" else data[section]
            body=[]
            for row in rows:
                record={"section":section,**row}
                index=len(records); records.append(record)
                # No scanned URL becomes an automatic resource or a clickable executable scheme.
                body.append(f'<details data-record="{index}"><summary>{html.escape(str(row.get("title") or row.get("url") or row.get("host") or row.get("name") or row.get("subject") or section))}</summary><pre>{html.escape(json.dumps(row,indent=2,ensure_ascii=False))}</pre></details>')
            sections.append(f'<section><h2>{section.title()} ({len(rows)})</h2>{"".join(body)}</section>')
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
<style>body{{font:16px system-ui;max-width:1100px;margin:2rem auto;padding:1rem;background:#101827;color:#e5ecfa}}input,select{{padding:.6rem;margin:.3rem}}details{{border:1px solid #43516b;margin:.4rem 0;padding:.5rem}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}a{{color:#9fccff}}[hidden]{{display:none}}small{{color:#bbcae0}}</style>
<h1>reconmap: {html.escape(manifest['host'])}</h1><p>State: {html.escape(manifest['state'])} · Transport: {html.escape(manifest.get('transport',''))} · Requests reserved: {manifest.get('requests',0)}</p>
<p>Investigation leads require manual validation. Raw artifacts may contain sensitive content. No target resource is loaded by this report.</p>
<details><summary>Effective scope and budgets</summary><pre>{html.escape(json.dumps(config,indent=2))}</pre></details>
<label>Search <input id="search" type="search"></label><label>Section <select id="filter"><option value="">All</option>{''.join(f'<option>{s}</option>' for s in ('hosts','origins','urls','findings','stages','parameters','observations','changes'))}</select></label>
<label>Status <select id="status"><option value="">All</option></select></label><label>Confidence <select id="confidence"><option value="">All</option></select></label><label>Source <select id="source"><option value="">All</option></select></label><label>Minimum priority <input id="priority" type="number" min="0" max="100" style="width:5rem"></label>
{''.join(sections)}<h2>Applications and relationship view</h2>{relations}<h2>Restricted source artifacts</h2><ul>{artifacts}</ul><h2>Comparison</h2><pre>{diff}</pre>
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
