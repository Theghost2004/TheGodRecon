"""Explainable fingerprints from captured evidence, with no network requests."""
import hashlib
import json
import re

from ..security import redact
from ..storage import artifact_path, timestamp

RULES = (
    ("Next.js", "body", r"(?:/_next/static/|__NEXT_DATA__)", "medium"),
    ("React", "body", r"(?:data-reactroot|react\.production\.min|react-dom(?:[./-]))", "low"),
    ("Vue", "body", r"(?:vue\.runtime|data-v-[0-9a-f]{6,}|Vue\.createApp)", "low"),
    ("WordPress", "body", r"(?:/wp-content/|/wp-includes/)", "medium"),
    ("Django", "body", r"(?:csrfmiddlewaretoken|__admin_media_prefix__)", "medium"),
    ("GraphQL", "body", r"(?:__schema\s*[:{]|GraphQL Playground|graphiql)", "medium"),
    ("Swagger/OpenAPI", "body", r"(?:swagger-ui|[\"']openapi[\"']\s*:)", "medium"),
    ("nginx", "server", r"\bnginx\b", "medium"),
    ("Apache HTTP Server", "server", r"\bApache\b", "medium"),
    ("Microsoft IIS", "server", r"\bMicrosoft-IIS\b", "medium"),
    ("Express", "x-powered-by", r"\bExpress\b", "medium"),
    ("PHP", "x-powered-by", r"\bPHP\b", "medium"),
    ("ASP.NET", "x-powered-by", r"\bASP\.NET\b", "medium"),
    ("Cloudflare", "server", r"\bcloudflare\b", "medium"),
    ("WordPress", "cookie-names", r"\bwordpress_(?:logged_in|sec)_", "medium"),
    ("Django", "cookie-names", r"\bcsrftoken\b", "low"),
    ("PHP", "cookie-names", r"\bPHPSESSID\b", "low"),
    ("ASP.NET", "cookie-names", r"\bASP\.NET_SessionId\b", "low"),
)


def fingerprint(store, subject, headers, text, digest):
    signals = {}
    fields = {**{k.lower(): v for k, v in headers.items()}, "body": text}
    fields["cookie-names"] = " ".join(re.findall(r"(?:^|[,;]\s*)([A-Za-z0-9_.-]+)=", headers.get("set-cookie", "")))
    for name, location, pattern, confidence in RULES:
        match = re.search(pattern, fields.get(location, ""), re.I)
        if match:
            signals.setdefault(name, []).append({"location": location, "signature": pattern, "excerpt": redact(match[0][:200]), "confidence": confidence, "hash": digest})
    generator = re.search(r'<meta\s+[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)', text, re.I)
    if generator:
        name = next((v for v in ("WordPress", "Drupal", "Joomla") if v.lower() in generator[1].lower()), None)
        if name:
            signals.setdefault(name, []).append({"location": "generator-meta", "excerpt": redact(generator[1][:200]), "confidence": "medium", "hash": digest})
    for name, evidence in signals.items():
        identity = hashlib.sha256(f"{subject}\0{name}\0{digest}".encode()).hexdigest()
        previous = store.conn.execute("SELECT evidence FROM technologies WHERE identity=?", (identity,)).fetchone()
        if previous:
            # Captured/report redaction removes cookie values. Preserve previously
            # recorded cookie-name-only signals instead of replacing them.
            keys = {(e['location'], e.get('signature')) for e in evidence}
            evidence += [e for e in json.loads(previous[0])["signals"] if (e['location'], e.get('signature')) not in keys]
        locations = {e["location"] for e in evidence}
        confidence = "high" if len(locations) >= 2 else "medium" if any(e["confidence"] == "medium" for e in evidence) else "low"
        store.execute("INSERT OR REPLACE INTO technologies VALUES(?,?,?,?,?,?,?,?)", (identity, subject, name, "", confidence, json.dumps({"signals": evidence, "version": "unknown; no version inferred from weak markers"}), "captured-signatures-v1", timestamp()))


def analyze_captured(scanner):
    headers = {}
    for row in scanner.store.rows("observations"):
        if row["kind"] == "http":
            data = json.loads(row["data"])
            headers[row["subject"]] = data.get("headers", {})
    count = 0
    for row in scanner.store.rows("urls"):
        if not row["hash"]:
            continue
        artifact = scanner.store.conn.execute("SELECT path FROM artifacts WHERE hash=?", (row["hash"],)).fetchone()
        if artifact:
            with artifact_path(scanner.run, artifact[0]).open('rb') as stream:
                text = stream.read(scanner.config.budgets.response_bytes).decode(errors="replace")
            fingerprint(scanner.store, row["url"], headers.get(row["url"], {}), text, row["hash"])
            count += 1
    for row in scanner.store.rows("artifacts"):
        if row["kind"] == "js":
            with artifact_path(scanner.run, row["path"]).open('rb') as stream:
                fingerprint(scanner.store, "artifact:" + row["hash"], {}, stream.read(scanner.config.budgets.response_bytes).decode(errors="replace"), row["hash"])
    scanner.store.stage("tech", "completed", f"{count} captured URL bodies considered; no additional requests or CVE validation")
