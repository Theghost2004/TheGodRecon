from __future__ import annotations

import hashlib
import json
import re
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin

from tree_sitter import Language, Parser
import tree_sitter_javascript

from .security import SECRET_PATTERNS, redact
from .config import normalize_url
from .storage import Store


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.references: list[tuple[str, str]] = []
        self.forms: list[dict] = []
        self.inline: list[str] = []
        self.comments: list[str] = []
        self.title = ""
        self.in_title = False
        self.in_script = False
        self.script_text: list[str] = []
        self.form: dict | None = None
        self.truncated = False

    def reference(self, value: str, kind: str) -> None:
        if len(self.references) < 10000 and len(value) < 8192:
            self.references.append((value,kind))
        else:
            self.truncated = True

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        if tag == "title":
            self.in_title = True
        if tag in {"a", "link"} and a.get("href"):
            self.reference(a["href"], "link")
        if tag == "script":
            self.in_script = True
            self.script_text = []
            if a.get("src"):
                self.reference(a["src"], "script")
        if tag == "form":
            self.form = {"action": a.get("action") or "", "method": (a.get("method") or "GET").upper(), "parameters": []}
            if len(self.forms) < 1000:
                self.forms.append(self.form)
            else:
                self.truncated = True
                self.form = None
        if tag in {"input", "textarea", "select"} and self.form is not None and a.get("name"):
            if len(self.form["parameters"]) < 1000 and len(a["name"]) <= 256:
                self.form["parameters"].append(a["name"])
            else:
                self.truncated = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self.in_title = False
        if tag == "script":
            self.in_script = False
            if self.script_text:
                self.inline.append("".join(self.script_text))
        if tag == "form":
            self.form = None

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title = (self.title + data)[:500]
        if self.in_script:
            self.script_text.append(data)

    def handle_comment(self, data: str) -> None:
        if len(self.comments) < 1000:
            self.comments.append(data[:1000])
        else:
            self.truncated = True


def literal_text(value: str) -> str:
    value = re.sub(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})", lambda m: chr(int(m[1] or m[2], 16)), value)
    return value.replace("\\/", "/").replace("\\'", "'").replace('\\"', '"')


def request_method(node, raw: bytes) -> str | None:
    """Read method syntax from the AST; unknown methods must never imply GET."""
    call = node.parent
    while call and call.type not in {"call_expression", "new_expression", "program"}:
        call = call.parent
    if not call or call.type == "program":
        return None
    function = call.child_by_field_name("function") or call.child_by_field_name("constructor")
    name = raw[function.start_byte:function.end_byte].decode(errors="replace") if function else ""
    args = call.child_by_field_name("arguments")
    values = [n for n in args.named_children if n.type != "comment"] if args else []

    def static(n):
        if n.type not in {"string", "template_string"} or any(c.type == "template_substitution" for c in n.named_children):
            return None
        return literal_text(raw[n.start_byte+1:n.end_byte-1].decode(errors="replace"))

    member = name.rsplit(".", 1)[-1].lower()
    if "." in name and member in {"get", "post", "put", "patch", "delete", "head", "options"}:
        return member.upper()
    if "." in name and member == "open":
        return (static(values[0]) or "UNKNOWN").upper() if values else "UNKNOWN"
    if name in {"fetch", "window.fetch", "globalThis.fetch", "Request"}:
        if len(values) < 2:
            return "GET"
        options = values[1]
        if options.type != "object":
            return "UNKNOWN"
        method = "GET"
        for prop in options.named_children:
            if prop.type == "comment":
                continue
            if prop.type != "pair":
                return "UNKNOWN"  # spread, shorthand, getters or computed runtime options
            key = prop.child_by_field_name("key")
            if key.type not in {"property_identifier", "string"}:
                return "UNKNOWN"
            key_text = static(key) if key.type == "string" else raw[key.start_byte:key.end_byte].decode()
            if key_text == "__proto__":
                return "UNKNOWN"
            if key_text == "method":
                method = (static(prop.child_by_field_name("value")) or "UNKNOWN").upper()
        return method
    return None


def js_strings(text: str) -> tuple[list[dict], list[str], list[str]]:
    """Parse strings in real JavaScript syntax; never evaluate target code."""
    parser = Parser(Language(tree_sitter_javascript.language()))
    raw = text.encode("utf-8", errors="replace")
    tree = parser.parse(raw)
    routes: list[dict] = []
    unresolved: list[str] = []
    parameters: list[str] = []
    stack = [tree.root_node]
    visited = 0
    while stack:
        node = stack.pop()
        visited += 1
        if visited > 200000:
            unresolved.append("AST node cap reached")
            break
        stack.extend(reversed(node.named_children))
        value = raw[node.start_byte:node.end_byte].decode(errors="replace")
        if node.type == "template_string" and any(c.type == "template_substitution" for c in node.named_children):
            unresolved.append(redact(value[:300]))
        if node.type in {"string", "template_string"}:
            if node.type == "template_string" and "${" in value:
                continue
            parent = node.parent
            dynamic = None
            while parent and parent.type not in {"arguments","program","variable_declarator","pair"}:
                if parent.type in {"binary_expression","template_substitution"}:
                    dynamic = parent
                    break
                parent = parent.parent
            if dynamic:
                unresolved.append(redact(raw[dynamic.start_byte:dynamic.end_byte].decode(errors="replace")[:300]))
                continue
            literal = literal_text(value[1:-1])
            call = node.parent.parent if node.parent and node.parent.type == "arguments" else None
            function = call.child_by_field_name("function") if call and call.type == "call_expression" else None
            function_name = raw[function.start_byte:function.end_byte].decode(errors="replace") if function else ""
            network_relative = bool(function_name == "fetch" or re.fullmatch(r"(?:axios|\w+)\.(?:get|post|put|patch|delete)",function_name)) and node.parent.named_children[0] == node
            if (literal.startswith(("/", "https://", "http://")) or network_relative) and literal and len(literal) < 8192:
                context = raw[max(0,node.start_byte-100):node.end_byte+300].decode(errors="replace")[:1000]
                routes.append({"value": literal, "method": request_method(node, raw), "line": node.start_point.row + 1, "context": redact(context)})
        if node.type == "pair":
            key = node.child_by_field_name("key")
            if key:
                name = raw[key.start_byte:key.end_byte].decode(errors="replace").strip("\"'")
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,80}", name):
                    parameters.append(name)
    if tree.root_node.has_error:
        unresolved.append("JavaScript contains syntax errors; recovered AST coverage is partial")
    return routes, unresolved, sorted(set(parameters))


def secrets(store: Store, text: str, artifact_hash: str, source: str, synthetic: bool = False) -> None:
    for rule, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            line = text[:match.start()].count("\n") + 1
            excerpt = redact(text[max(0, match.start()-40):match.end()+40])
            fingerprint = hashlib.sha256(match[0].encode()).hexdigest()
            store.finding(rule, f"artifact:{artifact_hash}:{fingerprint}", "Synthetic secret fixture" if synthetic else "Potential secret material; do not validate automatically", {"hash": artifact_hash, "line": line, "excerpt": excerpt, "synthetic": synthetic, "secret_fingerprint": fingerprint, "next_check": "Review ownership and context locally; never contact the credential provider automatically"}, confidence="low" if synthetic else "medium", priority=5 if synthetic else 80, reasons=["synthetic test data" if synthetic else "recognized secret syntax; validity untested"], source=source)


def basic_checks(store: Store, url: str, text: str, headers: dict[str, str], artifact_hash: str, status: int) -> None:
    evidence = {"hash": artifact_hash, "status": status, "next_check": "Review authorization and whether this exposure is intended; no vulnerability is confirmed"}
    signatures = [
        ("git-head", r"(?m)^ref: refs/heads/", "Potential exposed source-control metadata", 75),
        ("environment-config", r"(?m)^(?:DB_PASSWORD|DATABASE_URL|SECRET_KEY|AWS_SECRET_ACCESS_KEY)\s*=", "Potential exposed configuration", 85),
        ("directory-index", r"(?i)<title>\s*Index of |<h1>\s*Index of ", "Directory listing candidate", 55),
        ("debug-surface", r"(?i)(Werkzeug Debugger|Django administration|swagger-ui|phpinfo\(\))", "Debug, management or documentation surface", 50),
        ("api-docs", r'''["'](?:openapi|swagger)["']\s*:''', "API documentation lead", 45),
    ]
    if status == 200:
        for rule, pattern, title, score in signatures:
            match = re.search(pattern, text)
            if match:
                store.finding(rule, url, title, {**evidence, "excerpt": redact(text[max(0, match.start()-30):match.end()+70])}, priority=score, reasons=["current response matches a bounded exposure signature"])
    if headers.get("access-control-allow-origin"):
        store.observed(url, "cors", {"origin": headers.get("access-control-allow-origin"), "credentials": headers.get("access-control-allow-credentials"), "validation": "context required; no cross-origin credential request made"}, "native")
    path = url.lower()
    if any(p in path for p in ("/api/", "upload", "import", "export", "invite", "account", "admin")):
        store.finding("route-lead", url, "Route worth manual investigation", evidence, confidence="low", priority=45 + (10 if status in {401, 403} else 0), reasons=["sensitive functionality name", "restricted response remains a live asset" if status in {401,403} else "current HTTP response"])


def analyze_js(store: Store, text: str, source_url: str, artifact_hash: str, synthetic: bool = False) -> list[tuple[str, str]]:
    cache_key = "js-method-v2:" + artifact_hash
    cached = store.meta(cache_key)
    if cached is None:
        routes, unresolved, parameters = js_strings(text)
        cached = {"routes": routes, "unresolved": unresolved, "parameters": parameters}
        store.set_meta(cache_key, cached)
        secrets(store, text, artifact_hash, "tree-sitter", synthetic)
    output: list[tuple[str, str]] = []
    for route in cached["routes"]:
        try:
            url = normalize_url(urljoin(source_url, route["value"]))
        except ValueError:
            store.observed(source_url, "invalid_reference", {"value": redact(route["value"][:1000]), "reason": "Malformed JavaScript URL"}, "tree-sitter")
            continue
        store.observed(url, "inferred_endpoint", {**route, "hash": artifact_hash, "state": "inferred from code; never confirms execution"}, "tree-sitter", identity=hashlib.sha256(f"{source_url}:{artifact_hash}:{route}".encode()).hexdigest())
        store.relate("artifact:" + artifact_hash, url, "inferred_endpoint", source_url)
        if any(part in url.lower() for part in ("/api/","upload","import","export","invite","account")):
            store.finding("inferred-route-lead",url,"Inferred route; traffic and authorization unverified",{"hash":artifact_hash,"line":route["line"],"method":route["method"],"excerpt":route["context"],"next_check":"Review code context and permitted manual requests; no runtime execution is implied"},priority=20,confidence="low",reasons=["static JavaScript route and source context; inferred only"],source="tree-sitter")
        for name, _ in parse_qsl(route["value"].split("?",1)[1] if "?" in route["value"] else "", keep_blank_values=True):
            store.execute("INSERT OR IGNORE INTO parameters VALUES(?,?,?,?)", (url, name, "query", "tree-sitter"))
        output.append((url, "inferred_endpoint_non_get" if route["method"] not in {None,"GET"} else "inferred_endpoint"))
    for expression in cached["unresolved"]:
        if expression == "AST node cap reached" or "syntax errors" in expression:
            store.stage("analysis","partial",expression)
        store.observed(source_url, "unresolved_expression", {"hash": artifact_hash, "expression": expression}, "tree-sitter", identity=hashlib.sha256(f"{source_url}:{expression}".encode()).hexdigest())
    for name in cached["parameters"]:
        store.execute("INSERT OR IGNORE INTO parameters VALUES(?,?,?,?)", (source_url, name, "code-key-unresolved", "tree-sitter"))
    for match in re.finditer(r"[#@]\s*sourceMappingURL\s*=\s*([^\s*]+)", text):
        try:
            output.append((normalize_url(urljoin(source_url, match[1])), "source_map"))
        except ValueError:
            store.observed(source_url, "invalid_reference", {"reason": "Unsupported/malformed source map URL"}, "tree-sitter")
    return output


def analyze_map(store: Store, text: str, source_url: str, artifact_hash: str, limit: int, synthetic: bool = False) -> list[tuple[str, str]]:
    try:
        data = json.loads(text)
        if not isinstance(data, dict) or data.get("version") != 3 or not isinstance(data.get("sourcesContent", []), list):
            raise ValueError("Not a supported source map v3")
        content = data.get("sourcesContent", [])
        if len(content) > 1000 or sum(len(s.encode()) for s in content if isinstance(s,str)) > limit:
            raise ValueError("Source map embedded content cap reached")
        output = []
        for index, source in enumerate(content):
            if isinstance(source, str):
                digest = hashlib.sha256(source.encode()).hexdigest()
                store.relate("artifact:" + artifact_hash, "embedded:" + digest, "source_map_content", f"index:{index}")
                output.extend(analyze_js(store, source, source_url, digest, synthetic))
        store.observed(source_url, "source_map", {"hash": artifact_hash, "embedded_sources": len(content), "sources_fetched": False}, "native")
        store.finding("source-map", source_url, "Published source map; review context", {"hash": artifact_hash, "next_check": "Inspect embedded source locally; an exposed map alone is not a vulnerability"}, priority=25, confidence="low")
        return output
    except (ValueError, RecursionError, TypeError) as exc:
        store.observed(source_url, "parse_error", {"error": str(exc)}, "source-map")
        store.stage("source-map", "partial", str(exc))
        return []
