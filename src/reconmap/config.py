from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import unicodedata
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ConfigError(ValueError):
    pass


def hostname(value: str) -> str:
    value = unicodedata.normalize("NFC", value).lower().rstrip(".")
    if not value or any(c in value for c in "/\\@%?#\x00"):
        raise ConfigError("Invalid hostname")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ConfigError("Invalid IDNA hostname") from exc
    if len(value) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in value.split(".")):
        raise ConfigError("Invalid hostname labels")
    return value


def normalize_url(value: str) -> str:
    if len(value) > 8192:
        raise ConfigError("URL exceeds 8192 characters")
    if any(ord(c) < 32 or ord(c) == 127 for c in value) or "\\" in value:
        raise ConfigError("Control characters and backslashes are not accepted in URLs")
    try:
        u = urlsplit(value if "://" in value else "https://" + value)
        if u.scheme.lower() not in {"http", "https"} or not u.hostname or u.username is not None or u.password is not None:
            raise ConfigError("Only HTTP(S) URLs without userinfo are supported")
        host = hostname(u.hostname)
        port = u.port
        if port is not None and not 1 <= port <= 65535:
            raise ConfigError("Invalid port")
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    return urlunsplit((u.scheme.lower(), netloc, u.path or "/", u.query, u.fragment))


def request_url(url: str) -> str:
    u = urlsplit(normalize_url(url))
    return urlunsplit(u._replace(fragment=""))


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_default=True, validate_assignment=True)


class Scope(StrictModel):
    hosts: list[str] = Field(min_length=1)
    exclude_hosts: list[str] = []
    ports: list[int] = [80, 443]
    schemes: list[Literal["http", "https"]] = ["http", "https"]
    paths: list[str] = ["/"]
    exclude_paths: list[str] = []
    lab: bool = False

    @field_validator("hosts", "exclude_hosts")
    @classmethod
    def host_patterns(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(("*." + hostname(v[2:])) if v.startswith("*.") else hostname(v) for v in values))

    @field_validator("ports")
    @classmethod
    def valid_ports(cls, values: list[int]) -> list[int]:
        if not values or any(not 1 <= p <= 65535 for p in values):
            raise ValueError("Ports must be between 1 and 65535")
        return sorted(set(values))

    @field_validator("paths", "exclude_paths")
    @classmethod
    def valid_paths(cls, values: list[str]) -> list[str]:
        if any(not p.startswith("/") or "//" in p or any(c in p for c in "\\;?#%") or any(ord(c) < 32 or ord(c) == 127 for c in p) or any(s in {".", ".."} for s in p.split("/")) for p in values):
            raise ValueError("Scope paths must be absolute, unencoded paths without traversal")
        return values


class Budgets(StrictModel):
    per_host_rps: float = Field(default=2, gt=0, le=100)
    overall_rps: float = Field(default=10, gt=0, le=100)
    depth: int = Field(default=2, ge=0, le=20)
    urls_per_host: int = Field(default=500, ge=1, le=100000)
    requests: int = Field(default=5000, ge=1, le=1000000)
    timeout: float = Field(default=15, gt=0, le=300)
    retries: int = Field(default=1, ge=0, le=3)
    response_bytes: int = Field(default=10 * 1024 * 1024, ge=256, le=100 * 1024 * 1024)
    artifact_bytes: int = Field(default=1024**3, ge=1024, le=10 * 1024**3)
    minutes: float = Field(default=30, gt=0, le=1440)
    dns_queries: int = Field(default=1000, ge=1, le=100000)
    provider_results: int = Field(default=5000, ge=1, le=100000)
    provider_seconds: int = Field(default=60, ge=1, le=600)


MODULES = {"dns", "http", "crawl", "analysis", "checks", "subfinder", "urlfinder", "jsluice", "gitleaks", "dnsx", "httpx", "katana", "nuclei"}


class ProviderSettings(StrictModel):
    requests: int = Field(default=250, ge=1, le=10000)
    rps: float = Field(default=1, gt=0, le=5)
    cache_seconds: int = Field(default=86400, ge=0, le=2592000)
    wayback_pages: int = Field(default=5, ge=1, le=100)
    page_size: int = Field(default=100, ge=1, le=1000)


class GroupingSettings(StrictModel):
    numeric_segments: bool = True
    uuid_segments: bool = True
    query_names: bool = True


PRIORITY_WEIGHTS = {"base": 5, "route": 15, "observed": 25, "restricted": 10, "sources": 10, "parameters": 5, "technology": 5, "finding": 20, "duplicate_penalty": 10}


class PrioritySettings(StrictModel):
    version: Literal[1] = 1
    weights: dict[str, int] = Field(default_factory=lambda: dict(PRIORITY_WEIGHTS))

    @field_validator("weights")
    @classmethod
    def valid_weights(cls, values):
        if set(values) - PRIORITY_WEIGHTS.keys() or any(type(v) is not int or not 0 <= v <= 100 for v in values.values()):
            raise ValueError("Priority weights must use documented component names and integer weights 0–100")
        return {**PRIORITY_WEIGHTS, **values}


class ScanConfig(StrictModel):
    version: Literal[1, 2] = 2
    scope: Scope
    budgets: Budgets = Field(default_factory=Budgets)
    mode: Literal["standard", "passive", "offline", "demo"] = "standard"
    modules: list[str] = ["http", "crawl", "analysis", "checks"]
    tools: dict[str, str] = {}
    strict_tools: bool = False
    local_inputs: list[str] = []
    provider_sources: dict[str, list[str]] = {"subfinder": ["crtsh"], "urlfinder": ["commoncrawl"]}
    selected_tools: list[str] | None = None
    profile: Literal["standard", "passive", "offline", "full"] | None = None
    enrichments: list[str] = []
    providers: ProviderSettings = Field(default_factory=ProviderSettings)
    grouping: GroupingSettings = Field(default_factory=GroupingSettings)
    priority: PrioritySettings = Field(default_factory=PrioritySettings)

    @field_validator("selected_tools", mode="before")
    @classmethod
    def selected_names(cls, values):
        if values is None:
            return None
        from .selectors import select_tools
        if not isinstance(values, (str, list)) or values == []:
            return [] if values == [] else values
        return select_tools(values if isinstance(values, str) else ",".join(str(v) for v in values))

    @field_validator("enrichments")
    @classmethod
    def valid_enrichments(cls, values):
        from .tool_registry import ENRICHMENTS
        if set(values) - set(ENRICHMENTS):
            raise ValueError("Unknown enrichment; choose asn,wayback,tech,dedup,priority")
        return [v for v in ENRICHMENTS if v in values]

    @field_validator("provider_sources")
    @classmethod
    def provider_allowlist(cls, values: dict[str,list[str]]) -> dict[str,list[str]]:
        reviewed = {"subfinder": {"crtsh", "hackertarget"}, "urlfinder": {"commoncrawl", "alienvault"}}
        if any(k not in reviewed or not v or set(v) - reviewed[k] for k,v in values.items()):
            raise ValueError("Providers must be from the reviewed passive allowlist")
        return values

    @field_validator("modules")
    @classmethod
    def valid_modules(cls, values: list[str]) -> list[str]:
        if set(values) - MODULES:
            raise ValueError(f"Unknown modules: {sorted(set(values) - MODULES)}")
        return list(dict.fromkeys(values))

    @field_validator("tools")
    @classmethod
    def tool_names(cls, values: dict[str, str]) -> dict[str, str]:
        if set(values) - MODULES:
            raise ValueError("Unknown tool override")
        return values

    @model_validator(mode="after")
    def module_dependencies(self) -> ScanConfig:
        if "crawl" in self.modules and "http" not in self.modules:
            raise ValueError("crawl requires http")
        return self

    def digest(self) -> str:
        data = self.model_dump()
        if self.version == 1 and self.selected_tools is None and self.profile is None and not self.enrichments and self.providers == ProviderSettings() and self.grouping == GroupingSettings() and self.priority == PrioritySettings():
            for name in ("selected_tools", "profile", "enrichments", "providers", "grouping", "priority"):
                data.pop(name)
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def load_config(path: Path) -> ScanConfig:
    if path.stat().st_size > 1024 * 1024:
        raise ConfigError("Configuration exceeds 1 MiB")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and data.get("profile") and ("selected_tools" in data or "modules" in data or "mode" in data):
        raise ConfigError("YAML profile cannot also define selected_tools, modules or mode; use one selection layer")
    return ScanConfig.model_validate(data)


def default_config(target: str) -> ScanConfig:
    u = urlsplit(normalize_url(target))
    return ScanConfig(scope=Scope(hosts=[u.hostname], ports=[u.port or (443 if u.scheme == "https" else 80)]))
