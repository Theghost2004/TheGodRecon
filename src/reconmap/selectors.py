"""Selection syntax and explicit precedence over legacy modules."""
import re

from .config import ConfigError, ScanConfig
from .tool_registry import BY_ID, BY_NAME, ENRICHMENTS, PRESETS


def select_tools(expression: str) -> list[str]:
    chosen = set()
    for token in expression.lower().replace("+", ",").split(","):
        token = token.strip()
        if token in PRESETS:
            chosen.update(PRESETS[token])
        elif token in BY_NAME:
            chosen.add(BY_NAME[token].id)
        elif re.fullmatch(r"\d+", token):
            chosen.add(int(token))
        elif match := re.fullmatch(r"(\d+)-(\d+)", token):
            start, stop = map(int, match.groups())
            if start > stop or stop - start > len(BY_ID):
                raise ConfigError("Tool ranges must be ascending within IDs 1–8")
            chosen.update(range(start, stop + 1))
        else:
            raise ConfigError("Select IDs 1–8, ascending ranges, tool names or presets; example: --tools 1,3-5,offline")
    if not chosen or chosen - BY_ID.keys():
        raise ConfigError("Unknown tool ID; use reconmap tools list for IDs 1–8")
    return [BY_ID[number].name for number in sorted(chosen)]


def select_enrichments(expression: str) -> list[str]:
    if expression == "all":
        return list(ENRICHMENTS)
    if expression == "none":
        return []
    names = [v.strip().lower() for v in expression.split(",")]
    if not names or any(v not in ENRICHMENTS for v in names):
        raise ConfigError("Enrichments: asn,wayback,tech,dedup,priority, all or none")
    return [v for v in ENRICHMENTS if v in names]


def tool_modules(names: list[str]) -> list[str]:
    modules = list(names)
    for name in names:
        modules.extend(BY_NAME[name].fallback)
    if any(name in names for name in ("jsluice", "gitleaks")):
        modules.append("analysis")
    return list(dict.fromkeys(modules))


def resolve_selection(config: ScanConfig, *, tools=None, profile=None, enrich=None, modules=None, mode=None) -> ScanConfig:
    if tools is not None and modules is not None:
        raise ConfigError("--tools and --modules both replace execution selection; choose one")
    if profile is not None and (tools is not None or modules is not None or mode is not None):
        raise ConfigError("--profile cannot be combined with --tools, --modules or --mode; use explicit selections instead")
    data = config.model_dump()
    effective_profile = profile if profile is not None else config.profile
    # Explicit CLI selections override a YAML profile, without accidentally
    # inheriting that profile's provider permissions.
    if tools is not None or modules is not None or mode is not None:
        effective_profile = None
    if effective_profile:
        profiles = {
            "standard": ("standard", None, ["http", "crawl", "analysis", "checks"], []),
            "passive": ("passive", "passive", [], []),
            "offline": ("offline", "offline", ["analysis"], []),
            "full": ("standard", "all", [], list(ENRICHMENTS)),
        }
        new_mode, preset, native, enrichments = profiles[effective_profile]
        if profile is None and "enrichments" in config.model_fields_set:
            enrichments = config.enrichments
        data.update(mode=new_mode, selected_tools=select_tools(preset) if preset else [], enrichments=enrichments)
        data["modules"] = native + tool_modules(data["selected_tools"])
    elif config.selected_tools is not None:
        data["modules"] = tool_modules(config.selected_tools)
    if tools is not None:
        data["selected_tools"] = select_tools(tools)
        data["modules"] = tool_modules(data["selected_tools"])
    if modules is not None:
        data["modules"] = [v.strip() for v in modules.split(",") if v.strip()]
        data["selected_tools"] = None
    # Legacy module/YAML names select the same protected native alternatives,
    # while preserving explicitly selected core modules and never adding binaries.
    for name in list(data["modules"]):
        if name in BY_NAME:
            data["modules"].extend(BY_NAME[name].fallback)
    data["modules"] = list(dict.fromkeys(data["modules"]))
    if data.get("selected_tools"):
        if "httpx" not in data["selected_tools"]:
            data["modules"] = [m for m in data["modules"] if m not in {"http", "crawl", "checks"}]
    if mode is not None:
        data["mode"] = mode
    if enrich is not None:
        data["enrichments"] = select_enrichments(enrich)
    if data["mode"] == "offline":
        selected = data.get("selected_tools") or [n for n in data["modules"] if n in BY_NAME]
        if any(BY_NAME[n].risk != "offline" for n in selected) or set(data["enrichments"]) & {"asn", "wayback"}:
            raise ConfigError("Offline execution permits local tools and tech,dedup,priority only")
        data["modules"] = [m for m in data["modules"] if m not in {"http", "crawl", "checks", "dns"}]
    data["profile"] = effective_profile
    if tools is not None or profile is not None or enrich is not None or modules is not None or mode is not None:
        data["version"] = 2
    return ScanConfig.model_validate(data)


def capability_enabled(config, name):
    """Explicit numbered selection restricts fallbacks as well as executables.

    HTTP transport DNS validation is a safety prerequisite, not DNS enumeration.
    Legacy native module selections retain their original behavior.
    """
    if config.selected_tools:  # [] is also used by the existing standard native profile
        return name in config.selected_tools
    if config.selected_tools == [] and not config.modules:
        return False
    native = {"dnsx":"dns", "httpx":"http", "katana":"crawl", "jsluice":"analysis", "gitleaks":"analysis", "nuclei":"checks"}
    return name in config.modules or native.get(name) in config.modules
