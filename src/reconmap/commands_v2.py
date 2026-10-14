"""Additional CLI commands; the existing CLI remains the entry point."""
import json
from pathlib import Path

from .adapters import doctor, identify
from .config import ConfigError, ScanConfig, load_config
from .orchestrator import build_plan, print_plan, selected_names
from .selectors import resolve_selection
from .storage import read_manifest
from .tool_registry import BY_NAME, REGISTRY, execution_status
from .security import redact_data


def add_scan_arguments(parser, *, rerun=False):
    parser.add_argument("--target")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--output-root", type=Path, default=None if rerun else Path("recon-output"))
    if not rerun:
        parser.add_argument("--resume", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--break-lock", action="store_true")
    parser.add_argument("--mode", choices=["standard", "passive", "offline", "demo"])
    parser.add_argument("--profile", choices=["standard", "passive", "offline", "full"])
    parser.add_argument("--tools", help="IDs/names/ranges/presets: 1,3-5,offline or all; replaces module selection")
    parser.add_argument("--enrich", help="asn,wayback,tech,dedup,priority; all or none")
    parser.add_argument("--modules", help="Legacy comma-separated module selection")
    parser.add_argument("--tool", action="append", default=[], metavar="NAME=PATH")
    parser.add_argument("--strict-tools", action="store_true", default=None)
    for flag, typ in (("max-requests", int), ("max-urls", int), ("depth", int), ("timeout", float), ("retries", int), ("per-host-rps", float), ("overall-rps", float), ("max-response-bytes", int), ("max-artifact-bytes", int), ("max-minutes", float), ("dns-budget", int), ("provider-results", int), ("provider-seconds", int)):
        parser.add_argument("--" + flag, type=typ)


def register(commands, parser_class):
    tools = commands.add_parser("tools", help="Numbered registry and binary/policy diagnostics")
    sub = tools.add_subparsers(dest="tool_command", required=True, parser_class=parser_class)
    for name in ("list", "doctor"):
        command = sub.add_parser(name)
        command.add_argument("--tool", action="append", default=[], metavar="NAME=PATH")
        command.add_argument("--json", action="store_true")
    plan = commands.add_parser("plan", help="Preview scope, stages and dependencies without scanning")
    add_scan_arguments(plan)
    plan.add_argument("--json", action="store_true")
    rerun = commands.add_parser("rerun", help="Create a separate execution from validated parent evidence")
    add_scan_arguments(rerun, rerun=True)
    rerun.add_argument("--from", dest="parent", type=Path, required=True)
    return commands


def handle(args):
    from .cli import effective_config, overrides, run
    if args.command == "tools":
        records = doctor(overrides(args.tool))
        data = [{**records[t.name].record(), "status": execution_status(records[t.name]), "operating_systems": "Linux/Windows native core; external binary verification is platform-specific"} for t in REGISTRY]
        if args.json:
            print(json.dumps(data, indent=2))
        else:
            print("ID TOOL         VERSION       AVAILABLE COMPATIBLE EXECUTION          CAPABILITY / REASON")
            for row in data:
                print(f"{row['id']:2} {row['name']:12} {row['version'][:13]:13} {str(row['available']):9} {str(row['compatible']):10} {row['status']:18} {row['capability']}; {BY_NAME[row['name']].policy_reason or row['reason']}")
        return 0
    if args.command == "plan":
        config = effective_config(args)
        target = args.target or (read_manifest(args.resume)["target"] if args.resume else None)
        if not target:
            raise ConfigError("Plan requires --target or --resume")
        tools = {n: identify(n, config.tools.get(n)) for n in selected_names(config)}
        plan = build_plan(config, target, tools)
        preview = redact_data(plan)
        print(json.dumps(preview, indent=2)) if args.json else print_plan(preview)
        return 0 if plan["safe_to_execute"] else 4
    if args.command == "rerun":
        from .reruns import rerun
        return rerun(args)
    return None
