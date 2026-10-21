from __future__ import annotations

import argparse
import asyncio
import json
import signal
import sqlite3
import sys
from pathlib import Path

import yaml
from pydantic import ValidationError

from . import __version__
from .adapters import CAPABILITIES, PINS, doctor, identify
from .config import Budgets, ConfigError, ScanConfig, default_config, load_config
from .demo import fixtures
from .engine import Scanner, prepare_run
from .reporting import compare_runs, generate_report
from .security import redact
from .storage import RunLock, Store, atomic_json, read_manifest, timestamp
from .commands_v2 import add_scan_arguments, register
from .selectors import resolve_selection


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ConfigError(message)


def parser() -> Parser:
    root = Parser(prog="reconmap", description="Explicitly scoped local reconnaissance; no automatic vulnerability confirmation")
    root.add_argument("--version", action="version", version=__version__)
    commands=root.add_subparsers(dest="command",required=True,parser_class=Parser)
    doc=commands.add_parser("doctor",help="Check Python and optional external binary capabilities")
    doc.add_argument("--tool",action="append",default=[],metavar="NAME=PATH")
    doc.add_argument("--json",action="store_true")
    doc.add_argument("--fix",action="store_true",help="Repair missing reviewed tools with consent")
    doc.add_argument("--yes",action="store_true")
    setup=commands.add_parser("setup",help="Explicitly install/reuse verified optional tools")
    setup.add_argument("--yes",action="store_true",help="Consent to reviewed dependency downloads/builds")
    setup.add_argument("--directory",type=Path)
    setup.add_argument("--skip-tools",action="store_true")
    setup.add_argument("--go")
    setup.add_argument("--cc")
    wordlist_setup = setup.add_mutually_exclusive_group()
    wordlist_setup.add_argument("--with-seclists", dest="with_seclists", action="store_true", default=None)
    wordlist_setup.add_argument("--skip-wordlists", dest="with_seclists", action="store_false")
    setup.add_argument("--seclists-path", type=Path, help="Reuse an existing installation after pinned-file verification")
    lists = commands.add_parser("wordlists", help="Local dictionary diagnostics and explicit pinned subset installation")
    wordlist_commands = lists.add_subparsers(dest="wordlist_command", required=True, parser_class=Parser)
    for name in ("list", "doctor", "update"):
        item = wordlist_commands.add_parser(name)
        item.add_argument("--json", action="store_true")
        if name == "update":
            item.add_argument("--yes", action="store_true")
    prefs=commands.add_parser("settings",help="Show or set non-sensitive user preferences")
    prefs.add_argument("--set",nargs=2,metavar=("KEY","VALUE"))
    resume=commands.add_parser("resume",help="Resume an existing scan with unchanged scope and budgets")
    resume.add_argument("run",type=Path)
    resume.add_argument("--no-progress",action="store_true")
    resume.add_argument("--break-lock",action="store_true")
    init=commands.add_parser("init",help="Write an editable exact-host scope YAML; refuses overwrite")
    init.add_argument("--target",required=True)
    init.add_argument("--config",type=Path,required=True)
    init.add_argument("--lab",action="store_true",help="Separate loopback-only lab network policy")
    scan=commands.add_parser("scan",help="New scoped scan or resume an unchanged run")
    add_scan_arguments(scan)
    blackbox=commands.add_parser("blackbox",help="Complete eight-capability reconnaissance with endpoint tree and asset map")
    add_scan_arguments(blackbox)
    register(commands, Parser)
    report=commands.add_parser("report",help="Regenerate local redacted exports and HTML")
    report.add_argument("--run",type=Path)
    report.add_argument("--open",action="store_true",help="Open explicitly regenerated report")
    report.add_argument("--break-lock",action="store_true")
    diff=commands.add_parser("diff",help="Compare snapshots; older run remains untouched")
    diff.add_argument("--baseline",type=Path,required=True)
    diff.add_argument("--current",type=Path,required=True)
    demo=commands.add_parser("demo",help="Deterministic offline fixtures; no provider/target network")
    demo.add_argument("--output-root",type=Path)
    demo.add_argument("--no-progress",action="store_true")
    demo.add_argument("--with-gitleaks",action="store_true",help="Run optional installed Gitleaks offline")
    demo.add_argument("--tool",action="append",default=[],metavar="NAME=PATH")
    demo.add_argument("--tools", help="Optional numbered selection; active binaries remain blocked")
    demo.add_argument("--enrich", help="Optional enrichments; demo never contacts providers")
    validate=commands.add_parser("validate",help="Record an explicit analyst decision; no automatic credential testing")
    validate.add_argument("--run",type=Path,required=True)
    validate.add_argument("--finding",required=True,help="Finding fingerprint")
    validate.add_argument("--status",choices=["informational","needs manual validation","manually confirmed","dismissed"],required=True)
    validate.add_argument("--note",required=True)
    return root


def overrides(values: list[str]) -> dict[str,str]:
    output={}
    for value in values:
        name,sep,path=value.partition("=")
        if not sep or name not in PINS or not path:
            raise ConfigError("Tool overrides use NAME=PATH with a supported tool name")
        output[name]=path
    return output


def effective_config(args: argparse.Namespace) -> ScanConfig:
    from .settings import load_settings
    from .presets import apply_preset
    settings = load_settings()
    positional = getattr(args, "target_pos", None)
    if positional and args.target:
        raise ConfigError("Use a positional target or --target, not both")
    args.target = positional or args.target
    if getattr(args, "all_tool", False):
        if args.tools is not None or args.modules is not None or args.profile is not None:
            raise ConfigError("--all-tool cannot be combined with --tools, --modules or --profile")
        args.tools = "all"
    blackbox = args.command == "blackbox"
    god_mode = getattr(args, "god_mode", False) or blackbox
    if god_mode and args.exclude_tools:
        raise ConfigError("BlackBox selects all eight capabilities; use scan --tools/--exclude-tools for customization")
    if blackbox and args.graph is False:
        raise ConfigError("BlackBox always generates its endpoint map; use scan --no-graph for a customized scan")
    if getattr(args, "god_mode", False) and not blackbox:
        print("Compatibility alias: use reconmap blackbox TARGET for comprehensive reconnaissance.", file=sys.stderr)
    if god_mode and (args.all_tool or args.tools is not None or args.modules is not None or args.profile is not None or args.preset is not None):
        raise ConfigError("--god-mode/--full-coverage selects a complete profile; do not combine with --all-tool, --tools, --modules, --profile or --preset")
    if god_mode and args.resume and args.command != "rerun":
        raise ConfigError("Resume uses the saved profile; use reconmap resume RUN or create a separate rerun")
    preset = getattr(args, "preset", None)
    if preset and (args.config or getattr(args, "resume", None) or args.profile):
        raise ConfigError("Presets apply to new default scans; do not combine with --config, --resume or --profile")
    if args.output_root is None and args.command != "rerun":
        args.output_root = Path(settings.output_root)
    if args.resume:
        read_manifest(args.resume)
        config=ScanConfig.model_validate_json((args.resume/"config.effective.json").read_text(encoding="utf-8"))
    elif args.config:
        config=load_config(args.config)
    else:
        if not args.target:
            raise ConfigError("A new scan requires TARGET or --target; resume with --resume PATH")
        config=default_config(args.target)
        config=apply_preset(config, preset or (settings.preset if not args.profile else "standard"))
    if args.config and args.resume:
        config=load_config(args.config)
    choices = {name: getattr(args, name, None) for name in ("tools", "profile", "enrich", "modules", "mode")}
    if not args.resume or args.config is not None or any(value is not None for value in choices.values()):
        config = resolve_selection(config, **choices)
    if args.exclude_tools:
        from .selectors import select_tools, tool_modules
        excluded = set(select_tools(args.exclude_tools))
        engines = dict(config.execution_engines)
        if args.tools is not None or config.selected_tools:
            selected = config.selected_tools or []
        elif args.config or args.profile:
            from .selectors import capability_enabled
            selected = [n for n in select_tools("all") if capability_enabled(config, n)]
            # Excluding a capability never turns an existing native YAML module
            # into permission to execute an additional external binary.
            engines.update({n:"native" for n in selected if n not in config.modules})
        else:
            selected = select_tools("all")
        selected = [n for n in selected if n not in excluded]
        config = config.model_copy(update={"selected_tools": selected, "modules": tool_modules(selected), "profile": None, "execution_engines": engines})
        config = resolve_selection(config)
    if god_mode:
        from .presets import apply_god_mode
        config = apply_god_mode(config, defaults=not args.config and not args.resume)
    data=config.model_dump()
    if god_mode:
        data["workflow"] = "blackbox"
        data["graph"] = True
    if args.formats is not None:
        data["report_formats"] = list(dict.fromkeys(args.formats.split(",")))
        if god_mode and set(data["report_formats"]) != {"html","json","csv"}:
            raise ConfigError("BlackBox produces all report formats; use scan to customize exports")
    chosen_sources = {}
    for option in args.provider_source:
        name, sep, source = option.partition("=")
        if not sep:
            raise ConfigError("Provider source uses TOOL=SOURCE from the reviewed allowlist")
        chosen_sources.setdefault(name, []).append(source)
    data["provider_sources"].update(chosen_sources)
    if args.graph is not None:
        data["graph"] = args.graph
    if args.auto_wordlists:
        data["discovery"]["enabled"] = True
    data["discovery"]["exclude_wordlists"].extend(args.exclude_wordlist)
    if args.wordlist:
        data["discovery"]["wordlists"] = []  # explicit CLI lists replace YAML/automatic choices
    for option in args.engine:
        name, sep, value = option.partition("=")
        if not sep:
            raise ConfigError("Execution preference uses TOOL=auto or TOOL=native")
        data["execution_engines"][name] = value
    for path in args.wordlist:
        from .wordlists import load_dictionary
        load_dictionary(path, config.discovery.max_entries)
        data['discovery']['wordlists'].append(str(path.expanduser().absolute()))
        data['discovery']['enabled'] = True
    for flag, field in (("wordlist_budget", "request_budget"), ("max_wordlist_entries", "max_entries"), ("max_concurrent_jobs", "max_concurrent_jobs")):
        value = getattr(args, flag, None)
        if value is not None:
            data['discovery'][field] = value
    if args.command == 'rerun' and (getattr(args, 'mode', None) == 'offline' or 'http' not in data['modules']):
        data['discovery']['enabled'] = False
        data['discovery']['god_mode'] = False
    if data['discovery']['enabled'] and (data['mode'] not in {'standard', 'demo'} or 'http' not in data['modules']):
        raise ConfigError('Content discovery needs an explicitly selected HTTP capability in standard/demo mode')
    data["tools"].update(overrides(args.tool))
    if args.strict_tools is not None:
        data["strict_tools"]=args.strict_tools
    mapping={"max_requests":"requests","max_urls":"urls_per_host","depth":"depth","timeout":"timeout","retries":"retries","per_host_rps":"per_host_rps","overall_rps":"overall_rps","max_response_bytes":"response_bytes","max_artifact_bytes":"artifact_bytes","max_minutes":"minutes","dns_budget":"dns_queries","provider_results":"provider_results","provider_seconds":"provider_seconds"}
    for arg,field in mapping.items():
        value=getattr(args,arg)
        if value is not None:
            data["budgets"][field]=value
    return ScanConfig.model_validate(data)


def identify_selected(config, name):
    if config.execution_engines.get(name) == "native":
        from .adapters import ToolInfo
        return ToolInfo(name, None, "not checked (native selected)", None, False, False, CAPABILITIES[name], "Native engine explicitly selected; executable not inspected or invoked")
    return identify(name, config.tools.get(name))


def run(config: ScanConfig, target: str | None, output_root: Path, resume: Path | None = None, baseline: Path | None = None, break_lock: bool = False, initialize=None, no_progress=False, preset=None) -> int:
    if baseline:
        read_manifest(baseline)
    tools={name:identify_selected(config, name) for name in config.modules if name in PINS}
    if config.strict_tools:
        from .execution_boundary import ACTIVE_TOOLS, execution_requirement, probe_boundary
        boundary=probe_boundary() if set(tools) & ACTIVE_TOOLS else None
        effective_target=target or (read_manifest(resume)['target'] if resume else None)
        missing={name:execution_requirement(config,name,info,boundary,effective_target) for name,info in tools.items()}
        if any(missing.values()):
            print("Dependency preflight failed:\n"+"\n".join(name+': '+reason for name,reason in missing.items() if reason),file=sys.stderr)
            return 4
    path,manifest=prepare_run(config,target,output_root,resume,baseline)
    print("Effective scope: "+redact(json.dumps(config.scope.model_dump(),sort_keys=True)))
    print(f"Mode {config.mode}; ceilings {config.budgets.requests} HTTP requests, {config.budgets.urls_per_host} URLs/host, depth {config.budgets.depth}, {config.budgets.per_host_rps:g}/s/host, {config.budgets.minutes:g} minutes")
    print(f"Run directory: {path}")
    with RunLock(path,break_lock):
        if initialize is not None or manifest.get("lineage", {}).get("initialization_pending"):
            from .reruns import initialize_rerun
            initialization_state = initialize_rerun(path, manifest, config, initialize)
            if initialization_state is not None:
                print(f"{initialization_state}: {path/'reports/index.html'}")
                return 130 if initialization_state == "interrupted" else 2
        current={name:info.record() for name,info in tools.items()}
        saved_path=path/"tools.json"
        if resume and saved_path.exists():
            saved=json.loads(saved_path.read_text(encoding="utf-8"))
            for name,info in saved.get("external",{}).items():
                new=current.get(name,{})
                if info.get("sha256") != new.get("sha256") or info.get("version") != new.get("version"):
                    raise ConfigError(f"Tool identity changed for {name}; start a new run to preserve provenance")
        import importlib.metadata
        atomic_json(saved_path,{"engine":__version__,"python":sys.version.split()[0],"external":current,"libraries":{n:importlib.metadata.version(n) for n in ("aiohttp","pydantic","tree-sitter","tree-sitter-javascript")},"template_profile":"reconmap-exposure-v1 (two hashed templates; native or contained Nuclei, see stage results)","traffic_accounting":"Broker and native target HTTP share reservations; DNS operations and RIPE/CDX are separate measured counters; external Subfinder/URLFinder provider counts remain unknown"})
        from .environment import diagnostics
        atomic_json(path/"environment.json", diagnostics(tools))
        previous=signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGTERM,lambda *unused: (_ for _ in ()).throw(KeyboardInterrupt()))
        try:
            from .progress import Dashboard
            from .settings import load_settings
            scanner=Scanner(path,manifest,config,tools,fixtures() if config.mode=="demo" else None)
            with Dashboard(enabled=not no_progress and load_settings().progress, preset=preset or config.profile) as dashboard:
                state=asyncio.run(dashboard.run(scanner))
        finally:
            signal.signal(signal.SIGTERM,previous)
    from .report_access import finish_run
    finish_run(path, state)
    return {"completed":0,"partial":2,"interrupted":130}[state]


def main(argv: list[str] | None = None) -> int:
    try:
        values = list(sys.argv[1:] if argv is None else argv)
        if not values:
            if sys.stdin.isatty() and sys.stdout.isatty():
                from .menu import menu
                return menu()
            parser().print_help()
            return 0
        args=parser().parse_args(values)
        if args.command == "resume":
            return main(["scan", "--resume", str(args.run)] + (["--no-progress"] if args.no_progress else []) + (["--break-lock"] if args.break_lock else []))
        if args.command == "setup":
            from .setup import setup
            return setup(yes=args.yes, directory=args.directory, skip_tools=args.skip_tools, go=args.go, cc=args.cc, with_seclists=args.with_seclists, seclists_path=args.seclists_path)
        if args.command == "wordlists":
            from .wordlists import locate, summary
            if args.wordlist_command == "update":
                if args.json:
                    raise ConfigError("Use wordlists doctor --json separately from update")
                from .setup import setup
                return setup(yes=args.yes, skip_tools=True, with_seclists=True)
            data=locate()
            print(json.dumps(data,indent=2)) if args.json else summary(data)
            if args.wordlist_command == "list" and not args.json:
                for name, info in data['available'].items():
                    print(f"{name}: {info['location']} | sha256 {info['sha256']}")
            return 0 if data['installed'] else 2
        if args.command == "settings":
            from .settings import load_settings, save_settings
            settings = load_settings()
            if args.set:
                key, value = args.set
                if key not in {"preset", "output_root", "auto_open", "progress"}:
                    raise ConfigError("Editable preferences: preset, output_root, auto_open, progress; register tools with tools register")
                if key in {"auto_open", "progress"}:
                    if value.lower() not in {"true", "false"}:
                        raise ConfigError("Boolean preferences accept true or false")
                    value = value.lower() == "true"
                if key == "output_root":
                    value = str(Path(value).expanduser().resolve())
                setattr(settings, key, value)
                save_settings(settings)
            print(settings.model_dump_json(indent=2))
            return 0
        if args.command in {"tools", "plan", "rerun"}:
            from .commands_v2 import handle
            return handle(args)
        if args.command=="doctor":
            from .setup import health, print_health, setup
            if args.fix:
                if args.json or args.tool:
                    raise ConfigError("Use doctor --fix separately from --json or temporary --tool overrides")
                return setup(yes=args.yes)
            data=health(overrides(args.tool))
            print(json.dumps(data,indent=2)) if args.json else print_health(data)
            return 0 if data["core"] == "available" else 4
        if args.command=="init":
            config=default_config(args.target)
            config.scope.lab=args.lab
            from .scope import ScopePolicy
            if not ScopePolicy(config.scope).decision(args.target)[0]:
                raise ConfigError("Seed is denied; loopback fixtures require --lab and an explicit loopback target")
            with args.config.open("x",encoding="utf-8") as f:
                f.write("# Exact-host scope. Wildcards never include the apex. Exclusions win.\n# Provider keys belong in environment variables, never this file.\n")
                yaml.safe_dump(config.model_dump(),f,sort_keys=False)
            print(f"Editable exact-host scope saved: {args.config.absolute()}")
            return 0
        if args.command in {"scan", "blackbox"}:
            config=effective_config(args)
            from .settings import load_settings
            return run(config,args.target,args.output_root,args.resume,args.baseline,args.break_lock,
                       no_progress=args.no_progress,preset=("BLACKBOX" if config.workflow == "blackbox" or config.discovery.god_mode else args.preset) or ("YAML" if args.config else "saved run" if args.resume else load_settings().preset))
        if args.command=="demo":
            config=default_config("example.com")
            config.mode="demo"
            config.budgets.depth=3
            config.tools=overrides(args.tool)
            if args.with_gitleaks:
                if args.tools is not None:
                    raise ConfigError("Use --with-gitleaks or --tools, not both")
                config.modules.append("gitleaks")
            if args.tools is not None or args.enrich is not None:
                config = resolve_selection(config, tools=args.tools, enrich=args.enrich, mode="demo")
            from .settings import load_settings
            return run(config,"example.com",args.output_root or Path(load_settings().output_root),no_progress=args.no_progress,preset="demo")
        if args.command=="report":
            from .report_access import latest_report, open_report
            if args.run is None:
                open_report(latest_report())
                return 0
            read_manifest(args.run)
            with RunLock(args.run,args.break_lock):
                generate_report(args.run)
            print(args.run.absolute()/"reports"/"index.html")
            if args.open:
                open_report(args.run/"reports/index.html")
            return 0
        if args.command=="diff":
            if args.baseline.resolve()==args.current.resolve():
                raise ConfigError("Baseline and current must be different runs")
            with RunLock(args.current):
                result=compare_runs(args.baseline,args.current)
                atomic_json(args.current/"diff"/"comparison.json",result)
                generate_report(args.current)
            print(json.dumps(result,indent=2))
            return 0 if result["compatible"] else 2
        if args.command=="validate":
            read_manifest(args.run)
            if not args.note.strip():
                raise ConfigError("An analyst note is required")
            with RunLock(args.run):
                store=Store(args.run)
                try:
                    if not store.conn.execute("SELECT 1 FROM findings WHERE fingerprint=?",(args.finding,)).fetchone():
                        raise ConfigError("Unknown finding fingerprint")
                    with store.conn:
                        store.conn.execute("UPDATE findings SET validation=? WHERE fingerprint=?",(args.status,args.finding))
                        store.conn.execute("INSERT INTO analyst_actions(fingerprint,status,note,time) VALUES(?,?,?,?)",(args.finding,args.status,redact(args.note),timestamp()))
                    generate_report(args.run,store)
                finally:
                    store.close()
            return 0
        return 3
    except ValidationError as exc:
        print("Configuration validation failed: "+redact(json.dumps(exc.errors(include_input=False,include_context=False))),file=sys.stderr)
        return 3
    except yaml.YAMLError:
        print("Configuration error: malformed YAML; check indentation and quoting",file=sys.stderr)
        return 3
    except RecursionError:
        print("Configuration/operation error: input nesting exceeds parser limits",file=sys.stderr)
        return 3
    except sqlite3.Error as exc:
        print("Database error: "+redact(str(exc))+". Preserve this run and restore a valid backup or start a new run.",file=sys.stderr)
        return 3
    except (ConfigError,ValueError,OSError,json.JSONDecodeError) as exc:
        print("Configuration/operation error: "+redact(str(exc)),file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        print("Interrupted. Resume the existing run directory.",file=sys.stderr)
        return 130


if __name__=="__main__":
    raise SystemExit(main())
