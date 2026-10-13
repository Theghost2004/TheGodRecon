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
    init=commands.add_parser("init",help="Write an editable exact-host scope YAML; refuses overwrite")
    init.add_argument("--target",required=True)
    init.add_argument("--config",type=Path,required=True)
    init.add_argument("--lab",action="store_true",help="Separate loopback-only lab network policy")
    scan=commands.add_parser("scan",help="New scoped scan or resume an unchanged run")
    scan.add_argument("--target")
    scan.add_argument("--config",type=Path)
    scan.add_argument("--output-root",type=Path,default=Path("recon-output"))
    scan.add_argument("--resume",type=Path)
    scan.add_argument("--baseline",type=Path)
    scan.add_argument("--break-lock",action="store_true")
    scan.add_argument("--mode",choices=["standard","passive","demo"])
    scan.add_argument("--modules",help="Comma-separated module selection, replacing configured selection")
    scan.add_argument("--tool",action="append",default=[],metavar="NAME=PATH")
    scan.add_argument("--strict-tools",action="store_true",default=None)
    for flag,typ in (("max-requests",int),("max-urls",int),("depth",int),("timeout",float),("retries",int),("per-host-rps",float),("overall-rps",float),("max-response-bytes",int),("max-artifact-bytes",int),("max-minutes",float),("dns-budget",int),("provider-results",int),("provider-seconds",int)):
        scan.add_argument("--"+flag,type=typ)
    report=commands.add_parser("report",help="Regenerate local redacted exports and HTML")
    report.add_argument("--run",type=Path,required=True)
    report.add_argument("--break-lock",action="store_true")
    diff=commands.add_parser("diff",help="Compare snapshots; older run remains untouched")
    diff.add_argument("--baseline",type=Path,required=True)
    diff.add_argument("--current",type=Path,required=True)
    demo=commands.add_parser("demo",help="Deterministic offline fixtures; no provider/target network")
    demo.add_argument("--output-root",type=Path,default=Path("recon-output"))
    demo.add_argument("--with-gitleaks",action="store_true",help="Run optional installed Gitleaks offline")
    demo.add_argument("--tool",action="append",default=[],metavar="NAME=PATH")
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
    if args.resume:
        read_manifest(args.resume)
        config=ScanConfig.model_validate_json((args.resume/"config.effective.json").read_text(encoding="utf-8"))
    elif args.config:
        config=load_config(args.config)
    else:
        raise ConfigError("A new scan requires an explicit YAML --config; create one with reconmap init")
    if args.config and args.resume:
        config=load_config(args.config)
    data=config.model_dump()
    if args.mode:
        data["mode"]=args.mode
    if args.modules is not None:
        data["modules"]=[v.strip() for v in args.modules.split(",") if v.strip()]
    data["tools"].update(overrides(args.tool))
    if args.strict_tools is not None:
        data["strict_tools"]=args.strict_tools
    mapping={"max_requests":"requests","max_urls":"urls_per_host","depth":"depth","timeout":"timeout","retries":"retries","per_host_rps":"per_host_rps","overall_rps":"overall_rps","max_response_bytes":"response_bytes","max_artifact_bytes":"artifact_bytes","max_minutes":"minutes","dns_budget":"dns_queries","provider_results":"provider_results","provider_seconds":"provider_seconds"}
    for arg,field in mapping.items():
        value=getattr(args,arg)
        if value is not None:
            data["budgets"][field]=value
    return ScanConfig.model_validate(data)


def run(config: ScanConfig, target: str | None, output_root: Path, resume: Path | None = None, baseline: Path | None = None, break_lock: bool = False) -> int:
    if baseline:
        read_manifest(baseline)
    tools={name:identify(name,config.tools.get(name)) for name in config.modules if name in PINS}
    if config.strict_tools:
        missing=[name for name,info in tools.items() if not info.supported and not (config.mode=="demo" and name in {"subfinder","urlfinder"})]
        if missing:
            print("Dependency preflight failed: "+", ".join(missing)+". Run reconmap doctor.",file=sys.stderr)
            return 4
    path,manifest=prepare_run(config,target,output_root,resume,baseline)
    print("Effective scope: "+json.dumps(config.scope.model_dump(),sort_keys=True))
    print(f"Mode {config.mode}; ceilings {config.budgets.requests} HTTP requests, {config.budgets.urls_per_host} URLs/host, depth {config.budgets.depth}, {config.budgets.per_host_rps:g}/s/host, {config.budgets.minutes:g} minutes")
    print(f"Run directory: {path}")
    with RunLock(path,break_lock):
        current={name:info.record() for name,info in tools.items()}
        saved_path=path/"tools.json"
        if resume and saved_path.exists():
            saved=json.loads(saved_path.read_text(encoding="utf-8"))
            for name,info in saved.get("external",{}).items():
                new=current.get(name,{})
                if info.get("sha256") != new.get("sha256") or info.get("version") != new.get("version"):
                    raise ConfigError(f"Tool identity changed for {name}; start a new run to preserve provenance")
        import importlib.metadata
        atomic_json(saved_path,{"engine":__version__,"python":sys.version.split()[0],"external":current,"libraries":{n:importlib.metadata.version(n) for n in ("aiohttp","pydantic","tree-sitter","tree-sitter-javascript")},"template_profile":"reconmap-exposure-v1 (native, no upstream template execution)","traffic_accounting":"Measured reservations for application-owned HTTP attempts; provider network request counts unknown"})
        previous=signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGTERM,lambda *unused: (_ for _ in ()).throw(KeyboardInterrupt()))
        try:
            state=asyncio.run(Scanner(path,manifest,config,tools,fixtures() if config.mode=="demo" else None).run_scan())
        finally:
            signal.signal(signal.SIGTERM,previous)
    print(f"{state}: {path/'reports'/'index.html'}")
    return {"completed":0,"partial":2,"interrupted":130}[state]


def main(argv: list[str] | None = None) -> int:
    try:
        args=parser().parse_args(argv)
        if args.command=="doctor":
            tools=doctor(overrides(args.tool))
            if args.json:
                print(json.dumps({"python":sys.version.split()[0],"platform":sys.platform,"core":"available","tools":{name:info.record() for name,info in tools.items()}},indent=2))
            else:
                print(f"Native core: Python {sys.version.split()[0]} on {sys.platform}; HTTP, HTML crawl, JavaScript AST, SQLite and offline reports available")
                print("TOOL         VERSION      AVAILABLE  SUPPORTED  CAPABILITY / ACTION")
                for name,info in tools.items():
                    print(f"{name:12} {info.version[:12]:12} {str(info.available):10} {str(info.supported):10} {info.capability}; {info.reason}")
            return 0
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
        if args.command=="scan":
            return run(effective_config(args),args.target,args.output_root,args.resume,args.baseline,args.break_lock)
        if args.command=="demo":
            config=default_config("example.com")
            config.mode="demo"
            config.budgets.depth=3
            config.tools=overrides(args.tool)
            if args.with_gitleaks:
                config.modules.append("gitleaks")
            return run(config,"example.com",args.output_root)
        if args.command=="report":
            read_manifest(args.run)
            with RunLock(args.run,args.break_lock):
                generate_report(args.run)
            print(args.run.absolute()/"reports"/"index.html")
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
        print("Configuration validation failed: "+json.dumps(exc.errors(include_input=False,include_context=False)),file=sys.stderr)
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
