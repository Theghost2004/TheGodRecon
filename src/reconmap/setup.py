"""Explicit dependency setup and health; scans never download software."""
from __future__ import annotations

import importlib.metadata
import importlib.util
import json
import platform
import sys
import tarfile
import zipfile
from pathlib import Path

from . import __version__
from .adapters import doctor, identify
from .config import ConfigError
from .settings import load_settings, save_settings, register_tool
from .tool_registry import REGISTRY, execution_status


def health(overrides=None) -> dict:
    libraries = {}
    for module, distribution in [('aiohttp', 'aiohttp'), ('pydantic', 'pydantic'), ('yaml', 'PyYAML'),
                                 ('tree_sitter', 'tree-sitter'), ('tree_sitter_javascript', 'tree-sitter-javascript'), ('dns', 'dnspython')]:
        try:
            libraries[distribution] = {'version': importlib.metadata.version(distribution), 'available': importlib.util.find_spec(module) is not None}
        except importlib.metadata.PackageNotFoundError:
            libraries[distribution] = {'available': False, 'version': 'missing'}
    from .wordlists import locate
    records = doctor(overrides)
    from .environment import diagnostics
    environment = diagnostics(records)
    boundary = environment['network_controls']['external_active']
    from .execution_boundary import ACTIVE_TOOLS
    tool_rows={n:{**i.record(),'status':execution_status(i),'direct_execution_permitted':i.supported and (n not in ACTIVE_TOOLS or boundary['available'])} for n,i in records.items()}
    for name,row in tool_rows.items():
        if name in ACTIVE_TOOLS and row['supported'] and not boundary['available']:
            row.update(status='backend-unavailable',reason=boundary['reason'])
    return {'version': __version__, 'python': platform.python_version(), 'platform': platform.system(), 'architecture': platform.machine(),
            'core': 'available' if sys.version_info >= (3, 12) and all(v['available'] for v in libraries.values()) else 'incomplete',
            'libraries': libraries, 'tools': tool_rows,
            'environment': environment, 'optional_tools': 'ready' if all(r['direct_execution_permitted'] for r in tool_rows.values()) else 'partial', 'wordlists': locate()}


def print_health(data):
    print(f"TheGodRecon {data['version']} Health Check")
    print(f"Python {data['python']} | {data['platform']} {data['architecture']} | Core: {data['core']}")
    for name, row in data['tools'].items():
        status = 'Installed / backend unavailable' if row['status']=='backend-unavailable' else 'Ready' if row['compatible'] else 'Missing' if not row['available'] else 'Incompatible'
        fallback = ', '.join(row['fallback']) or 'no equivalent native enumeration'
        print(f"{row['id']} {name:12} {status:30} {row['version']}")
        print(f"  {row['path'] or '(not found)'} | fallback: {fallback}")
        if not row.get('direct_execution_permitted',row['supported']):
            print('  ' + row['reason'])
    environment = data.get("environment", {})
    print(f"Environment: user {environment.get('user', 'unknown')}; UID {environment.get('effective_uid')}")
    print('Active execution backend: '+str(environment.get('network_controls',{}).get('external_active',{}).get('reason','not checked')))
    from .wordlists import summary
    summary(data.get("wordlists"))
    print(f"Overall: Core {data['core']}; optional tools {data['optional_tools']}. Native fallbacks retain scope and budgets.")
    print("Repair supported tools: reconmap doctor --fix --yes. Core packages: python tools/bootstrap.py")


def setup(*, yes=False, directory=None, skip_tools=False, go=None, cc=None, with_seclists=None, seclists_path=None) -> int:
    from .installer import install
    from .jsbuild import build
    want_wordlists = with_seclists if with_seclists is not None else platform.system() == 'Linux' and not skip_tools
    if not skip_tools and not yes:
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            raise ConfigError('Setup downloads verified optional tools. Use --yes to consent in non-interactive mode, or --skip-tools for core health only')
        try:
            consent = input('Install missing reviewed tools in your user directory (no administrator access)? [y/N] ').strip().lower()
        except EOFError:
            return 3
        if consent not in {'y', 'yes'}:
            return 3
    if want_wordlists and not yes:
        from .wordlists import CATALOG, locate
        if not locate()['installed']:
            if not (sys.stdin.isatty() and sys.stdout.isatty()):
                raise ConfigError('Optional SecLists download requires --yes or --skip-wordlists in non-interactive setup')
            size = sum(s['bytes'] for s in CATALOG['files'].values())
            try:
                want_wordlists = input(f'Install optional pinned SecLists curated subset ({size:,} bytes, four lists plus license)? [y/N] ').strip().lower() in {'y','yes'}
            except EOFError:
                want_wordlists = False
            if not want_wordlists:
                print('SecLists download declined; core scanner remains available.')
    settings = load_settings()
    if directory:
        settings.tool_directory = str(Path(directory).expanduser().resolve())
    managed = Path(settings.tool_directory)
    managed.mkdir(mode=0o700, parents=True, exist_ok=True)
    if managed.is_symlink() or managed.is_junction():
        raise ConfigError('Managed installation directory must not be a link or junction')
    save_settings(settings)
    failures = []
    for spec in REGISTRY:
        info = identify(spec.name)
        if info.compatible:
            # Remember an existing PATH tool across subsequent terminal sessions.
            register_tool(spec.name, Path(info.path))
            print(f'{spec.name}: reusing verified compatible {info.path}')
            continue
        if skip_tools:
            continue
        if spec.name in settings.registered_tools:
            failures.append(spec.name)
            print(f'{spec.name}: preserving incompatible registered custom path; use tools unregister {spec.name} to return to managed setup, or register a repaired binary')
            continue
        print(f'{spec.name}: installing reviewed dependency...', flush=True)
        try:
            receipt = build(managed, go, cc) if spec.name == 'jsluice' else install(spec.name, managed)
            checked = identify(spec.name, receipt['path'])
            if not checked.compatible:
                raise ValueError(checked.reason)
            register_tool(spec.name, Path(receipt['path']))
        except (OSError, ValueError, TimeoutError, tarfile.TarError, zipfile.BadZipFile) as exc:
            from .security import redact
            failures.append(spec.name)
            print(f'{spec.name}: incomplete: {redact(str(exc))}; native fallback remains available where applicable')
    from .wordlists import install, locate, verify
    wordlists = locate()
    try:
        if seclists_path:
            wordlists = verify(Path(seclists_path))
            if not wordlists['installed']:
                raise ConfigError('Selected SecLists path does not match the reviewed subset: ' + '; '.join(wordlists['errors'][:2]))
            settings = load_settings(); settings.seclists_directory = wordlists['path']; save_settings(settings)
        elif want_wordlists:
            wordlists = install()
        elif wordlists['installed']:
            settings = load_settings(); settings.seclists_directory = wordlists['path']; save_settings(settings)
    except (OSError, ValueError, TimeoutError) as exc:
        failures.append('seclists')
        print('SecLists optional setup incomplete: ' + str(exc))
    data = health()
    print_health(data)
    complete = data['core'] == 'available' and data['optional_tools'] == 'ready' and not failures
    print('Setup complete.' if complete else 'Setup finished with optional coverage limitations; see diagnostics above.')
    print('Run an authorized target: reconmap scan authorized.example')
    return 0 if complete else 2
