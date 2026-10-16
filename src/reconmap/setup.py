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
    records = doctor(overrides)
    return {'version': __version__, 'python': platform.python_version(), 'platform': platform.system(), 'architecture': platform.machine(),
            'core': 'available' if sys.version_info >= (3, 12) and all(v['available'] for v in libraries.values()) else 'incomplete',
            'libraries': libraries, 'tools': {n: {**i.record(), 'status': execution_status(i)} for n, i in records.items()},
            'optional_tools': 'ready' if all(i.compatible for i in records.values()) else 'partial'}


def print_health(data):
    print(f"TheGodRecon {data['version']} Health Check")
    print(f"Python {data['python']} | {data['platform']} {data['architecture']} | Core: {data['core']}")
    for name, row in data['tools'].items():
        status = 'Installed / policy restricted' if row['compatible'] and row['status'] == 'blocked-by-policy' else 'Ready' if row['compatible'] else 'Missing' if not row['available'] else 'Incompatible'
        fallback = ', '.join(row['fallback']) or 'no equivalent native enumeration'
        print(f"{row['id']} {name:12} {status:30} {row['version']}")
        print(f"  {row['path'] or '(not found)'} | fallback: {fallback}")
        if not row['supported']:
            print('  ' + row['reason'])
    print(f"Overall: Core {data['core']}; optional tools {data['optional_tools']}. Native fallbacks retain scope and budgets.")
    print("Repair supported tools: reconmap doctor --fix --yes. Core packages: python tools/bootstrap.py")


def setup(*, yes=False, directory=None, skip_tools=False, go=None, cc=None) -> int:
    from .installer import install
    from .jsbuild import build
    if not skip_tools and not yes:
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            raise ConfigError('Setup downloads verified optional tools. Use --yes to consent in non-interactive mode, or --skip-tools for core health only')
        try:
            consent = input('Install missing reviewed tools in your user directory (no administrator access)? [y/N] ').strip().lower()
        except EOFError:
            return 3
        if consent not in {'y', 'yes'}:
            return 3
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
    data = health()
    print_health(data)
    complete = data['core'] == 'available' and data['optional_tools'] == 'ready' and not failures
    print('Setup complete.' if complete else 'Setup finished with optional coverage limitations; see diagnostics above.')
    print('Run an authorized target: reconmap scan authorized.example')
    return 0 if complete else 2
