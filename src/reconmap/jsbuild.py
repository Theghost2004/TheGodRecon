"""Pinned source build. Arbitrary registration/help output never grants trust."""
from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import platform
import re
import shutil
import tarfile
import tempfile
from pathlib import Path

from .installer import atomic_install, download, safe_destination
from .settings import config_directory
from .tool_registry import BY_NAME

REVISION = BY_NAME['jsluice'].version
SOURCE_SHA256 = '9a5db8164f2cbbf99ead65f83926e3a169df9b1570e00dfee097f896c70db078'
SOURCE_URL = f'https://codeload.github.com/BishopFox/jsluice/tar.gz/{REVISION}'


def trusted_build(path: Path, digest: str) -> bool:
    """User-private build attestations are separate from arbitrary registered paths.

    Same-account attackers can change both application code and this store; this
    protects against accidental/unreviewed replacement, not a compromised user.
    """
    receipt = config_directory() / 'jsluice-build.json'
    try:
        if config_directory().is_symlink() or config_directory().is_junction() or receipt.is_symlink() or receipt.is_junction() or receipt.stat().st_size > 65536:
            return False
        data = json.loads(receipt.read_text(encoding='utf-8'))
        return (data.get('source_sha256') == SOURCE_SHA256 and data.get('revision') == REVISION
                and data.get('binary_sha256') == digest and data.get('path') == str(path.resolve())
                and data.get('recipe') == 1 and data.get('fixture_verified') is True)
    except (OSError, ValueError, AttributeError):
        return False


def extract_source(data: bytes, directory: Path) -> Path:
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError('jsluice source checksum mismatch; build refused')
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        members = archive.getmembers()
        if len(members) > 2000 or sum(m.size for m in members) > 20 * 1024 * 1024:
            raise ValueError('Source archive exceeds bounds')
        for member in members:
            destination = directory / member.name
            if not destination.resolve().is_relative_to(directory.resolve()) or not (member.isfile() or member.isdir()):
                raise ValueError('Unsafe source archive entry')
        archive.extractall(directory, members=members, filter='data')
    return directory / ('jsluice-' + REVISION)


def build(directory: Path, go: str | None = None, compiler: str | None = None) -> dict:
    from .adapters import execute, REQUIRED_FLAGS
    if platform.system().lower() not in {'linux', 'windows'} or platform.machine().lower() not in {'x86_64', 'amd64'}:
        raise ValueError('Reviewed jsluice build recipe supports Linux/Windows x86-64; use native Tree-sitter here')
    go_path, cc = shutil.which(go or 'go'), shutil.which(compiler or 'gcc')
    if not go_path or not cc:
        raise ValueError('jsluice requires Go and a native GCC C compiler. Supply --go/--cc paths; Tree-sitter is available without them')
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / ('jsluice.exe' if os.name == 'nt' else 'jsluice')
    safe_destination(target)
    if target.exists():
        raise ValueError(f'Preserving existing {target}; move it explicitly before building a replacement')
    with tempfile.TemporaryDirectory(prefix='.jsluice-build-', dir=directory.parent) as temporary:
        workspace = Path(temporary)
        (workspace / 'tmp').mkdir()
        env = {'TMPDIR': str(workspace / 'tmp'), 'TEMP': str(workspace / 'tmp'), 'TMP': str(workspace / 'tmp'), 'GOENV': 'off', 'GOTOOLCHAIN': 'local', 'GOWORK': 'off', 'GOFLAGS': '-mod=readonly',
               'GOSUMDB': 'sum.golang.org', 'GOPROXY': 'https://proxy.golang.org', 'GONOSUMDB': '',
               'GONOPROXY': '', 'GOPRIVATE': '', 'CGO_ENABLED': '1', 'CC': str(Path(cc).resolve()),
               'CGO_CFLAGS': '', 'CGO_CPPFLAGS': '', 'CGO_CXXFLAGS': '', 'CGO_LDFLAGS': '',
               'GOCACHE': str(workspace / 'cache'), 'GOMODCACHE': str(workspace / 'modules'),
               'GOPATH': str(workspace / 'gopath'), 'GOOS': 'windows' if os.name == 'nt' else 'linux', 'GOARCH': 'amd64'}
        def command(argv, cwd=workspace, timeout=30):
            result = asyncio.run(execute(argv, cwd, timeout, limit=2*1024*1024, env_updates=env))
            if result.code:
                raise ValueError('Build step failed: ' + result.stderr[-2000:] + result.stdout[-1000:])
            return result.stdout + result.stderr
        version = command([go_path, 'version'])
        if not re.search(r'go version go1\.(?:2[0-9]|[3-9][0-9])\.', version):
            raise ValueError('A verified Go 1.20+ toolchain is required; native Tree-sitter remains available')
        compiler_version = command([cc, '--version']).splitlines()[0]
        source = extract_source(download(SOURCE_URL, 20*1024*1024), workspace)
        locks = {name: (source/name).read_bytes() for name in ('go.mod', 'go.sum')}
        command([go_path, 'mod', 'download'], source, 300)
        command([go_path, 'mod', 'verify'], source, 60)
        command([go_path, 'build', '-trimpath', '-buildvcs=false', '-o', str(workspace / target.name), './cmd/jsluice'], source, 600)
        if any((source/name).read_bytes() != content for name, content in locks.items()):
            raise ValueError('Build modified pinned dependency locks; refusing installation')
        binary = workspace / target.name
        help_text = command([str(binary), '-h'])
        if 'jsluice - Extract URLs' not in help_text or not all(flag in help_text for flag in REQUIRED_FLAGS['jsluice']):
            raise ValueError('Built jsluice lacks expected capabilities')
        fixture = workspace / 'fixture.js'
        fixture.write_text('fetch("/api/reconmap-build-check");', encoding='utf-8')
        records = [json.loads(line) for line in command([str(binary), 'urls', str(fixture)]).splitlines() if line.strip()]
        if not any(r.get('url') == '/api/reconmap-build-check' and r.get('method') == 'GET' for r in records):
            raise ValueError('Built jsluice failed local endpoint fixture')
        content = binary.read_bytes()
        receipt = {'recipe': 1, 'revision': REVISION, 'source_sha256': SOURCE_SHA256,
                   'binary_sha256': hashlib.sha256(content).hexdigest(), 'path': str(target.resolve()),
                   'go_version': version.strip(), 'compiler': compiler_version, 'fixture_verified': True,
                   'platform': platform.platform(), 'dependency_verification': 'pinned go.mod/go.sum; Go checksum database enabled'}
        atomic_install(target, content, executable=True)
        config_directory().mkdir(mode=0o700, parents=True, exist_ok=True)
        if config_directory().is_symlink() or config_directory().is_junction():
            raise ValueError('Build trust directory must not be a link or junction')
        atomic_install(config_directory() / 'jsluice-build.json', (json.dumps(receipt, indent=2)+'\n').encode())
        atomic_install(directory / 'jsluice.receipt.json', (json.dumps(receipt, indent=2)+'\n').encode())
        return receipt
