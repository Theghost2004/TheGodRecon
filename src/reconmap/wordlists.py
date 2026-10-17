"""Local dictionaries and an explicitly installed, pinned SecLists subset.

Neither discovery nor dictionary loading performs network requests. Only install()
uses the existing bounded downloader, against reviewed upstream immutable files.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from functools import lru_cache
from pathlib import Path

from .config import ConfigError
from .installer import download
from .settings import config_directory, load_settings, save_settings
from .storage import atomic_json

CATALOG = json.loads(Path(__file__).with_name('seclists_manifest.json').read_text(encoding='utf-8'))
MAX_FILE_BYTES = 2 * 1024 * 1024
CONVENTIONAL = (Path('/usr/share/seclists'), Path('/usr/share/wordlists/seclists'))


def default_directory() -> Path:
    if os.environ.get('RECONMAP_CONFIG_DIR'):
        return config_directory() / 'wordlists' / 'seclists'
    root = Path(os.environ.get('LOCALAPPDATA', str(Path.home()/'AppData/Local'))) if os.name == 'nt' else Path(os.environ.get('XDG_DATA_HOME', str(Path.home()/'.local/share')))
    return root / 'thegodrecon/wordlists/seclists'


def safe_path(path: Path, *, file=False) -> Path:
    path = path.expanduser().absolute()
    for part in (path, *path.parents):
        if part.is_symlink() or part.is_junction():
            raise ConfigError('Wordlist path contains a link or junction: ' + str(part))
    if file and (not path.is_file() or path.stat().st_nlink > 1):
        raise ConfigError('Wordlist must be a regular unlinked file: ' + str(path))
    return path


def read_file(path: Path, expected=None) -> bytes:
    path = safe_path(path, file=True)
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ConfigError('Wordlist exceeds 2 MiB; supply a smaller curated dictionary')
    with path.open('rb') as stream:
        data = stream.read(MAX_FILE_BYTES+1)
    if len(data) > MAX_FILE_BYTES:
        raise ConfigError('Wordlist grew beyond size cap')
    if expected and (len(data) != expected['bytes'] or hashlib.sha256(data).hexdigest() != expected['sha256']):
        raise ConfigError('Wordlist integrity mismatch: ' + str(path))
    return data


@lru_cache(maxsize=16)
def parse_dictionary(data: bytes, limit: int, task: str) -> tuple:
    try:
        text = data.decode('utf-8-sig')
    except UnicodeError as exc:
        raise ConfigError('Wordlist must be UTF-8 text') from exc
    values, seen, rejected, clipped = [], set(), 0, False
    for line in text.splitlines():
        value = line.strip()
        if not value or value.startswith('#'):
            continue
        # Dictionaries contain literal path/hostname components, never URLs,
        # traversal, query actions, interpolation or scanner payload syntax.
        if (len(value) > 512 or not re.fullmatch(r'[A-Za-z0-9_./~+-]+', value)
                or value.startswith('//') or '//' in value
                or any(part in {'.', '..'} for part in value.split('/'))):
            rejected += 1
            continue
        if task == 'dns' and not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', value):
            rejected += 1
            continue
        value = value.strip('/')
        if not value or value in seen:
            continue
        seen.add(value)
        if len(values) >= limit:
            clipped = True
            continue
        values.append(value)
    return tuple(values), rejected, clipped


def load_dictionary(path: Path, limit: int = 500, task='content', expected=None) -> dict:
    if not 1 <= limit <= 100000:
        raise ConfigError('Dictionary entry cap must be 1–100000')
    data = read_file(path, expected)
    entries, rejected, clipped = parse_dictionary(data, limit, task)
    return {'path': str(path.expanduser().absolute()), 'sha256': hashlib.sha256(data).hexdigest(),
            'bytes': len(data), 'entries': entries, 'rejected_entries': rejected,
            'entry_limit_reached': clipped, 'task': task, 'data': data}


def verify(directory: Path) -> dict:
    directory = safe_path(directory)
    available, errors = {}, []
    for name, spec in CATALOG['files'].items():
        try:
            read_file(directory/spec['path'], spec)
            if name != 'license':
                available[name] = {**spec, 'location': str(directory/spec['path'])}
        except (OSError, ValueError) as exc:
            errors.append(str(exc))
    return {'manager': 'ready', 'installed': len(available) == 4 and not errors,
            'path': str(directory), 'integrity': 'verified' if len(available) == 4 and not errors else 'missing/incompatible',
            'release': CATALOG['release'], 'revision': CATALOG['revision'], 'kind': CATALOG['kind'],
            'available': available, 'errors': errors}


def locate() -> dict:
    settings = load_settings()
    locations = ([Path(settings.seclists_directory)] if settings.seclists_directory else []) + [default_directory()] + (list(CONVENTIONAL) if os.name != 'nt' else [])
    seen, diagnostics = set(), []
    for directory in locations:
        if str(directory) in seen:
            continue
        seen.add(str(directory))
        if directory.exists() or directory.is_symlink():
            try:
                result = verify(directory)
            except (OSError, ValueError) as exc:
                diagnostics.append(str(exc))
                continue
            if result['installed']:
                return result
            diagnostics.extend(result['errors'])
    return {'manager': 'ready', 'installed': False, 'path': None, 'integrity': 'unavailable',
            'release': CATALOG['release'], 'revision': CATALOG['revision'], 'kind': CATALOG['kind'],
            'available': {}, 'errors': diagnostics or ['SecLists subset absent; run reconmap setup --with-seclists --yes']}


def install(directory: Path | None = None) -> dict:
    existing = locate() if directory is None else verify(directory)
    if existing['installed']:
        settings = load_settings(); settings.seclists_directory = existing['path']; save_settings(settings)
        return existing
    target = safe_path(directory or default_directory())
    if target.exists():
        raise ConfigError('Preserving unrelated/incomplete SecLists directory; inspect or move it explicitly: ' + str(target))
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    expected_bytes = sum(item['bytes'] for item in CATALOG['files'].values())
    if shutil.disk_usage(target.parent).free < expected_bytes * 3 + 1024 * 1024:
        raise ConfigError('Insufficient free disk space for verified SecLists staging')
    print(f"SecLists {CATALOG['release']}: curated 4-list subset, {expected_bytes:,} download bytes; full collection is not installed", flush=True)
    # A sibling staging directory is never discoverable as an installed set.
    # Cancellation/checksum/network failures remove it; retry starts cleanly.
    with tempfile.TemporaryDirectory(prefix='.seclists-', dir=target.parent) as temporary:
        staged = Path(temporary)/'subset'; staged.mkdir(mode=0o700)
        for name, spec in CATALOG['files'].items():
            url = f"https://raw.githubusercontent.com/danielmiessler/SecLists/{CATALOG['revision']}/{spec['path']}"
            data = download(url, spec['bytes'])
            if len(data) != spec['bytes'] or hashlib.sha256(data).hexdigest() != spec['sha256']:
                raise ConfigError('SecLists checksum/size mismatch; refusing publication: ' + spec['path'])
            path = staged/spec['path']; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        atomic_json(staged/'reconmap-receipt.json', CATALOG)
        # Destination is never replaced; even an unrelated empty directory is
        # preserved. A setup lock closes the ordinary concurrent-install race.
        lock = target.with_name(target.name+'.install.lock')
        with lock.open('x'):
            pass
        try:
            if target.exists() or target.is_symlink():
                raise ConfigError('SecLists destination appeared during setup; preserved')
            staged.rename(target)
        finally:
            lock.unlink(missing_ok=True)
    settings = load_settings(); settings.seclists_directory = str(target); save_settings(settings)
    return verify(target)


def summary(data=None) -> None:
    data = data or locate()
    print('Wordlist Manager: Ready (local, bounded dictionaries)')
    print('SecLists: ' + ('Installed — curated subset' if data['installed'] else 'Optional / unavailable'))
    print('SecLists Path: ' + (data['path'] or '(not installed)'))
    print('Wordlist Integrity: ' + data['integrity'])
    print(f"Selected Wordlists: {len(data['available'])} available; release {data['release']}")
    if not data['installed']:
        print('; '.join(data['errors'][:3]))


def select_lists(store, installed: dict) -> list[tuple[str, str]]:
    """Selection evidence is current application context, not bundled library names."""
    names = [('common', 'small common application/documentation paths')]
    current = {r['url']: r for r in store.rows('urls') if r['status'] is not None and 200 <= r['status'] < 300}
    api = any(re.search(r'/(?:api|graphql|v[0-9]+)(?:/|$)', urlsplit_path(u)) for u in current)
    api |= bool(store.conn.execute("SELECT 1 FROM observations WHERE kind='inferred_endpoint' AND (subject LIKE '%/api/%' OR subject LIKE '%/graphql%') LIMIT 1").fetchone())
    php = False
    for row in store.rows('technologies'):
        asset = current.get(row['subject'])
        if not asset or row['confidence'] == 'low' or asset['content_type'] not in {'text/html','application/json'}:
            continue
        evidence = json.loads(row['evidence'])
        php |= row['name'] == 'PHP' and any(s['location'] in {'x-powered-by','cookie-names'} for s in evidence.get('signals', []))
        api |= row['name'] in {'Swagger/OpenAPI','GraphQL'}
    if api: names.append(('api', 'captured API routes or application API documentation'))
    if store.conn.execute("SELECT 1 FROM artifacts WHERE kind='js' LIMIT 1").fetchone():
        names.append(('assets', 'captured JavaScript; only small asset-directory subset'))
    if php: names.append(('php', 'current application PHP header/cookie evidence; PHP entries in common list'))
    return [(name, reason) for name, reason in names if ('common' if name == 'php' else name) in installed['available']]


def urlsplit_path(url):
    from urllib.parse import urlsplit
    return urlsplit(url).path.lower()


def selected_entries(name, entries):
    if name == 'assets':
        allowed = {'assets','static','js','scripts','dist','build','public','chunks'}
        return [e for e in entries if e in allowed]
    if name == 'php':
        return [e for e in entries if e.endswith('.php')]
    if name == 'common':
        allowed = {'admin','login','api','docs','documentation','status','health','assets','static','js','scripts','config.json','package.json','robots.txt','sitemap.xml','swagger.json','openapi.json','.well-known/security.txt','manifest.json','server-status','version','readme','README.md'}
        return [e for e in entries if e in allowed]
    return list(entries)
