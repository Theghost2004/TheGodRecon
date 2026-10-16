"""One-command local installation; standard library only, no privileged changes."""
from __future__ import annotations

import argparse
import os
import platform
import subprocess
import sys
import venv
from pathlib import Path


def environment_python(directory: Path, windows: bool | None = None) -> Path:
    windows = os.name == 'nt' if windows is None else windows
    return directory / ('Scripts/python.exe' if windows else 'bin/python')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--skip-tools', action='store_true', help='Install Python core only; optional tools remain unchanged')
    parser.add_argument('--directory', type=Path, help='Portable managed tool directory')
    parser.add_argument('--go', help='Existing Go executable for the pinned jsluice build')
    parser.add_argument('--cc', help='Existing GCC executable for the pinned jsluice build')
    args = parser.parse_args(argv)
    if sys.version_info < (3, 12):
        parser.exit(3, 'Python 3.12+ required. Install it, then rerun this command. No OS packages were changed.\n')
    if platform.system() not in {'Linux', 'Windows'}:
        parser.exit(3, 'This bootstrap supports Linux and Windows.\n')
    root = Path(__file__).resolve().parents[1]
    environment = root / '.venv'
    python = environment_python(environment)
    print(f'TheGodRecon bootstrap | {platform.system()} {platform.machine()} | Python {platform.python_version()}', flush=True)
    try:
        if environment.is_symlink() or environment.is_junction():
            raise ValueError('Refusing linked .venv; choose an ordinary project directory')
        if environment.exists():
            if not python.is_file() or not (environment/'pyvenv.cfg').is_file():
                raise ValueError('Existing .venv is incomplete. Preserve/remove it explicitly before retrying')
            subprocess.run([str(python), '-c', 'import sys; assert sys.version_info >= (3,12) and sys.prefix != sys.base_prefix'], check=True, timeout=15)
        else:
            venv.EnvBuilder(with_pip=True).create(environment)
        env = os.environ.copy()
        env['PIP_CACHE_DIR'] = str(root / '.cache' / 'pip')
        subprocess.run([str(python), '-m', 'pip', 'install', '--require-hashes', '-r', str(root/'requirements.lock')], cwd=root, env=env, check=True)
        subprocess.run([str(python), '-m', 'pip', 'install', '--no-deps', '-e', str(root)], cwd=root, env=env, check=True)
        command = [str(python), '-m', 'reconmap', 'setup', '--yes']
        if args.skip_tools:
            command.append('--skip-tools')
        for name in ('directory', 'go', 'cc'):
            value = getattr(args, name)
            if value:
                command.extend(['--' + name, str(value)])
        status = subprocess.run(command, cwd=root, env=env, check=False).returncode
        print('\nActivate once per terminal:')
        print(r'.\.venv\Scripts\Activate.ps1' if os.name == 'nt' else 'source .venv/bin/activate')
        print('Then: reconmap doctor | reconmap scan authorized.example | reconmap report')
        print(r'Or without activation: .\reconmap.cmd doctor' if os.name == 'nt' else 'Or without activation: ./reconmap doctor')
        return status
    except KeyboardInterrupt:
        print('Setup interrupted. Rerun bootstrap; completed verified tools are reused.', file=sys.stderr)
        return 130
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f'Bootstrap incomplete: {exc}. Install Python with pip/venv support; no privileged repair attempted.', file=sys.stderr)
        return 3


if __name__ == '__main__':
    raise SystemExit(main())
