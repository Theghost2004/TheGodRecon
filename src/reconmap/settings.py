"""Small per-user preferences; never a source of scope or executable trust."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic import Field

from .config import ConfigError, StrictModel
from .storage import atomic_json


def config_directory() -> Path:
    if override := os.environ.get('RECONMAP_CONFIG_DIR'):
        return Path(override).expanduser().absolute()
    base = Path(os.environ.get('APPDATA', str(Path.home() / 'AppData/Roaming'))) if os.name == 'nt' else Path(os.environ.get('XDG_CONFIG_HOME', str(Path.home() / '.config')))
    return base / 'thegodrecon'


def default_tool_directory() -> Path:
    if os.environ.get('RECONMAP_CONFIG_DIR'):
        return config_directory() / 'tools' / 'bin'
    base = Path(os.environ.get('LOCALAPPDATA', str(Path.home() / 'AppData/Local'))) if os.name == 'nt' else Path(os.environ.get('XDG_DATA_HOME', str(Path.home() / '.local/share')))
    return base / 'thegodrecon' / 'tools' / 'bin'


class Settings(StrictModel):
    version: Literal[1] = 1
    tool_directory: str = Field(default_factory=lambda: str(default_tool_directory()))
    registered_tools: dict[str, str] = {}
    preset: Literal['quick', 'standard', 'deep'] = 'standard'
    output_root: str = 'recon-output'
    auto_open: bool = False
    progress: bool = True
    last_run: str | None = None


def load_settings() -> Settings:
    path = config_directory() / 'settings.json'
    if not path.exists():
        return Settings()
    if path.is_symlink() or path.is_junction() or path.stat().st_size > 65536:
        raise ConfigError('Unsafe or oversized user settings; inspect ' + str(path))
    return Settings.model_validate_json(path.read_text(encoding='utf-8'))


def save_settings(settings: Settings) -> None:
    directory = config_directory()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.is_symlink() or directory.is_junction():
        raise ConfigError('Settings directory must not be a link or junction')
    path = directory / 'settings.json'
    if path.is_symlink() or path.is_junction() or (path.exists() and path.stat().st_nlink > 1):
        raise ConfigError('Unsafe settings file')
    atomic_json(path, settings.model_dump())
    if os.name != 'nt':
        path.chmod(0o600)


def discover(name: str, explicit: str | None = None) -> str:
    if explicit is not None:
        return explicit
    settings = load_settings()
    if name in settings.registered_tools:
        return settings.registered_tools[name]
    candidate = Path(settings.tool_directory) / (name + ('.exe' if os.name == 'nt' else ''))
    return str(candidate) if candidate.exists() else name


def register_tool(name: str, path: Path) -> None:
    from .tool_registry import BY_NAME
    if name not in BY_NAME:
        raise ConfigError('Unknown tool; use reconmap tools list')
    if not path.is_file():
        raise ConfigError('Executable path must be an existing file')
    settings = load_settings()
    settings.registered_tools[name] = str(path.resolve())
    save_settings(settings)
