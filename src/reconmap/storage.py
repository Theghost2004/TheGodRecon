from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import socket
import sqlite3
import stat
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from .config import ScanConfig, normalize_url

SCHEMA = 1
POLICY_REVISION = 2


def validate_run_tree(run: Path) -> None:
    """Reject redirected writes/reads in an existing private run directory.

    This catches accidental or preexisting tampering, not a concurrent attacker
    with the same OS account; run directories must remain private.
    """
    def check(path: Path) -> None:
        info = path.lstat()
        if path.is_symlink() or path.is_junction():
            raise ValueError(f"Unsafe run entry: link or junction at {path.name}")
        if stat.S_ISREG(info.st_mode):
            if info.st_nlink > 1:
                raise ValueError(f"Unsafe run entry: hard link at {path.name}")
        elif not stat.S_ISDIR(info.st_mode):
            raise ValueError(f"Unsafe run entry: non-regular file at {path.name}")

    check(run)
    if not run.is_dir():
        raise ValueError("Run must be an existing non-symlink directory")
    for directory, dirs, files in os.walk(run, followlinks=False):
        for name in dirs + files:
            check(Path(directory) / name)


def artifact_path(run: Path, relative: str) -> Path:
    if not re.fullmatch(r"assets/(?:js|maps|content)/[0-9a-f]{64}\.(?:js|json|bin)", relative):
        raise ValueError("Invalid artifact path in run database")
    path = run / relative
    if not path.resolve().is_relative_to(run.resolve()):
        raise ValueError("Artifact path leaves run directory")
    return path


def timestamp() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def safe_name(target: str) -> str:
    host = urlsplit(normalize_url(target)).hostname
    name = re.sub(r"[^a-z0-9.-]", "_", host).rstrip(" .")
    if name.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}:
        name = "host_" + name
    if len(name) > 160:
        name = name[:140] + "_" + hashlib.sha256(host.encode()).hexdigest()[:16]
    return name


def allocate_run(root: Path, target: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    name = safe_name(target)
    for i in range(1000000):
        path = root / (name if i == 0 else f"{i}_{name}")
        try:
            path.mkdir(mode=0o700)
            return path.resolve()
        except FileExistsError:
            continue
    raise RuntimeError("Run directory collision limit reached")


def atomic_json(path: Path, value: object) -> None:
    tmp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with tmp.open("x", encoding="utf-8") as f:
            json.dump(value, f, ensure_ascii=True, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def pid_alive(pid: int) -> bool:
    if os.name == "nt":
        import ctypes
        kernel = ctypes.windll.kernel32
        kernel.OpenProcess.argtypes = [ctypes.c_ulong,ctypes.c_int,ctypes.c_ulong]
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            return kernel.GetLastError() == 5
        kernel.CloseHandle(handle)
        return True
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


class RunLock:
    def __init__(self, run: Path, break_stale: bool = False):
        self.path = run / "run.lock"
        self.token = uuid.uuid4().hex
        self.break_stale = break_stale

    def __enter__(self) -> RunLock:
        validate_run_tree(self.path.parent)
        if self.path.exists() and self.break_stale:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if data.get("host") == socket.gethostname() and pid_alive(int(data["pid"])):
                raise ValueError("Run is locked by a live process")
            self.path.unlink()
        try:
            with self.path.open("x", encoding="utf-8") as f:
                json.dump({"pid": os.getpid(), "host": socket.gethostname(), "token": self.token}, f)
                f.flush()
                os.fsync(f.fileno())
        except FileExistsError as exc:
            raise ValueError("Run is locked; use --break-lock only after confirming the old scan stopped") from exc
        return self

    def __exit__(self, *args: object) -> None:
        if self.path.exists() and json.loads(self.path.read_text(encoding="utf-8")).get("token") == self.token:
            self.path.unlink()


DDL = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runs(run_id TEXT PRIMARY KEY, target TEXT, original_target TEXT, state TEXT, created TEXT, updated TEXT, config_json TEXT);
CREATE TABLE IF NOT EXISTS hosts(host TEXT PRIMARY KEY, state TEXT, first_seen TEXT);
CREATE TABLE IF NOT EXISTS dns(id INTEGER PRIMARY KEY, host TEXT, address TEXT, kind TEXT, time TEXT, source TEXT);
CREATE TABLE IF NOT EXISTS origins(origin TEXT PRIMARY KEY, state TEXT, status INTEGER, time TEXT);
CREATE TABLE IF NOT EXISTS urls(url TEXT PRIMARY KEY, grouping_key TEXT, source TEXT, state TEXT DEFAULT 'untested', depth INTEGER, status INTEGER, title TEXT, content_type TEXT, hash TEXT, bytes INTEGER, time TEXT);
CREATE TABLE IF NOT EXISTS observations(id INTEGER PRIMARY KEY, identity TEXT UNIQUE, subject TEXT, kind TEXT, data TEXT, source TEXT, time TEXT);
CREATE TABLE IF NOT EXISTS parameters(url TEXT, name TEXT, location TEXT, source TEXT, PRIMARY KEY(url,name,location,source));
CREATE TABLE IF NOT EXISTS artifacts(hash TEXT PRIMARY KEY, path TEXT, kind TEXT, bytes INTEGER, analyzed INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS relationships(parent TEXT, child TEXT, kind TEXT, source TEXT, PRIMARY KEY(parent,child,kind,source));
CREATE TABLE IF NOT EXISTS findings(fingerprint TEXT PRIMARY KEY, rule TEXT, subject TEXT, title TEXT, priority INTEGER, reasons TEXT, confidence TEXT, severity TEXT, validation TEXT, evidence TEXT, source TEXT, time TEXT);
CREATE TABLE IF NOT EXISTS analyst_actions(id INTEGER PRIMARY KEY, fingerprint TEXT, status TEXT, note TEXT, time TEXT);
CREATE TABLE IF NOT EXISTS stages(name TEXT PRIMARY KEY, state TEXT, detail TEXT, time TEXT);
CREATE TABLE IF NOT EXISTS jobs(url TEXT PRIMARY KEY, depth INTEGER, source TEXT, state TEXT, attempts INTEGER DEFAULT 0);
"""


class Store:
    def __init__(self, run: Path):
        self.run = run
        for name in ("recon.sqlite", "recon.sqlite-wal", "recon.sqlite-shm", "recon.sqlite-journal"):
            path = run / name
            if path.is_symlink() or path.is_junction() or (path.exists() and (not path.is_file() or path.stat().st_nlink > 1)):
                raise ValueError("Unsafe database file in run directory")
        self.conn = sqlite3.connect(run / "recon.sqlite")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA trusted_schema=OFF")
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=FULL")
        version = self.conn.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, SCHEMA):
            self.conn.close()
            raise ValueError(f"Unsupported database schema {version}")
        # Migration 0 -> 1. Later versions require explicit migrations here.
        self.conn.executescript(DDL)
        self.conn.execute(f"PRAGMA user_version={SCHEMA}")
        self.conn.commit()

    def execute(self, sql: str, args: tuple = ()) -> sqlite3.Cursor:
        cursor = self.conn.execute(sql, args)
        self.conn.commit()
        return cursor

    def rows(self, table: str) -> list[dict]:
        if table not in {"runs", "hosts", "dns", "origins", "urls", "observations", "parameters", "artifacts", "relationships", "findings", "stages", "jobs", "analyst_actions"}:
            raise ValueError("Unknown table")
        rows = [dict(row) for row in self.conn.execute(f"SELECT * FROM {table}")]
        if table == "artifacts":
            for row in rows:
                if artifact_path(self.run, row["path"]).stem != row["hash"]:
                    raise ValueError("Artifact hash/path mismatch in run database")
        return rows

    def meta(self, key: str, default: object = None) -> object:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set_meta(self, key: str, value: object) -> None:
        self.execute("INSERT OR REPLACE INTO meta VALUES(?,?)", (key, json.dumps(value)))

    def stage(self, name: str, state: str, detail: str = "") -> None:
        self.execute("INSERT OR REPLACE INTO stages VALUES(?,?,?,?)", (name, state, detail, timestamp()))

    def observed(self, subject: str, kind: str, data: object, source: str, identity: str | None = None) -> None:
        self.execute("INSERT OR IGNORE INTO observations(identity,subject,kind,data,source,time) VALUES(?,?,?,?,?,?)", (identity, subject, kind, json.dumps(data), source, timestamp()))

    def relate(self, parent: str, child: str, kind: str, source: str) -> None:
        self.execute("INSERT OR IGNORE INTO relationships VALUES(?,?,?,?)", (parent, child, kind, source))

    def finding(self, rule: str, subject: str, title: str, evidence: dict, confidence: str = "medium", priority: int = 40, reasons: list[str] | None = None, source: str = "native") -> None:
        fingerprint = hashlib.sha256(f"{rule}\0{subject}\0{evidence.get('hash','')}\0{evidence.get('line','')}".encode()).hexdigest()
        self.execute("INSERT OR IGNORE INTO findings VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (fingerprint, rule, subject, title, priority, json.dumps(reasons or ["current local evidence; manual review required"]), confidence, "unassessed", "candidate", json.dumps(evidence), source, timestamp()))
        self.relate(subject,"finding:"+fingerprint,"candidate_finding",source)
        if evidence.get("hash"):
            self.relate("artifact:"+evidence["hash"],"finding:"+fingerprint,"candidate_evidence",source)

    def close(self) -> None:
        self.conn.close()


def read_manifest(run: Path) -> dict:
    validate_run_tree(run)
    for name in ("manifest.json", "config.effective.json", "recon.sqlite"):
        if not (run / name).is_file() or (run / name).is_symlink():
            raise ValueError(f"Invalid run: missing or unsafe {name}")
    if any((run / name).stat().st_size > 1024 * 1024 for name in ("manifest.json", "config.effective.json")):
        raise ValueError("Run metadata exceeds 1 MiB")
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA or not re.fullmatch(r"[0-9a-f]{32}", str(manifest.get("run_id", ""))) or not isinstance(manifest.get("target"), str) or manifest.get("state") not in {"created", "running", "interrupted", "partial", "completed"}:
        raise ValueError("Invalid or unsupported run manifest")
    config = ScanConfig.model_validate_json((run / "config.effective.json").read_text(encoding="utf-8"))
    if manifest.get("config_digest") != config.digest() or normalize_url(manifest["target"]) != manifest["target"] or urlsplit(manifest["target"]).hostname != manifest.get("host"):
        raise ValueError("Run manifest target/configuration integrity check failed")
    from .scope import ScopePolicy
    if not ScopePolicy(config.scope).decision(manifest["target"])[0]:
        raise ValueError("Run target is outside its saved scope")
    if manifest.get("baseline") is not None and not isinstance(manifest["baseline"], str):
        raise ValueError("Invalid baseline in run manifest")
    if type(manifest.get("requests", 0)) is not int or manifest.get("requests", 0) < 0 or not isinstance(manifest.get("transport", ""), str):
        raise ValueError("Invalid request count/transport in run manifest")
    return manifest


def safe_csv(value: object) -> str:
    text = str(value if value is not None else "")
    return "'" + text if text.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else text
