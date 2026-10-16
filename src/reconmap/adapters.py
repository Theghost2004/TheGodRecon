from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from .security import redact
from .tool_registry import BY_NAME, REGISTRY

PINS = {tool.name: tool.version for tool in REGISTRY}
CAPABILITIES = {tool.name: tool.capability for tool in REGISTRY}
REQUIRED_FLAGS = {"subfinder": ["-json", "-collect-sources", "-disable-update-check", "-rate-limit"], "urlfinder": ["-jsonl", "-collect-sources", "-disable-update-check", "-rate-limit"], "gitleaks": ["--redact", "--report-format", "--report-path"], "jsluice": ["urls", "secrets"], "dnsx": ["-json", "-rate-limit", "-disable-update-check"], "httpx": ["-json", "-rate-limit", "-disable-update-check"], "katana": ["-jsonl", "-crawl-duration", "-disable-update-check"], "nuclei": ["-jsonl", "-no-interactsh", "-disable-update-check"]}
REVIEWED_JSLUICE_HASHES = {"0fe91d8b9a88b1029e90b6265417b4a34b3e617b0959b4d2aceea219d7917c43"}


@dataclass
class ToolInfo:
    name: str
    path: str | None
    version: str
    sha256: str | None
    available: bool
    supported: bool
    capability: str
    reason: str
    compatible: bool = False

    def record(self) -> dict:
        spec = BY_NAME[self.name]
        return {**asdict(self), "id": spec.id, "risk": spec.risk, "fallback": list(spec.fallback), "adapter_version": 3}


def terminate_tree(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True, check=False)
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    proc.wait()


def creation_options() -> dict:
    return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}


def identify(name: str, override: str | None = None) -> ToolInfo:
    from .settings import discover
    path = shutil.which(discover(name, override))
    if path is None:
        return ToolInfo(name, None, "unavailable", None, False, False, CAPABILITIES[name], "Install a verified user-local binary; see docs/TOOLS.md")
    path = str(Path(path).resolve())
    sha = None
    flags = ["-h"] if name == "jsluice" else ["version"] if name == "gitleaks" else ["-version", "-duc"]
    try:
        with Path(path).open("rb") as binary:
            sha = hashlib.file_digest(binary, "sha256").hexdigest()
        if name == "jsluice" and sha not in REVIEWED_JSLUICE_HASHES:
            from .jsbuild import trusted_build
            if not trusted_build(Path(path), sha):
                return ToolInfo(name, path, "unverified build", sha, True, False, CAPABILITIES[name],
                    "Unreviewed jsluice fingerprint; run reconmap setup for a verified source build. Native Tree-sitter available")
        # Use the same bounded process handling as scan adapters. Invalid binaries,
        # excessive help output and timeouts become a dependency diagnostic.
        with tempfile.TemporaryDirectory(prefix="reconmap-doctor-") as temporary:
            result = asyncio.run(execute([path, *flags], Path(temporary), 8, limit=1024*1024))
            help_result = asyncio.run(execute([path, "--help" if name == "gitleaks" else "-h"], Path(temporary), 8, limit=1024*1024))
        text = result.stdout + result.stderr
        if name == "jsluice":
            version = "unversioned; executable sha256 identity"
            verified = "jsluice - Extract URLs" in text  # fingerprint checked before any execution
        else:
            match = re.search(r"\bv?(\d+\.\d+\.\d+)\b", text)
            version = match[1] if match else "unrecognized"
            verified = version == PINS[name]
        # Distinguish the ProjectDiscovery binary from Python's unrelated httpx CLI.
        help_text = help_result.stdout + help_result.stderr
        if name == "httpx" and "projectdiscovery" not in (help_text + text).lower():
            verified = False
        flags_present = all(f in help_text for f in REQUIRED_FLAGS.get(name, []))
        compatible = verified and flags_present and result.code == help_result.code == 0
        supported = compatible and not BY_NAME[name].policy_reason
        reason = BY_NAME[name].policy_reason or ("reviewed flags present; version compatible" if supported else "unreviewed version/flags; install the reviewed binary")
        if name == "jsluice" and not verified:
            reason = "Unversioned jsluice build hash has not been reviewed; native Tree-sitter remains available. Review the build and add its fingerprint before execution"
        return ToolInfo(name, path, version, sha, True, supported, CAPABILITIES[name], reason, compatible)
    except (OSError, ValueError, TimeoutError) as exc:
        return ToolInfo(name, path, "failed version check", sha, True, False, CAPABILITIES[name], redact(f"{type(exc).__name__}: {exc}"))


def doctor(overrides: dict[str, str] | None = None) -> dict[str, ToolInfo]:
    return {name: identify(name, (overrides or {}).get(name)) for name in PINS}


@dataclass
class ProcessResult:
    code: int
    stdout: str
    stderr: str


class ToolTimeout(TimeoutError):
    """A killed tool can still have useful complete records in its prefix."""
    def __init__(self, result):
        super().__init__("Tool time cap reached; partial output retained")
        self.result = result


class ToolOutputLimit(ValueError):
    def __init__(self, result):
        super().__init__("Tool output cap reached; bounded prefix retained")
        self.result = result


async def execute(argv: list[str], cwd: Path, timeout: float, limit: int = 10 * 1024 * 1024, expected_sha: str | None = None, output_files: tuple[Path, ...] = (), env_updates: dict | None = None) -> ProcessResult:
    if expected_sha is not None:
        with Path(argv[0]).open('rb') as binary:
            if hashlib.file_digest(binary, 'sha256').hexdigest() != expected_sha:
                raise ValueError("Executable identity changed after preflight; refusing execution")
    env = os.environ.copy()
    # Prevent tool defaults from putting target-specific output in the real home.
    home = cwd / "home"
    home.mkdir(exist_ok=True)
    env.update({"HOME": str(home), "USERPROFILE": str(home), "APPDATA": str(home), "LOCALAPPDATA": str(home), "XDG_CONFIG_HOME": str(home), "XDG_CACHE_HOME": str(home), "XDG_STATE_HOME": str(home), "TMPDIR": str(cwd), "TEMP": str(cwd), "TMP": str(cwd)})
    env.update(env_updates or {})
    options = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
    proc = await asyncio.create_subprocess_exec(*argv, cwd=cwd, env=env, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, **options)

    buffers = [bytearray(), bytearray()]

    async def read(stream: asyncio.StreamReader, output: bytearray) -> bytes:
        while chunk := await stream.read(65536):
            remaining = limit - len(output)
            output.extend(chunk[:remaining])
            if len(chunk) > remaining:
                raise ValueError("Tool output cap reached")
        return bytes(output)

    async def kill() -> None:
        if os.name == "nt":
            if proc.returncode is None:
                killer = await asyncio.create_subprocess_exec("taskkill", "/PID", str(proc.pid), "/T", "/F", stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
                try:
                    await asyncio.wait_for(killer.wait(), 5)
                except TimeoutError:
                    killer.kill()
                    await killer.wait()
                if proc.returncode is None:
                    proc.kill()
        else:
            # A parent can exit while descendants still own its stdout pipes.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    async def monitor_files():
        while True:
            for path in output_files:
                if path.exists() and path.stat().st_size > limit:
                    raise ValueError("Tool output cap reached")
            if proc.returncode is not None:
                return
            await asyncio.sleep(0.05)

    readers = [asyncio.create_task(read(proc.stdout, buffers[0])), asyncio.create_task(read(proc.stderr, buffers[1])), asyncio.create_task(monitor_files())]
    try:
        async with asyncio.timeout(timeout):
            stdout, stderr, _ = await asyncio.gather(*readers)
            await proc.wait()
        return ProcessResult(proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace"))
    except BaseException as exc:
        for task in readers:
            task.cancel()
        await asyncio.gather(*readers, return_exceptions=True)
        await kill()
        # Drain after killing: waiting first can deadlock on a full pipe buffer.
        async def discard(stream):
            while await stream.read(65536):
                pass
        async with asyncio.timeout(5):
            await asyncio.gather(discard(proc.stdout), discard(proc.stderr), proc.wait())
        partial = ProcessResult(proc.returncode or -1, buffers[0].decode(errors="replace"), buffers[1].decode(errors="replace"))
        if isinstance(exc, TimeoutError):
            raise ToolTimeout(partial) from exc
        if isinstance(exc, ValueError) and str(exc) == "Tool output cap reached":
            raise ToolOutputLimit(partial) from exc
        if isinstance(exc, asyncio.CancelledError):
            exc.result = partial
        raise


def command(info: ToolInfo, target_host: str, cwd: Path, seconds: int, input_path: Path | None = None, sources: list[str] | None = None) -> list[str]:
    if BY_NAME[info.name].policy_reason:
        raise ValueError("blocked-by-policy: " + BY_NAME[info.name].policy_reason)
    if not info.supported or not info.path:
        raise ValueError(f"Unsupported {info.name}: {info.reason}")
    if info.name == "subfinder":
        return [info.path, "-d", target_host, "-json", "-cs", "-silent", "-duc", "-s", ",".join(sources or ["crtsh"]), "-rl", "2", "-timeout", str(min(seconds, 15)), "-max-time", "1"]
    if info.name == "urlfinder":
        return [info.path, "-d", target_host, "-j", "-cs", "-silent", "-duc", "-s", ",".join(sources or ["commoncrawl"]), "-fs", "fqdn", "-rl", "2", "-timeout", str(min(seconds, 15)), "-max-time", "1"]
    if info.name == "gitleaks" and input_path:
        return [info.path, "dir", str(input_path.resolve()), "--no-banner", "--redact=100", "--report-format", "json", "--report-path", str((cwd / "findings.json").resolve()), "--exit-code", "10", "--max-target-megabytes", "10"]
    if info.name == "jsluice" and input_path:
        return [info.path, "urls", str(input_path.resolve())]
    raise ValueError("Adapter has no safe invocation for this operation")


def parse_records(name: str, text: str) -> tuple[list[dict], list[str]]:
    records: list[dict] = []
    errors: list[str] = []
    if name == "gitleaks":
        try:
            data = json.loads(text or "[]")
            if not isinstance(data, list) or any(not isinstance(x, dict) or not isinstance(x.get("RuleID"), str) or not isinstance(x.get("File", ""), str) for x in data):
                raise ValueError("Expected Gitleaks findings array with RuleID")
            return data, []
        except (ValueError, TypeError) as exc:
            return [], [str(exc)]
    fields = {"subfinder": "host", "urlfinder": "url", "jsluice": "url", "dnsx": "host", "httpx": "url", "katana": "request", "nuclei": "matched-at"}
    for i, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
            if name == "katana" and isinstance(record, dict):
                request = record.get("request")
                if not isinstance(request, dict) or not isinstance(request.get("endpoint"), str):
                    raise ValueError("Missing Katana request.endpoint")
            elif not isinstance(record, dict) or not isinstance(record.get(fields[name]), str):
                raise ValueError(f"Missing string field {fields[name]}")
            if name == "jsluice" and not isinstance(record.get("method", ""), str):
                raise ValueError("Invalid method field")
            records.append(record)
        except (ValueError, KeyError, TypeError) as exc:
            errors.append(f"line {i}: {exc}")
    return records, errors


def capture(result: ProcessResult, cwd: Path) -> None:
    (cwd / "stdout.txt").write_text(redact(result.stdout), encoding="utf-8")
    (cwd / "stderr.txt").write_text(redact(result.stderr), encoding="utf-8")
