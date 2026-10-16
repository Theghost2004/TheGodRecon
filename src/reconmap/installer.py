"""Explicit user-local, checksum-verified optional binary installation. No scanning."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import platform
import re
import tarfile
import tempfile
import sys
import urllib.request
import zipfile
from pathlib import Path

from .tool_registry import REGISTRY

PINS={tool.name: tool.version for tool in REGISTRY if tool.name != 'jsluice'}


def download(url: str, cap: int) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(cap + 1)
    if len(data) > cap:
        raise ValueError("Release download exceeds size cap")
    return data


def safe_destination(path: Path) -> None:
    if path.is_symlink() or path.is_junction() or (path.exists() and (not path.is_file() or path.stat().st_nlink > 1)):
        raise ValueError(f"Unsafe installation destination: {path}")


def atomic_install(path: Path, content: bytes, executable: bool = False) -> None:
    safe_destination(path)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.reconmap-', delete=False) as file:
        temp = Path(file.name)
        try:
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        except BaseException:
            file.close()
            temp.unlink(missing_ok=True)
            raise
    try:
        temp.chmod(0o700 if executable else 0o600)
        if executable:
            try:
                # Publish a complete binary without replacing an existing path.
                os.link(temp, path)
            except FileExistsError:
                safe_destination(path)
                with path.open('rb') as existing:
                    if hashlib.file_digest(existing, 'sha256').digest() != hashlib.sha256(content).digest():
                        raise ValueError(f"{path} contains a different binary. Preserve/remove it explicitly before updating")
        else:
            os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def install(name: str, directory: Path) -> dict:
    system=platform.system().lower()
    if system not in {"linux","windows"} or platform.machine().lower() not in {"x86_64","amd64"}:
        raise ValueError("This installer supports Linux/Windows x86-64 only")
    version=PINS[name]
    binary=name+('.exe' if system=='windows' else '')
    receipt_path=directory/(name+'.receipt.json')
    target=directory/binary
    if receipt_path.exists() and target.exists():
        safe_destination(receipt_path)
        safe_destination(target)
        if receipt_path.stat().st_size <= 65536:
            try:
                receipt=json.loads(receipt_path.read_text(encoding='utf-8'))
                with target.open('rb') as installed:
                    digest=hashlib.file_digest(installed,'sha256').hexdigest()
                if (receipt.get('name')==name and receipt.get('version')==version and receipt.get('platform')==system
                        and receipt.get('binary_sha256')==digest):
                    return receipt
            except (ValueError, AttributeError):
                pass
    arch="x64" if name=="gitleaks" else "amd64"
    ext="tar.gz" if name=="gitleaks" and system=="linux" else "zip"
    filename=f"{name}_{version}_{system}_{arch}.{ext}"
    owner="gitleaks" if name=="gitleaks" else "projectdiscovery"
    base=f"https://github.com/{owner}/{name}/releases/download/v{version}/"
    checksum_file = f"katana-{version}-checksums.txt" if name == 'katana' else f"{name}_{version}_checksums.txt"
    checksum_text=download(base+checksum_file, 1024*1024).decode()
    expected=next((parts[0] for line in checksum_text.splitlines() if len(parts := line.split()) == 2 and parts[1].lstrip('*')==filename),None)
    if not expected or not re.fullmatch('[0-9a-f]{64}',expected):
        raise ValueError("Authoritative archive checksum missing")
    data=download(base+filename, 256*1024*1024)
    if hashlib.sha256(data).hexdigest()!=expected:
        raise ValueError("Archive checksum mismatch; installation refused")
    binary=name+('.exe' if system=='windows' else '')
    if ext=='zip':
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if archive.getinfo(binary).file_size > 256*1024*1024:
                raise ValueError("Executable exceeds size cap")
            content=archive.read(binary)
    else:
        with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
            member=archive.getmember(binary)
            if not member.isfile():raise ValueError("Executable is not an archive regular file")
            if member.size > 256*1024*1024:raise ValueError("Executable exceeds size cap")
            content=archive.extractfile(member).read()
    directory.mkdir(parents=True,exist_ok=True)
    if directory.is_symlink() or directory.is_junction():
        raise ValueError("Installation directory must not be a link or junction")
    target=directory/binary
    # Maintenance updates are explicit; refuse replacing a different installed binary.
    digest=hashlib.sha256(content).hexdigest()
    safe_destination(directory/(name+'.receipt.json'))
    atomic_install(target, content, executable=True)
    receipt={"name":name,"version":version,"platform":system,"archive":filename,"archive_sha256":expected,"binary_sha256":digest,"path":str(target.absolute())}
    atomic_install(directory/(name+'.receipt.json'), (json.dumps(receipt,indent=2)+'\n').encode())
    return receipt


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tool',choices=list(PINS),action='append',required=True)
    parser.add_argument('--directory',type=Path,default=Path('.tools/bin'))
    args=parser.parse_args()
    try:
        for name in args.tool:print(json.dumps(install(name,args.directory)))
    except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError) as exc:
        parser.exit(2, f"Verified installation failed: {exc}\n")


if __name__=='__main__':main()
