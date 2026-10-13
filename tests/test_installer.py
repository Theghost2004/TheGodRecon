from __future__ import annotations

import hashlib
import importlib.util
import io
import zipfile
from pathlib import Path

import pytest

spec=importlib.util.spec_from_file_location('installer',Path(__file__).parents[1]/'tools/install_tools.py')
installer=importlib.util.module_from_spec(spec);spec.loader.exec_module(installer)


def archive(content):
    stream=io.BytesIO()
    with zipfile.ZipFile(stream,'w') as z:z.writestr('gitleaks.exe',content)
    return stream.getvalue()


def mock_windows(monkeypatch,data,checksum):
    monkeypatch.setattr(installer.platform,'system',lambda:'Windows')
    monkeypatch.setattr(installer.platform,'machine',lambda:'AMD64')
    def request(url,**kwargs):
        if url.endswith('checksums.txt'):return io.BytesIO((checksum+'  gitleaks_8.30.1_windows_x64.zip\n').encode())
        assert url.endswith('gitleaks_8.30.1_windows_x64.zip')
        return io.BytesIO(data)
    monkeypatch.setattr(installer.urllib.request,'urlopen',request)


def test_windows_archive_name_and_verified_extraction(tmp_path,monkeypatch):
    data=archive(b'fixture binary')
    mock_windows(monkeypatch,data,hashlib.sha256(data).hexdigest())
    result=installer.install('gitleaks',tmp_path)
    assert (tmp_path/'gitleaks.exe').read_bytes()==b'fixture binary'
    assert result['platform']=='windows' and result['path'].endswith('gitleaks.exe')
    assert installer.install('gitleaks',tmp_path)['binary_sha256']==result['binary_sha256']


def test_checksum_mismatch_never_uses_artifact(tmp_path,monkeypatch):
    data=archive(b'untrusted binary');mock_windows(monkeypatch,data,'0'*64)
    with pytest.raises(ValueError,match='mismatch'):installer.install('gitleaks',tmp_path)
    assert not list(tmp_path.iterdir())


def test_different_binary_is_preserved(tmp_path,monkeypatch):
    data=archive(b'new binary');mock_windows(monkeypatch,data,hashlib.sha256(data).hexdigest())
    (tmp_path/'gitleaks.exe').write_bytes(b'user binary')
    with pytest.raises(ValueError,match='different'):installer.install('gitleaks',tmp_path)
    assert (tmp_path/'gitleaks.exe').read_bytes()==b'user binary'


@pytest.mark.parametrize('filename', ['gitleaks.exe', 'gitleaks.receipt.json'])
def test_installer_refuses_symlinks_without_modifying_target(tmp_path, monkeypatch, filename):
    data=archive(b'fixture binary');mock_windows(monkeypatch,data,hashlib.sha256(data).hexdigest())
    outside=tmp_path/'keep';outside.write_bytes(b'fixture binary')
    try:
        (tmp_path/filename).symlink_to(outside)
    except OSError:
        pytest.skip('Native symlink privilege unavailable')
    with pytest.raises(ValueError,match='Unsafe'):
        installer.install('gitleaks',tmp_path)
    assert outside.read_bytes()==b'fixture binary'


def test_matching_binary_is_not_rewritten(tmp_path, monkeypatch):
    data=archive(b'fixture binary');mock_windows(monkeypatch,data,hashlib.sha256(data).hexdigest())
    installer.install('gitleaks',tmp_path)
    before=(tmp_path/'gitleaks.exe').stat()
    installer.install('gitleaks',tmp_path)
    after=(tmp_path/'gitleaks.exe').stat()
    assert (before.st_ino, before.st_mtime_ns)==(after.st_ino, after.st_mtime_ns)
    assert not list(tmp_path.glob('.reconmap-*'))


def test_checksum_file_blank_lines_are_accepted(tmp_path, monkeypatch):
    data=archive(b'fixture binary')
    monkeypatch.setattr(installer.platform,'system',lambda:'Windows')
    monkeypatch.setattr(installer.platform,'machine',lambda:'AMD64')
    def request(url,**kwargs):
        return io.BytesIO(('\n\n'+hashlib.sha256(data).hexdigest()+'  gitleaks_8.30.1_windows_x64.zip\n\n').encode() if url.endswith('checksums.txt') else data)
    monkeypatch.setattr(installer.urllib.request,'urlopen',request)
    assert installer.install('gitleaks',tmp_path)['name']=='gitleaks'
