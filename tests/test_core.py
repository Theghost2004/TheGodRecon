from __future__ import annotations

import concurrent.futures
import json
from pathlib import Path

import pytest

from reconmap.config import ConfigError, ScanConfig, Scope, default_config, normalize_url, request_url
from reconmap.engine import prepare_run
from reconmap.scope import ScopePolicy
from reconmap.storage import RunLock, Store, allocate_run, atomic_json, read_manifest, safe_name


def test_folder_sequence_and_smallest_gap(tmp_path):
    root=tmp_path/"out"
    a=allocate_run(root,"https://Example.COM/path?x=1")
    b=allocate_run(root,"example.com")
    c=allocate_run(root,"example.com")
    assert [p.name for p in (a,b,c)]==["example.com","1_example.com","2_example.com"]
    marker=a/"keep.txt"; marker.write_text("preserve")
    b.rmdir()
    assert allocate_run(root,"example.com").name=="1_example.com"
    assert marker.read_text()=="preserve"


def test_concurrent_allocation(tmp_path):
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        paths=list(pool.map(lambda _:allocate_run(tmp_path,"example.com"),range(20)))
    assert len(set(paths))==20
    assert {p.name for p in paths}=={"example.com",*(f"{i}_example.com" for i in range(1,20))}


def test_files_and_symlinks_occupied(tmp_path):
    (tmp_path/"example.com").write_text("keep")
    try:
        (tmp_path/"1_example.com").symlink_to(tmp_path/"missing",target_is_directory=True)
    except OSError:
        (tmp_path/"1_example.com").write_text("symlink privilege unavailable on Windows; collision equivalent")
    assert allocate_run(tmp_path,"example.com").name=="2_example.com"
    assert (tmp_path/"example.com").read_text()=="keep"


@pytest.mark.parametrize("seed,name",[("https://www.Example.com:443/path","www.example.com"),("http://127.0.0.1:8080/","127.0.0.1"),("http://[::1]:8000/","__1"),("CON","host_con"),("https://例え.テスト/","xn--r8jz45g.xn--zckzah")])
def test_portable_names(seed,name):
    assert safe_name(seed)==name


@pytest.mark.parametrize("url",["https://user:pass@example.com/","file:///etc/passwd","https://../","https://example.com:70000/","https://example.com\\evil/","https://example.com/\n"])
def test_reject_invalid_urls(url):
    with pytest.raises(ConfigError): normalize_url(url)


def test_scope_exact_wildcard_exclusion_idna():
    p=ScopePolicy(Scope(hosts=["example.com","*.例え.テスト"],exclude_hosts=["private.例え.テスト"]))
    assert p.decision("https://EXAMPLE.COM/a")[0]
    assert not p.decision("https://www.example.com/")[0]
    assert not p.decision("https://example.com.attacker.test/")[0]
    assert not p.decision("https://例え.テスト/")[0]
    assert p.decision("https://www.例え.テスト/")[0]
    assert not p.decision("https://private.例え.テスト/")[0]


def test_scope_paths_ports_actions():
    p=ScopePolicy(Scope(hosts=["example.com"],ports=[443],paths=["/API"],exclude_paths=["/API/private"]))
    for url in ["https://example.com/API","https://example.com/API/users"]:assert p.decision(url)[0]
    for url in ["http://example.com/API","https://example.com/api","https://example.com/API2","https://example.com/API/private/a","https://example.com/API/%70rivate","https://example.com/API/../public","https://example.com/API/%2e%2e/public","https://example.com/API/logout","https://example.com/API/%252e%252e/x"]:assert not p.decision(url)[0],url


def test_private_addresses_and_lab():
    p=ScopePolicy(Scope(hosts=["example.com"]))
    for ip in ["127.0.0.1","10.0.0.1","169.254.169.254","::1","::ffff:127.0.0.1","192.168.1.1","0.0.0.0"]:assert not p.ip_allowed(ip)
    assert p.ip_allowed("8.8.8.8")
    lab=ScopePolicy(Scope(hosts=["localhost"],lab=True))
    assert lab.ip_allowed("127.0.0.1") and lab.ip_allowed("::1")
    assert not lab.ip_allowed("10.0.0.1") and not lab.ip_allowed("8.8.8.8")


def test_grouping_preserves_semantics():
    values=["http://example.com/a","https://example.com/a","https://example.com:443/a","https://example.com/A","https://example.com/a/","https://example.com/a?x=1&x=2","https://example.com/a?x=2&x=1","https://example.com/a#route"]
    assert len({normalize_url(v) for v in values})==len(values)
    assert request_url(values[-1])=="https://example.com/a"


def test_resume_manifest_config_lock(tmp_path):
    config=default_config("example.com"); config.mode="demo"
    path,manifest=prepare_run(config,"example.com",tmp_path)
    assert read_manifest(path)==manifest
    assert prepare_run(config,None,tmp_path,resume=path)[0]==path
    with RunLock(path):
        with pytest.raises(ValueError,match="locked"):
            with RunLock(path):pass
        with pytest.raises(ValueError,match="live"):
            with RunLock(path,True):pass
    assert not (path/"run.lock").exists()
    config.scope.exclude_paths=["/admin"]
    with pytest.raises(ValueError,match="changed"):prepare_run(config,None,tmp_path,resume=path)
    assert len(list(tmp_path.iterdir()))==1


def test_atomic_manifest_failed_write_preserves_previous(tmp_path,monkeypatch):
    path=tmp_path/"manifest.json"
    atomic_json(path,{"old":True})
    def failed(*args):raise OSError("simulated interrupted replacement")
    monkeypatch.setattr("reconmap.storage.os.replace",failed)
    with pytest.raises(OSError):atomic_json(path,{"new":True})
    assert json.loads(path.read_text())=={"old":True}
    assert list(tmp_path.iterdir())==[path]


def test_store_dedup_schema(tmp_path):
    store=Store(tmp_path)
    store.observed("a","kind",{},"fixture",identity="same")
    store.observed("a","kind",{},"fixture",identity="same")
    store.finding("rule","a","lead",{})
    store.finding("rule","a","lead",{})
    assert len(store.rows("observations"))==1 and len(store.rows("findings"))==1
    from reconmap.storage import SCHEMA
    assert store.conn.execute("PRAGMA user_version").fetchone()[0]==SCHEMA
    store.close()
