import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from reconmap import wordlists as w
from reconmap.cli import effective_config, main, parser
from reconmap.config import ConfigError, default_config
from reconmap.settings import load_settings, save_settings


def config(*args):
    return effective_config(parser().parse_args(['scan','example.com',*args]))


def test_god_alias_defaults_and_legacy_digest():
    god=config('--god-mode')
    assert god.model_dump()==config('--full-coverage').model_dump()
    assert len(god.selected_tools)==8 and god.discovery.enabled and god.discovery.god_mode
    assert god.budgets.requests==5000 and god.budgets.depth==3 and god.budgets.minutes==30
    assert god.scope==default_config('example.com').scope
    assert god.discovery.max_concurrent_jobs==2
    assert not config().discovery.enabled and not config('--all-tool').discovery.enabled
    original=config(); data=original.model_dump(); data.pop('discovery')
    assert type(original).model_validate(data).digest()==original.digest()


def test_god_yaml_scope_budget_and_overrides(tmp_path):
    import yaml
    c=default_config('example.com');c.scope.paths=['/authorized'];c.budgets.requests=41;c.budgets.depth=1
    path=tmp_path/'scope.yml';path.write_text(yaml.safe_dump(c.model_dump()))
    chosen=config('--config',str(path),'--god-mode','--max-minutes','3')
    assert chosen.scope==c.scope and chosen.budgets.requests==41 and chosen.budgets.depth==1
    assert chosen.budgets.minutes==3
    assert main(['scan','https://example.com/','--config',str(path),'--god-mode','--output-root',str(tmp_path/'runs')])==3
    assert not (tmp_path/'runs').exists()


@pytest.mark.parametrize('args', [ ['--all-tool'],['--tools','6'],['--mode','offline'],['--wordlist-budget','-1'],['--max-concurrent-jobs','3'] ])
def test_invalid_god_options_before_run(tmp_path,args):
    assert main(['scan','example.com','--god-mode',*args,'--output-root',str(tmp_path/'runs')])==3
    assert not (tmp_path/'runs').exists()


@pytest.fixture
def upstream(monkeypatch):
    bodies={'common':b'admin\nlogin\napi\nsecret.php\nrobots.txt\n', 'api':b'api/users\napi/status\n',
            'assets':b'assets\njs\nrandom\n', 'dns':b'www\napi\n', 'license':b'Fixture license\n'}
    catalog=json.loads(json.dumps(w.CATALOG))
    for name,body in bodies.items():
        catalog['files'][name]['bytes']=len(body);catalog['files'][name]['sha256']=hashlib.sha256(body).hexdigest()
    monkeypatch.setattr(w,'CATALOG',catalog);monkeypatch.setattr(w,'CONVENTIONAL',())
    calls=[]
    def download(url,limit):
        assert url.startswith('https://raw.githubusercontent.com/danielmiessler/SecLists/'+catalog['revision']+'/')
        name=next(n for n,s in catalog['files'].items() if url.endswith('/'+s['path']))
        assert limit==len(bodies[name]);calls.append(name);return bodies[name]
    monkeypatch.setattr(w,'download',download)
    return bodies,calls,download


def test_fresh_install_idempotence_receipt_and_cli(upstream,capsys):
    installed=w.install();assert installed['installed'] and installed['integrity']=='verified'
    assert Path(installed['path'],'reconmap-receipt.json').is_file()
    assert load_settings().seclists_directory==installed['path']
    assert len(upstream[1])==5
    assert w.install()['path']==installed['path'] and len(upstream[1])==5
    assert main(['wordlists','list','--json'])==0
    assert 'installed' in capsys.readouterr().out.lower()


@pytest.fixture
def verified_copy(tmp_path,upstream):
    def create(location):
        target=tmp_path/location
        for name,spec in w.CATALOG['files'].items():
            path=target/spec['path'];path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(upstream[0][name])
        return target
    return create


def test_explicit_copy_reused(verified_copy,upstream):
    target=verified_copy('custom SecLists café')
    for _ in range(2):
        result=w.install(target)
        assert result['installed'] is True and result['integrity']=='verified'
        assert Path(result['path'])==target
        assert set(result['available'])=={'common','api','assets','dns'}
        for spec in w.CATALOG['files'].values():
            assert hashlib.sha256((target/spec['path']).read_bytes()).hexdigest()==spec['sha256']
        assert Path(load_settings().seclists_directory)==target
        assert upstream[1]==[]


def test_conventional_copy_reused(verified_copy,upstream,monkeypatch):
    # Simulate only this module's selector; pathlib retains the real host OS.
    monkeypatch.setattr(w,'os',SimpleNamespace(name='posix',environ=w.os.environ))
    target=verified_copy('usr/share/seclists')
    assert load_settings().seclists_directory is None
    assert not w.default_directory().exists()
    monkeypatch.setattr(w,'CONVENTIONAL',(target,))
    located=w.locate()
    assert located['installed'] is True and located['integrity']=='verified'
    assert Path(located['path'])==target
    assert Path(w.install()['path'])==target
    assert Path(load_settings().seclists_directory)==target
    assert upstream[1]==[]


def test_windows_ignores_conventional_copy_until_registered(verified_copy,upstream,monkeypatch):
    monkeypatch.setattr(w,'os',SimpleNamespace(name='nt',environ=w.os.environ))
    target=verified_copy('usr/share/seclists')
    assert load_settings().seclists_directory is None
    assert not w.default_directory().exists()
    monkeypatch.setattr(w,'CONVENTIONAL',(target,))
    assert w.locate()['installed'] is False
    assert Path(w.install(target)['path'])==target
    assert Path(load_settings().seclists_directory)==target
    assert Path(w.locate()['path'])==target
    assert upstream[1]==[]


@pytest.mark.parametrize('platform',['posix','nt'])
@pytest.mark.parametrize('registered',[False,True],ids=['managed','registered'])
def test_copy_discovery_precedence(verified_copy,upstream,monkeypatch,platform,registered):
    monkeypatch.setattr(w,'os',SimpleNamespace(name=platform,environ=w.os.environ))
    conventional=verified_copy('usr/share/seclists')
    managed=verified_copy(w.default_directory())
    monkeypatch.setattr(w,'CONVENTIONAL',(conventional,))
    expected=managed
    if registered:
        expected=verified_copy('registered SecLists')
        settings=load_settings();settings.seclists_directory=str(expected);save_settings(settings)
    assert Path(w.locate()['path'])==expected
    assert Path(w.install()['path'])==expected
    assert Path(load_settings().seclists_directory)==expected
    assert upstream[1]==[]


@pytest.mark.parametrize('failure',['interrupted','checksum','timeout'])
def test_download_failure_clean_retry(upstream,monkeypatch,failure):
    def broken(url,limit):
        if failure=='interrupted':raise KeyboardInterrupt()
        if failure=='timeout':raise TimeoutError('interrupted transfer')
        return b'bad'
    monkeypatch.setattr(w,'download',broken)
    with pytest.raises((KeyboardInterrupt,TimeoutError,ConfigError)):w.install()
    assert not w.default_directory().exists()
    assert not list(w.default_directory().parent.glob('.seclists-*'))
    monkeypatch.setattr(w,'download',upstream[2])
    assert w.install()['installed']


def test_disk_unrelated_and_changed_source_preserved(tmp_path,upstream,monkeypatch):
    target=w.default_directory();target.mkdir(parents=True);(target/'mine').write_text('keep')
    with pytest.raises(ConfigError,match='Preserving'):w.install()
    assert (target/'mine').read_text()=='keep' and not upstream[1]
    other=tmp_path/'empty-disk'
    monkeypatch.setattr(w.shutil,'disk_usage',lambda p:SimpleNamespace(free=0))
    with pytest.raises(ConfigError,match='disk'):w.install(other)
    assert not other.exists() and not upstream[1]


def test_custom_dictionary_validation(tmp_path):
    path=tmp_path/'custom.txt';path.write_text('# comment\n/admin\nadmin\nAdmin\napi/v1\n../bad\nhttps://x.test\n//bad\nlogout?x=1\n')
    result=w.load_dictionary(path,2)
    assert result['entries']==('admin','Admin') and result['entry_limit_reached']
    assert result['rejected_entries']==4
    c=config('--wordlist',str(path),'--wordlist-budget','8')
    assert c.discovery.enabled and c.discovery.request_budget==8 and not c.discovery.god_mode
    path.write_bytes(b'\xff')
    with pytest.raises(ConfigError,match='UTF-8'):w.load_dictionary(path)
    path.write_bytes(b'x'*(w.MAX_FILE_BYTES+1))
    with pytest.raises(ConfigError,match='2 MiB'):w.load_dictionary(path)


def test_symlink_dictionary_and_install_target_refused(tmp_path,upstream):
    path=tmp_path/'real';path.write_text('admin')
    link=tmp_path/'link'
    try:link.symlink_to(path)
    except OSError:pytest.skip('OS does not permit test symlinks')
    with pytest.raises(ConfigError,match='link'):w.load_dictionary(link)
    target=tmp_path/'linked-dir';target.symlink_to(tmp_path,target_is_directory=True)
    with pytest.raises(ConfigError,match='link'):w.install(target)


def test_modified_installed_file_fails_integrity(upstream):
    installed=w.install();path=Path(installed['available']['common']['location']);path.write_text('changed')
    assert not w.verify(Path(installed['path']))['installed']
    assert not w.locate()['installed']
    with pytest.raises(ConfigError,match='Preserving'):w.install()


def test_platform_data_paths(tmp_path,monkeypatch):
    monkeypatch.delenv('RECONMAP_CONFIG_DIR')
    monkeypatch.setattr(w,'os',SimpleNamespace(name='posix',environ={'XDG_DATA_HOME':str(tmp_path/'linux-data')}))
    assert w.default_directory()==tmp_path/'linux-data/thegodrecon/wordlists/seclists'
    # Patch this module's platform selector only, leaving pathlib's host OS intact.
    monkeypatch.setattr(w,'os',SimpleNamespace(name='nt',environ={'LOCALAPPDATA':str(tmp_path/'windows-data')}))
    assert w.default_directory()==tmp_path/'windows-data/thegodrecon/wordlists/seclists'


def test_official_catalog_pinned_and_small():
    assert len(w.CATALOG['revision'])==40 and w.CATALOG['release']=='2026.1'
    assert all(len(s['sha256'])==64 for s in w.CATALOG['files'].values())
    assert sum(s['bytes'] for s in w.CATALOG['files'].values())<250000


def test_saved_310_configuration_digest_still_valid():
    from reconmap.config import ScanConfig
    fixture=json.loads((Path(__file__).parent/'fixtures/v31-config.json').read_text())
    assert 'discovery' not in fixture['config']
    assert ScanConfig.model_validate(fixture['config']).digest()==fixture['digest']


def test_optional_wordlist_decline_preserves_setup(monkeypatch,upstream):
    from reconmap import setup as setup_module
    from reconmap.adapters import ToolInfo
    monkeypatch.setattr(setup_module.sys.stdin,'isatty',lambda:True)
    monkeypatch.setattr(setup_module.sys.stdout,'isatty',lambda:True)
    monkeypatch.setattr('builtins.input',lambda prompt:'no')
    monkeypatch.setattr(setup_module,'identify',lambda name:ToolInfo(name,None,'missing',None,False,False,'','missing',False))
    monkeypatch.setattr(setup_module,'health',lambda:{'core':'available','optional_tools':'ready'})
    monkeypatch.setattr(setup_module,'print_health',lambda data:None)
    assert setup_module.setup(skip_tools=True,with_seclists=True)==0
    assert not upstream[1] and not w.default_directory().exists()


def test_bootstrap_repairs_existing_venv_without_pip(tmp_path,monkeypatch):
    import importlib.util
    spec=importlib.util.spec_from_file_location('god_bootstrap',Path(__file__).parents[1]/'tools/bootstrap.py')
    bootstrap=importlib.util.module_from_spec(spec);spec.loader.exec_module(bootstrap)
    project=tmp_path/'portable project';(project/'tools').mkdir(parents=True)
    python=bootstrap.environment_python(project/'.venv');python.parent.mkdir(parents=True);python.write_text('fixture')
    (project/'.venv/pyvenv.cfg').write_text('fixture')
    monkeypatch.setattr(bootstrap,'__file__',str(project/'tools/bootstrap.py'))
    calls=[]
    def run(argv,**kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=1 if 'importlib.util.find_spec' in argv[-1] else 0)
    monkeypatch.setattr(bootstrap.subprocess,'run',run)
    assert bootstrap.main(['--skip-tools','--with-seclists'])==0
    repair=next(i for i,c in enumerate(calls) if 'ensurepip' in c)
    packages=next(i for i,c in enumerate(calls) if '--require-hashes' in c)
    assert repair<packages
    assert '--with-seclists' in calls[-1]
