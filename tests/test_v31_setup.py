import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile

import pytest

from reconmap import adapters, installer, jsbuild, settings
from reconmap.cli import main
from reconmap.setup import setup
from reconmap.tool_registry import BY_NAME


def fake_info(name, path=None, compatible=False):
    return adapters.ToolInfo(name, str(path) if path else None, BY_NAME[name].version, 'a'*64 if path else None, bool(path), compatible and not BY_NAME[name].policy_reason, BY_NAME[name].capability, BY_NAME[name].policy_reason or 'fixture', compatible)


def test_discovery_precedence_and_registration_not_trust(tmp_path, monkeypatch):
    managed = Path(settings.load_settings().tool_directory); managed.mkdir(parents=True)
    binary = managed/('jsluice.exe' if os.name=='nt' else 'jsluice'); binary.write_bytes(b'unreviewed')
    assert settings.discover('jsluice') == str(binary)
    custom = tmp_path/'custom path ü.exe'; custom.write_bytes(b'unreviewed custom')
    settings.register_tool('jsluice', custom)
    monkeypatch.chdir(tmp_path)
    assert settings.discover('jsluice') == str(custom.resolve())
    assert settings.discover('jsluice', '/explicit') == '/explicit'
    assert not jsbuild.trusted_build(custom, hashlib.sha256(custom.read_bytes()).hexdigest())


def test_untrusted_jsluice_never_runs_even_help(tmp_path, monkeypatch):
    binary = tmp_path/'jsluice'; binary.write_bytes(b'untrusted'); binary.chmod(0o700)
    monkeypatch.setattr(adapters.shutil,'which',lambda _:str(binary))
    async def forbidden(*a, **kw): pytest.fail('untrusted executable ran')
    monkeypatch.setattr(adapters,'execute',forbidden)
    info = adapters.identify('jsluice')
    assert info.available and not info.compatible and 'Tree-sitter' in info.reason


def test_build_trust_is_bound_to_path_source_and_hash(tmp_path):
    binary = tmp_path/'jsluice'; binary.write_bytes(b'built')
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    config = settings.config_directory(); config.mkdir()
    record = {'recipe':1,'revision':jsbuild.REVISION,'source_sha256':jsbuild.SOURCE_SHA256,'path':str(binary.resolve()),'binary_sha256':digest,'fixture_verified':True}
    (config/'jsluice-build.json').write_text(json.dumps(record))
    assert jsbuild.trusted_build(binary,digest)
    assert not jsbuild.trusted_build(binary,'b'*64)
    assert not jsbuild.trusted_build(tmp_path/'other',digest)
    record['source_sha256']='0'*64
    (config/'jsluice-build.json').write_text(json.dumps(record))
    assert not jsbuild.trusted_build(binary,digest)


def test_registered_damaged_binary_preserved_during_repair(tmp_path,monkeypatch):
    from reconmap import setup as module
    binary=tmp_path/'custom.exe';binary.write_bytes(b'keep')
    settings.register_tool('gitleaks',binary)
    monkeypatch.setattr(module,'identify',lambda n,*a:fake_info(n,binary,n!='gitleaks'))
    monkeypatch.setattr(installer,'install',lambda *a:pytest.fail('should preserve custom'))
    monkeypatch.setattr(module,'health',lambda:{'core':'available','optional_tools':'partial'})
    monkeypatch.setattr(module,'print_health',lambda _:None)
    assert setup(yes=True)==2
    assert binary.read_bytes()==b'keep'


def test_setup_reuses_all_compatible_without_download(tmp_path,monkeypatch):
    from reconmap import setup as module
    for name in BY_NAME: (tmp_path/name).write_bytes(b'fixture')
    monkeypatch.setattr(module,'identify',lambda n,*a:fake_info(n,tmp_path/n,True))
    monkeypatch.setattr(installer,'install',lambda *a:pytest.fail('redownload'))
    monkeypatch.setattr(module,'health',lambda:{'core':'available','optional_tools':'ready'})
    monkeypatch.setattr(module,'print_health',lambda _:None)
    assert setup(yes=True)==0
    assert setup(yes=True)==0
    assert set(settings.load_settings().registered_tools)==set(BY_NAME)


def test_setup_missing_network_failure_continues_independent_tools(tmp_path,monkeypatch,capsys):
    from reconmap import setup as module
    installed=set(); attempts=[]
    def identity(n,*a): return fake_info(n,tmp_path/n,n in installed)
    def install(n,d):
        attempts.append(n)
        if n=='subfinder':raise OSError('fixture offline')
        (tmp_path/n).write_bytes(b'verified'); installed.add(n)
        return {'path':str(tmp_path/n)}
    monkeypatch.setattr(module,'identify',identity)
    monkeypatch.setattr(installer,'install',install)
    monkeypatch.setattr(jsbuild,'build',lambda *a:(_ for _ in ()).throw(ValueError('compiler missing')))
    monkeypatch.setattr(module,'health',lambda:{'core':'available','optional_tools':'partial'})
    monkeypatch.setattr(module,'print_health',lambda _:None)
    assert setup(yes=True)==2
    assert len(attempts)==7 and 'gitleaks' in installed
    assert 'compiler missing' in capsys.readouterr().out


def test_noninteractive_repair_requires_explicit_consent(monkeypatch):
    monkeypatch.setattr('builtins.input',lambda *a:pytest.fail('prompt'))
    assert main(['doctor','--fix'])==3
    assert main(['doctor','--fix','--json','--yes'])==3


def test_idempotent_install_checks_receipt_without_network(tmp_path,monkeypatch):
    name='gitleaks'; binary=tmp_path/('gitleaks.exe' if os.name=='nt' else 'gitleaks'); binary.write_bytes(b'verified')
    receipt={'name':name,'version':BY_NAME[name].version,'platform':installer.platform.system().lower(),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}
    (tmp_path/'gitleaks.receipt.json').write_text(json.dumps(receipt))
    monkeypatch.setattr(installer,'download',lambda *a:pytest.fail('downloaded reused binary'))
    assert installer.install(name,tmp_path)==receipt


@pytest.mark.parametrize('architecture',['arm64','riscv64','mips'])
def test_unsupported_architecture_no_download(monkeypatch,tmp_path,architecture):
    monkeypatch.setattr(installer.platform,'machine',lambda:architecture)
    monkeypatch.setattr(installer,'download',lambda *a:pytest.fail('download'))
    with pytest.raises(ValueError,match='x86-64'):installer.install('gitleaks',tmp_path)


def test_atomic_install_interruption_leaves_no_partial_binary(tmp_path,monkeypatch):
    monkeypatch.setattr(installer.os,'link',lambda *a:(_ for _ in ()).throw(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):installer.atomic_install(tmp_path/'tool',b'complete',executable=True)
    assert list(tmp_path.iterdir())==[]


def test_js_source_checksum_rejected_before_extraction(tmp_path):
    with pytest.raises(ValueError,match='checksum'):jsbuild.extract_source(b'wrong',tmp_path)
    assert list(tmp_path.iterdir())==[]


def test_js_source_traversal_rejected(tmp_path,monkeypatch):
    out=io.BytesIO()
    with tarfile.open(fileobj=out,mode='w:gz') as tar:
        entry=tarfile.TarInfo('../escape');entry.size=4;tar.addfile(entry,io.BytesIO(b'bad!'))
    data=out.getvalue();monkeypatch.setattr(jsbuild,'SOURCE_SHA256',hashlib.sha256(data).hexdigest())
    with pytest.raises(ValueError,match='Unsafe'):jsbuild.extract_source(data,tmp_path)


def test_js_missing_compiler_does_not_download(monkeypatch,tmp_path):
    monkeypatch.setattr(jsbuild.shutil,'which',lambda _:None)
    monkeypatch.setattr(jsbuild,'download',lambda *a:pytest.fail('download'))
    with pytest.raises(ValueError,match='compiler'):jsbuild.build(tmp_path)


def test_platform_config_locations(monkeypatch,tmp_path):
    monkeypatch.delenv('RECONMAP_CONFIG_DIR')
    monkeypatch.setenv('XDG_CONFIG_HOME',str(tmp_path/'xdg ü'))
    monkeypatch.setenv('APPDATA',str(tmp_path/'Roaming'))
    expected=tmp_path/('Roaming' if os.name=='nt' else 'xdg ü')/'thegodrecon'
    assert settings.config_directory()==expected


def test_bootstrap_platform_paths_and_existing_environment(tmp_path,monkeypatch):
    spec=importlib.util.spec_from_file_location('bootstrap',Path(__file__).parents[1]/'tools/bootstrap.py')
    bootstrap=importlib.util.module_from_spec(spec);spec.loader.exec_module(bootstrap)
    assert str(bootstrap.environment_python(Path('C:/User Space'),True)).replace('\\','/')=='C:/User Space/Scripts/python.exe'
    assert bootstrap.environment_python(tmp_path,False)==tmp_path/'bin/python'
    project=tmp_path/'portable ü';(project/'tools').mkdir(parents=True)
    monkeypatch.setattr(bootstrap,'__file__',str(project/'tools/bootstrap.py'))
    calls=[]
    def create(path):
        python=bootstrap.environment_python(path);python.parent.mkdir(parents=True);python.write_text('fixture');(path/'pyvenv.cfg').write_text('home=fixture')
    monkeypatch.setattr(bootstrap.venv.EnvBuilder,'create',lambda self,path:create(path))
    def run(argv,**kw):
        calls.append(argv)
        return type('Result',(),{'returncode':0})()
    monkeypatch.setattr(bootstrap.subprocess,'run',run)
    assert bootstrap.main(['--skip-tools'])==0
    assert any('--require-hashes' in command for command in calls)
    assert '--skip-tools' in calls[-1] and '--yes' in calls[-1]
    monkeypatch.setattr(bootstrap.venv.EnvBuilder,'create',lambda *a:pytest.fail('recreated venv'))
    assert bootstrap.main(['--skip-tools'])==0


def test_corrupt_archive_is_reported_and_setup_continues(tmp_path,monkeypatch,capsys):
    import zipfile
    from reconmap import setup as module
    attempted=[]
    monkeypatch.setattr(module,'identify',lambda n,*a:fake_info(n))
    def install(n,*a):
        attempted.append(n)
        raise zipfile.BadZipFile('fixture corrupt archive')
    monkeypatch.setattr(installer,'install',install)
    monkeypatch.setattr(jsbuild,'build',lambda *a:(_ for _ in ()).throw(tarfile.ReadError('fixture corrupt source')))
    monkeypatch.setattr(module,'health',lambda:{'core':'available','optional_tools':'partial'})
    monkeypatch.setattr(module,'print_health',lambda _:None)
    assert setup(yes=True)==2
    assert len(attempted)==7 and 'nuclei' in attempted
    assert 'corrupt archive' in capsys.readouterr().out


def test_wrong_go_program_is_rejected_before_source_download(tmp_path,monkeypatch):
    monkeypatch.setattr(jsbuild.shutil,'which',lambda name:'/tools/'+name)
    async def fake_execute(*args,**kwargs):
        return adapters.ProcessResult(0,'Go: not the Go compiler','')
    monkeypatch.setattr(adapters,'execute',fake_execute)
    monkeypatch.setattr(jsbuild,'download',lambda *a:pytest.fail('download before compiler validation'))
    with pytest.raises(ValueError,match='toolchain'):jsbuild.build(tmp_path/'bin')


def test_unregister_repairs_discovery_without_deleting_custom_binary(tmp_path):
    custom=tmp_path/'keep executable.exe';custom.write_bytes(b'preserve custom')
    settings.register_tool('jsluice',custom)
    assert settings.discover('jsluice')==str(custom.resolve())
    assert main(['tools','unregister','jsluice'])==0
    assert settings.discover('jsluice')=='jsluice'
    assert custom.read_bytes()==b'preserve custom'
