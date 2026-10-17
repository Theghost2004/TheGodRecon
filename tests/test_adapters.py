from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import time
from pathlib import Path, PureWindowsPath

import pytest

from reconmap.adapters import ProcessResult, ToolInfo, capture, command, execute, identify, parse_records
from reconmap.cli import main
from reconmap.storage import pid_alive


def tool(name):
    return ToolInfo(name,str(PureWindowsPath('C:/Tools With Spaces/工具')/(name+'.exe')),'tested','a'*64,True,True,'fixture','test')


def test_argument_arrays_no_shell_or_interpolation(tmp_path):
    info=tool('subfinder')
    argv=command(info,'example.com; touch pwned',tmp_path,20)
    assert argv[0]==info.path
    assert argv[argv.index('-d')+1]=='example.com; touch pwned'
    assert '-duc' in argv and '-json' in argv and '-s' in argv
    g=command(tool('gitleaks'),'example.com',tmp_path,15,tmp_path/'files with spaces')
    assert '--redact=100' in g and g[g.index('--exit-code')+1]=='10'


@pytest.mark.parametrize('name,text,expected',[
    ('subfinder','{"host":"a.example.com","sources":["crtsh"]}\nbad\n',1),
    ('urlfinder','{"url":"https://example.com/a","sources":["commoncrawl"]}\n{"host":"wrong"}',1),
    ('jsluice','{"url":"/api","method":"GET"}\n["not a record"]',1),
    ('gitleaks','[{"RuleID":"github-pat","StartLine":1}]',1),
])
def test_parsing_good_and_malformed(name,text,expected):
    records,errors=parse_records(name,text)
    assert len(records)==expected
    if name!='gitleaks':assert errors
    assert parse_records('gitleaks','{}')[1]


def test_missing_binary_and_strict_preflight(tmp_path):
    assert not identify('subfinder',str(tmp_path/'missing.exe')).available
    config=tmp_path/'scope.yaml'
    assert main(['init','--target','example.com','--config',str(config)])==0
    assert main(['scan','--target','example.com','--config',str(config),'--modules','subfinder','--strict-tools','--tool',f'subfinder={tmp_path / "missing.exe"}','--output-root',str(tmp_path/'out')])==4
    assert not (tmp_path/'out').exists()


def test_real_process_unicode_space_paths_and_redacted_capture(tmp_path):
    folder=tmp_path/'spaces ü';folder.mkdir()
    async def go():
        result=await execute([sys.executable,'-c','import sys;print(sys.argv[1]);sys.exit(10)','one arg with spaces'],folder,5)
        assert result.code==10 and result.stdout.strip()=='one arg with spaces'
        capture(ProcessResult(10,'token="sensitivevalue"','password="secretvalue"'),folder)
    asyncio.run(go())
    assert 'sensitivevalue' not in (folder/'stdout.txt').read_text()
    assert 'secretvalue' not in (folder/'stderr.txt').read_text()


def test_timeout_kills_process_tree(tmp_path):
    child_pid=tmp_path/'child.pid'
    script='import subprocess,sys,time,pathlib; p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(30)"]);pathlib.Path(sys.argv[1]).write_text(str(p.pid));time.sleep(30)'
    async def go():
        with pytest.raises(TimeoutError):await execute([sys.executable,'-c',script,str(child_pid)],tmp_path,0.5)
    asyncio.run(go())
    pid=int(child_pid.read_text())
    # SIGKILL closes inherited pipes before every descendant necessarily reaches
    # its final /proc state. Observe bounded termination rather than racing that
    # kernel transition when independent test suites run under CPU load.
    proc_stat=Path(f'/proc/{pid}/stat')
    deadline=time.monotonic()+2
    while True:
        try:
            stopped=proc_stat.read_text().split()[2]=='Z' if proc_stat.exists() else not pid_alive(pid)
        except FileNotFoundError:
            stopped=True
        if stopped:break
        assert time.monotonic()<deadline, 'Timed-out tool descendant remains alive'
        time.sleep(.01)


def test_cancel_subprocess(tmp_path):
    async def go():
        task=asyncio.create_task(execute([sys.executable,'-c','import time;time.sleep(30)'],tmp_path,60))
        await asyncio.sleep(0.1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):await task
    asyncio.run(go())


def test_output_cap(tmp_path):
    async def go():
        with pytest.raises(ValueError,match='cap'):await execute([sys.executable,'-c','print("x"*100000)'],tmp_path,5,limit=1024)
    asyncio.run(go())


def test_real_gitleaks_offline_when_installed(tmp_path):
    path=os.environ.get('RECONMAP_TEST_GITLEAKS')
    if not path:pytest.skip('Set RECONMAP_TEST_GITLEAKS to a verified 8.30.1 binary for real integration')
    info=identify('gitleaks',path);assert info.supported
    inputs=tmp_path/'inputs';inputs.mkdir()
    synthetic='ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'
    (inputs/'synthetic.js').write_text('const token="'+synthetic+'"; // SYNTHETIC FIXTURE')
    async def go():
        result=await execute(command(info,'example.com',tmp_path,10,inputs),tmp_path,10)
        assert result.code==10
        records,errors=parse_records('gitleaks',(tmp_path/'findings.json').read_text())
        assert records and not errors
        assert all(synthetic not in json.dumps(r) for r in records)
    asyncio.run(go())


def test_real_jsluice_offline_when_installed(tmp_path):
    path=os.environ.get('RECONMAP_TEST_JSLUICE')
    if not path:pytest.skip('Set RECONMAP_TEST_JSLUICE to the reviewed local binary')
    info=identify('jsluice',path);assert info.supported
    inputs=tmp_path/'fixture with spaces.js';inputs.write_text('fetch("/api/account");')
    async def go():
        result=await execute(command(info,'example.com',tmp_path,10,inputs),tmp_path,10)
        records,errors=parse_records('jsluice',result.stdout)
        assert result.code==0 and not errors and any(r['url']=='/api/account' for r in records)
    asyncio.run(go())
