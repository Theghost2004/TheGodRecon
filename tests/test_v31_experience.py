import asyncio
import io
import json
import sqlite3
from pathlib import Path

import pytest

from reconmap.cli import main
from reconmap.config import default_config
from reconmap.demo import fixtures
from reconmap.engine import Scanner, prepare_run
from reconmap.progress import Dashboard, snapshot
from reconmap import report_access
from reconmap.settings import load_settings, save_settings


class TTY(io.StringIO):
    def isatty(self): return True


def scanner(tmp_path):
    c=default_config('example.com');c.mode='demo';c.budgets.requests=1
    path, manifest=prepare_run(c,'example.com',tmp_path)
    return Scanner(path,manifest,c,{},fixtures())


def test_real_progress_counters_and_phase_completion(tmp_path):
    scan=scanner(tmp_path)
    stream=io.StringIO()
    with Dashboard(enabled=False,stream=stream) as view:
        assert asyncio.run(view.run(scan))=='partial'
    text=stream.getvalue()
    assert 'Fixture operations: 1/1' in text and 'partial' in text
    assert '\x1b' not in text and '%' not in text
    assert '100% complete' not in text
    assert json.loads((scan.run/'manifest.json').read_text())['requests']==1


def test_terminal_cursor_restored_on_interrupt(monkeypatch,tmp_path):
    import reconmap.progress as progress
    monkeypatch.setattr(progress,'ansi_terminal',lambda _:True)
    stream=TTY(); scan=scanner(tmp_path)
    try:
        with pytest.raises(KeyboardInterrupt):
            with Dashboard(stream=stream) as view:
                view.update(scan,force=True)
                raise KeyboardInterrupt()
    finally:scan.store.close()
    assert stream.getvalue().startswith('\x1b[?25l')
    assert stream.getvalue().endswith('\x1b[?25h\x1b[0m')


def test_plain_progress_status_reports_actual_engine(tmp_path):
    from reconmap.adapters import ToolInfo
    from reconmap.orchestrator import record_execution
    scan=scanner(tmp_path)
    scan.tools['jsluice']=ToolInfo('jsluice',None,'unavailable',None,False,False,'local JS','missing')
    scan.config.modules.append('jsluice')
    record_execution(scan,'jsluice',state='unavailable',reason='missing',limitations=['native coverage only'])
    record_execution(scan,'jsluice',engine='native-tree-sitter',state='running',fallback=True)
    data=snapshot(scan)
    assert data['tools'][0]['primary']=='unavailable'
    assert data['tools'][0]['fallback'] and data['tools'][0]['status']=='running'
    stream=io.StringIO();Dashboard(enabled=False,stream=stream).update(scan,force=True)
    assert 'native-tree-sitter' in stream.getvalue() and 'Native fallback' in stream.getvalue()
    assert 'primary=completed' not in stream.getvalue()
    scan.store.close()


def test_cancelled_run_keeps_checkpoint_and_restores_terminal(tmp_path,monkeypatch):
    import reconmap.orchestrator as orchestrator
    scan=scanner(tmp_path)
    async def interrupt(scanner): raise asyncio.CancelledError()
    monkeypatch.setattr(orchestrator,'run_pipeline',interrupt)
    stream=io.StringIO()
    with Dashboard(enabled=False,stream=stream) as view:
        assert asyncio.run(view.run(scan))=='interrupted'
    assert json.loads((scan.run/'checkpoints/state.json').read_text())['state']=='interrupted'
    assert (scan.run/'reports/index.html').is_file()
    assert 'interrupted' in stream.getvalue()


def test_latest_report_known_roots_integrity_and_no_rewrites(tmp_path,monkeypatch):
    root=tmp_path/'results'
    assert main(['demo','--output-root',str(root)])==0
    first=root/'example.com'
    assert main(['demo','--output-root',str(root)])==0
    latest=root/'1_example.com'
    settings=load_settings();settings.output_root=str(root);save_settings(settings)
    before={p:p.read_bytes() for p in latest.rglob('*') if p.is_file()}
    monkeypatch.chdir(tmp_path)
    assert report_access.latest_report()==(latest/'reports/index.html').resolve()
    monkeypatch.setattr(report_access,'open_report',lambda path:path.is_file())
    assert main(['report'])==0
    assert before=={p:p.read_bytes() for p in latest.rglob('*') if p.is_file()}
    (latest/'reports/index.html').unlink()
    assert report_access.latest_report()==(first/'reports/index.html').resolve()
    # Explicit --run retains regeneration, repairing a missing report.
    assert main(['report','--run',str(latest)])==0
    assert (latest/'reports/index.html').is_file()


def test_report_database_mismatch_rejected(tmp_path):
    assert main(['demo','--output-root',str(tmp_path)])==0
    run=tmp_path/'example.com'
    with sqlite3.connect(run/'recon.sqlite') as conn:conn.execute('DELETE FROM runs')
    with pytest.raises(ValueError,match='database'):report_access.valid_report(run)


def test_headless_and_browser_failures_are_nonfatal(tmp_path,monkeypatch,capsys):
    path=tmp_path/'report space ü.html';path.write_text('fixture')
    monkeypatch.delenv('DISPLAY',raising=False);monkeypatch.delenv('WAYLAND_DISPLAY',raising=False)
    calls=[]
    monkeypatch.setattr(report_access.webbrowser,'open',lambda url:calls.append(url) or False)
    assert report_access.open_report(path) is False
    if report_access.os.name!='nt': assert calls==[]
    monkeypatch.setenv('DISPLAY',':fixture')
    def fail(url):
        assert url==path.resolve().as_uri()
        raise OSError('no browser')
    monkeypatch.setattr(report_access.webbrowser,'open',fail)
    assert report_access.open_report(path) is False
    assert 'Browser could not be opened' in capsys.readouterr().out


def test_auto_open_preference_browser_failure_does_not_fail_scan(tmp_path,monkeypatch):
    settings=load_settings();settings.auto_open=True;save_settings(settings)
    monkeypatch.setenv('DISPLAY',':fixture')
    monkeypatch.setattr(report_access.webbrowser,'open',lambda *_:False)
    assert main(['demo','--output-root',str(tmp_path)])==0


def test_report_missing_returns_useful_error(tmp_path,monkeypatch,capsys):
    monkeypatch.chdir(tmp_path)
    assert main(['report'])==3
    assert 'No valid reports' in capsys.readouterr().err


def test_menu_exit_and_invalid_selection(monkeypatch,capsys):
    from reconmap.menu import menu
    answers=iter(['invalid','0'])
    monkeypatch.setattr('builtins.input',lambda *_:next(answers))
    assert menu()==0
    assert 'Choose an option' in capsys.readouterr().out


def test_menu_reviews_scope_and_requires_start_consent(monkeypatch,tmp_path,capsys):
    from reconmap.menu import menu
    settings=load_settings();settings.output_root=str(tmp_path/'never');save_settings(settings)
    answers=iter(['1','example.com','n','0'])
    monkeypatch.setattr('builtins.input',lambda *_:next(answers))
    assert menu()==0
    text=capsys.readouterr().out
    assert 'Scope:' in text and 'Budgets:' in text and '100' in text
    assert not (tmp_path/'never').exists()


def test_active_run_is_not_opened_as_latest(tmp_path):
    assert main(['demo','--output-root',str(tmp_path)])==0
    run=tmp_path/'example.com'
    (run/'run.lock').write_text('{}')
    with pytest.raises(ValueError,match='active'):report_access.valid_report(run)
