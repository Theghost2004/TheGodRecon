import json
from pathlib import Path

import pytest
import yaml

from reconmap.cli import main, parser, effective_config
from reconmap.config import default_config
from reconmap.settings import load_settings, save_settings
from reconmap.tool_registry import BY_NAME


def config(*args):
    return effective_config(parser().parse_args(['scan', *args]))


def test_version_and_noninteractive_menu(capsys, monkeypatch):
    with pytest.raises(SystemExit) as result:
        main(['--version'])
    assert result.value.code == 0
    assert capsys.readouterr().out.strip() == '3.1.0'
    monkeypatch.setattr('builtins.input', lambda *a: pytest.fail('noninteractive prompt'))
    assert main([]) == 0
    assert 'scan' in capsys.readouterr().out


@pytest.mark.parametrize('arguments', [['example.com'], ['--target', 'example.com']])
def test_simple_target_exact_scope(arguments):
    c = config(*arguments)
    assert c.scope.hosts == ['example.com'] and c.scope.ports == [443]
    assert c.scope.lab is False and c.enrichments == []
    assert c.budgets.requests == 5000 and c.budgets.minutes == 30


def test_alias_equivalence():
    expected = config('example.com', '--tools', 'all').model_dump()
    for alias in ['--all-tool', '--all-tools']:
        assert config('example.com', alias).model_dump() == expected
    assert set(expected['selected_tools']) == set(BY_NAME)
    assert expected['enrichments'] == []


@pytest.mark.parametrize('args', [
    ['--target', 'other.example'], ['--all-tool', '--tools', 'all'], ['--all-tool', '--modules', 'http'],
    ['--all-tool', '--profile', 'full'], ['--quick', '--deep'], ['--quick', '--profile', 'full'],
])
def test_conflicts_fail_before_allocation(tmp_path, args, capsys):
    root = tmp_path/'must not exist'
    assert main(['scan', 'example.com', '--output-root', str(root), *args]) == 3
    assert not root.exists()
    assert 'error' in capsys.readouterr().err.lower()


@pytest.mark.parametrize('preset,requests,depth', [('quick',100,1), ('standard',5000,2), ('deep',10000,4)])
def test_presets_are_bounded_and_explicit_overrides_win(preset, requests, depth):
    c = config('example.com', '--'+preset)
    assert c.budgets.requests == requests and c.budgets.depth == depth
    assert not {'asn','wayback'} & set(c.enrichments)
    assert not {'subfinder','urlfinder'} & set(c.modules)
    assert config('example.com','--'+preset,'--max-requests','7').budgets.requests == 7
    assert config('example.com','--preset',preset).digest() == c.digest()


def test_yaml_unchanged_by_saved_preset(tmp_path):
    settings = load_settings(); settings.preset = 'deep'; save_settings(settings)
    c = default_config('example.com'); c.budgets.requests = 42
    path = tmp_path/'scope.yaml'; path.write_text(yaml.safe_dump(c.model_dump()))
    assert config('example.com', '--config', str(path)).digest() == c.digest()
    assert main(['scan','example.com','--config',str(path),'--quick']) == 3


def test_saved_defaults_cli_override_and_effective_config(tmp_path, monkeypatch):
    settings = load_settings(); settings.preset='quick'; settings.output_root=str(tmp_path/'saved root'); save_settings(settings)
    monkeypatch.setattr('builtins.input', lambda *a: pytest.fail('noninteractive prompt'))
    root = tmp_path/'overridden root ü'
    assert main(['scan','example.com','--mode','demo','--output-root',str(root),'--no-progress']) == 2
    run = root/'example.com'
    saved = json.loads((run/'config.effective.json').read_text())
    assert saved['budgets']['requests'] == 100
    assert saved['scope']['hosts'] == ['example.com']
    assert load_settings().last_run == str(run.resolve())
    before = json.loads((run/'manifest.json').read_text())['requests']
    assert main(['resume',str(run),'--no-progress']) == 2
    assert json.loads((run/'manifest.json').read_text())['limits'] == ['crawl depth cap reached']
    assert json.loads((run/'manifest.json').read_text())['requests'] == before
    assert not (tmp_path/'saved root').exists()


def test_offline_all_tools_reports_policy_blocks_and_no_false_success(tmp_path, capsys):
    root = tmp_path/'runs'
    overrides = [item for name in BY_NAME for item in ['--tool', f'{name}={tmp_path/name}']]
    assert main(['scan','example.com','--all-tool','--mode','demo','--no-progress','--output-root',str(root),*overrides]) == 2
    output = capsys.readouterr().out
    assert '\x1b' not in output and 'Native fallback' in output and 'blocked-by-policy' in output
    report = json.loads((root/'example.com/reports/investigation.json').read_text())['summary']
    assert len(report['selected_tools']) == 8 and report['executed_tools'] == []
    assert report['target_requests'] > 0


def test_settings_boolean_validation_and_persistence():
    assert main(['settings','--set','auto_open','true']) == 0
    assert load_settings().auto_open is True
    assert main(['settings','--set','auto_open','yesplease']) == 3
    assert main(['settings','--set','preset','quick']) == 0
    assert config('example.com').budgets.requests == 100
    assert main(['settings','--set','api_key','anything']) == 3


def test_simple_scan_rejects_loopback_without_lab_before_requests(tmp_path):
    assert main(['scan','127.0.0.1','--output-root',str(tmp_path/'runs')]) == 3
    assert not (tmp_path/'runs').exists()
