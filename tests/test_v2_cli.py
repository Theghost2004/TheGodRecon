import json

import pytest

from reconmap.adapters import ToolInfo, command
from reconmap.cli import effective_config, main, parser
from reconmap.config import ConfigError, default_config
from reconmap.orchestrator import build_plan, stage_order, Stage
from reconmap.selectors import resolve_selection, select_enrichments, select_tools
from reconmap.tool_registry import REGISTRY


@pytest.mark.parametrize('expression,names', [
    ('1', ['subfinder']), ('1,3,5,7', ['subfinder', 'dnsx', 'katana', 'gitleaks']),
    ('1-4', ['subfinder', 'urlfinder', 'dnsx', 'httpx']),
    ('quad', ['subfinder', 'urlfinder', 'dnsx', 'httpx']),
    ('passive', ['subfinder', 'urlfinder']), ('offline', ['jsluice', 'gitleaks']),
    ('web', ['httpx', 'katana']), ('all', [t.name for t in REGISTRY]),
    ('2,1,2,subfinder', ['subfinder', 'urlfinder']), ('1+2+3', ['subfinder', 'urlfinder', 'dnsx']),
])
def test_selectors(expression, names):
    assert select_tools(expression) == names


@pytest.mark.parametrize('expression', ['', '0', '9', '1,', '3-1', '1--3', '-1', '1-99', '1.5', '1;touch x'])
def test_invalid_selectors(expression):
    with pytest.raises(ConfigError):
        select_tools(expression)


def test_profiles_and_explicit_selection_do_not_enable_unselected_tools(tmp_path):
    config = default_config('example.com')
    selected = resolve_selection(config, tools='1')
    assert selected.modules == ['subfinder']
    selected = resolve_selection(config, tools='6')
    assert selected.modules == ['jsluice', 'analysis'] and 'http' not in selected.modules
    assert resolve_selection(config, tools='all', enrich='all').modules == resolve_selection(config, profile='full').modules
    assert resolve_selection(config, modules='dnsx,httpx').modules == ['dnsx','httpx','dns','http']
    config.profile = 'full'
    selected = resolve_selection(config, tools='7', enrich='none')
    assert selected.profile is None and selected.modules == ['gitleaks', 'analysis'] and selected.enrichments == []
    with pytest.raises(ConfigError): resolve_selection(config, tools='1', modules='http')
    with pytest.raises(ConfigError): resolve_selection(config, profile='offline', mode='standard')
    with pytest.raises(ConfigError): resolve_selection(default_config('example.com'), mode='offline', tools='1')
    with pytest.raises(ConfigError): resolve_selection(default_config('example.com'), profile='offline', enrich='wayback')


def test_yaml_selection_and_path_override_compatibility(tmp_path):
    path = tmp_path / 'scope.yaml'
    path.write_text('scope: {hosts: [example.com]}\nselected_tools: [6, 7]\nenrichments: [tech, priority]\n')
    args = parser().parse_args(['scan', '--target', 'example.com', '--config', str(path), '--tool', 'gitleaks=C:/Tools With Spaces/gitleaks.exe'])
    config = effective_config(args)
    assert config.modules == ['jsluice', 'gitleaks', 'analysis']
    assert config.tools['gitleaks'] == 'C:/Tools With Spaces/gitleaks.exe'
    path.write_text('scope: {hosts: [example.com]}\nprofile: offline\nenrichments: [tech, priority]\n')
    config = effective_config(parser().parse_args(['scan','--target','example.com','--config',str(path)]))
    assert config.mode == 'offline' and config.enrichments == ['tech','priority']
    path.write_text('scope: {hosts: [example.com]}\nprofile: full\nmodules: [http]\n')
    assert main(['plan', '--target', 'example.com', '--config', str(path)]) == 3


def test_plan_is_read_only_and_does_not_request_targets(tmp_path, monkeypatch, capsys):
    path = tmp_path / 'scope.yaml'; path.write_text('scope: {hosts: [example.com]}')
    def identify(name, override=None):
        return ToolInfo(name, None, 'unavailable', None, False, False, 'fixture', 'missing')
    monkeypatch.setattr('reconmap.commands_v2.identify', identify)
    async def forbidden(*args, **kwargs): raise AssertionError('network attempt')
    monkeypatch.setattr('aiohttp.ClientSession._request', forbidden)
    assert main(['plan', '--target', 'example.com', '--config', str(path), '--tools', 'all', '--json']) == 0
    plan = json.loads(capsys.readouterr().out)
    assert [t['id'] for t in plan['selected_tools']] == list(range(1, 9))
    assert len([t for t in plan['selected_tools'] if t['status'] == 'blocked-by-policy']) == 4
    assert not (tmp_path / 'recon-output').exists()
    assert main(['plan', '--target', 'example.com', '--config', str(path), '--tools', 'all', '--strict-tools']) == 4


@pytest.mark.parametrize('name', ['dnsx', 'httpx', 'katana', 'nuclei'])
def test_active_command_is_blocked_even_if_info_claims_support(tmp_path, name):
    info = ToolInfo(name, '/malicious-binary', 'compatible', 'a'*64, True, True, 'fixture', 'fixture')
    with pytest.raises(ValueError, match='blocked-by-policy'):
        command(info, 'example.com', tmp_path, 10)


def test_stage_dependencies_detect_cycle():
    with pytest.raises(ConfigError): stage_order([Stage('a', ('b',), 'local'), Stage('b', ('a',), 'local')])
    assert [s.name for s in stage_order()][0] == 'discovery'


def test_resume_with_original_profile_yaml_keeps_effective_digest(tmp_path):
    from reconmap.engine import prepare_run
    yaml=tmp_path/'scope.yaml'
    yaml.write_text('scope: {hosts: [example.com]}\nprofile: standard\nenrichments: [tech, dedup]\n')
    args=parser().parse_args(['scan','--target','example.com','--config',str(yaml)])
    config=effective_config(args)
    run,_=prepare_run(config,'example.com',tmp_path/'runs')
    resumed=effective_config(parser().parse_args(['scan','--resume',str(run),'--config',str(yaml)]))
    assert resumed.digest()==config.digest()
