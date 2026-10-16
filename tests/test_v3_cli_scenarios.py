"""Offline CLI scenarios: selection, collisions, ceilings and invalid input."""
import json

import pytest
import yaml

from reconmap.cli import main
from reconmap.config import default_config
from reconmap.storage import Store
from reconmap.tool_registry import REGISTRY


@pytest.mark.parametrize('number', range(1, 9))
def test_every_numbered_tool_has_an_honest_offline_result(tmp_path, number):
    root = tmp_path / 'results with spaces and ünicode'
    tool = REGISTRY[number - 1]
    code = main(['demo', '--tools', str(number), '--tool', f'{tool.name}={tmp_path / "missing executable"}', '--output-root', str(root)])
    assert code == (2 if tool.risk == 'active' else 0)
    run = root / 'example.com'
    report = json.loads((run / 'reports/investigation.json').read_text())
    assert report['summary']['selected_tools'] == [tool.name]
    assert report['summary']['executed_tools'] == []
    if tool.name not in {'httpx', 'katana', 'nuclei'}:
        assert report['summary']['target_requests'] == 0
    if tool.risk == 'offline':
        assert any(s['status'] == 'skipped' and 'No suitable local artifacts' in s['reason'] for s in report['summary']['partial_coverage'])
    assert not (run / 'run.lock').exists()
    assert (run / 'reports/index.html').is_file()


@pytest.mark.parametrize('flag,value', [
    ('--max-requests', '1'), ('--max-urls', '1'), ('--depth', '0'),
    ('--max-minutes', '0.000000001'), ('--max-artifact-bytes', '1024'),
])
def test_tight_cli_limits_produce_reports_and_resume_never_resets_caps(tmp_path, flag, value):
    config = default_config('example.com')
    config.mode = 'demo'
    scope = tmp_path / 'scope.yaml'
    scope.write_text(yaml.safe_dump(config.model_dump()), encoding='utf-8')
    root = tmp_path / 'runs'
    code = main(['scan', '--target', 'example.com', '--config', str(scope), '--output-root', str(root), flag, value])
    assert code in {0, 2}
    run = root / 'example.com'
    before = json.loads((run / 'manifest.json').read_text())
    store = Store(run, readonly=True)
    try:
        completed = {r['url'] for r in store.rows('jobs') if r['state'] == 'completed'}
        requests = store.meta('requests', 0)
    finally:
        store.close()
    assert main(['scan', '--resume', str(run)]) == code
    after = json.loads((run / 'manifest.json').read_text())
    assert after['requests'] == before['requests'] == requests
    if flag == '--max-requests':
        assert requests == 1 and code == 2
    if flag == '--max-minutes':
        assert requests == 0 and code == 2
    store = Store(run, readonly=True)
    try:
        assert completed == {r['url'] for r in store.rows('jobs') if r['state'] == 'completed'}
        if flag == '--depth':
            assert completed  # Prove this preservation check exercised finished jobs.
    finally:
        store.close()
    assert (run / 'reports/stage-results.json').is_file()
    assert not (run / 'run.lock').exists()


@pytest.mark.parametrize('arguments', [
    ['--max-requests', '0'], ['--depth', '-1'], ['--timeout', 'nan'],
    ['--max-minutes', 'inf'], ['--tools', '0'], ['--tools', '8-1'],
    ['--tools', '6', '--modules', 'analysis'], ['--profile', 'full', '--tools', '6'],
    ['--tool', 'unknown=/missing'],
])
def test_invalid_cli_inputs_fail_before_output_allocation(tmp_path, arguments, capsys):
    scope = tmp_path / 'scope.yaml'
    config = default_config('example.com')
    config.mode = 'demo'
    scope.write_text(yaml.safe_dump(config.model_dump()), encoding='utf-8')
    root = tmp_path / 'never allocated'
    assert main(['scan', '--target', 'example.com', '--config', str(scope), '--output-root', str(root), *arguments]) == 3
    assert not root.exists()
    assert 'Traceback' not in capsys.readouterr().err
