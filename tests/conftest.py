"""Keep user preferences and tool registrations out of regression fixtures."""
import pytest


@pytest.fixture(autouse=True)
def isolated_preferences(tmp_path, monkeypatch):
    monkeypatch.setenv('RECONMAP_CONFIG_DIR', str(tmp_path / 'user preferences'))
