"""Friendly bounded budgets; explicit YAML and legacy profiles remain authoritative."""
from .config import ConfigError, ScanConfig

PRESETS = {
    'quick': {'requests': 100, 'urls_per_host': 50, 'depth': 1, 'minutes': 5},
    'standard': {},
    'deep': {'requests': 10000, 'urls_per_host': 1500, 'depth': 4, 'minutes': 60},
}


def apply_preset(config: ScanConfig, preset: str) -> ScanConfig:
    if preset not in PRESETS:
        raise ConfigError('Unknown preset; choose quick, standard or deep')
    data = config.model_dump()
    data['budgets'].update(PRESETS[preset])
    if preset == 'quick':
        data['modules'] = ['http', 'crawl', 'analysis']
    elif preset == 'deep':
        data['modules'] = ['dns', 'http', 'crawl', 'analysis', 'checks', 'jsluice', 'gitleaks']
        data['enrichments'] = ['tech', 'dedup', 'priority']
    return ScanConfig.model_validate(data)
