#!/usr/bin/env bash
set -eu
cd /workspace/TheGodRecon
UV_CACHE_DIR=/workspace/.cache/uv uv sync --frozen --extra test
.venv/bin/python tools/install_tools.py --tool gitleaks --tool subfinder --tool urlfinder --directory /workspace/tooling/bin
RECONMAP_TEST_GITLEAKS=/workspace/tooling/bin/gitleaks .venv/bin/python -m pytest -q
.venv/bin/reconmap doctor --tool gitleaks=/workspace/tooling/bin/gitleaks --tool subfinder=/workspace/tooling/bin/subfinder --tool urlfinder=/workspace/tooling/bin/urlfinder
