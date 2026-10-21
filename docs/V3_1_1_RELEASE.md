# TheGodRecon V3.1.1 — Linux-First Eight-Tool Execution Engine

V3.1.1 extends the existing BlackBox/scan orchestrator. Linux x86-64 is the first
platform with a verified active-tool boundary. Windows retains the native core,
SQLite, reports, graphs and supported offline adapters; equivalent Windows
active containment is deferred.

The four formerly blocked tools now have real external adapters: dnsx through a
counted DNS broker, ProjectDiscovery httpx through the shared HTTP broker, Katana
through bounded non-headless crawling, and Nuclei with two hashed exposure
checks. Compatibility and execution permission are checked separately at runtime.
`strict_tools: true` requires actual selected external processes and rejects
missing prerequisites; it never substitutes native results.

## Install and verify on Kali Linux

Provision the optional system dependencies, then run the application unprivileged:

```sh
sudo apt-get install bubblewrap openssl python3 python3-venv
python tools/bootstrap.py
reconmap --version
reconmap doctor
reconmap tools doctor --json
```

Doctor must show the actual namespace backend available. Restricted containers
may prohibit user namespaces even with bubblewrap installed. Do not disable scope
checks or run the whole scanner as root to work around such restrictions.

For an explicitly authorized target, keep the existing scope YAML and set
`strict_tools: true`:

```sh
reconmap blackbox https://authorized.example --config scope.yaml
reconmap scan https://authorized.example --config scope.yaml --tools subfinder,httpx,katana
```

The first command selects all eight capabilities. The second honors its subset.
SecLists remains an optional setup dependency and is never downloaded during scans.

## Verify without public targets

```sh
python tools/install_tools.py --tool subfinder --tool urlfinder --tool dnsx --tool httpx --tool katana --tool nuclei --directory .tools/bin
RECONMAP_REQUIRE_CONTAINMENT=1 RECONMAP_TEST_ACTIVE_TOOLS=.tools/bin python -m pytest -q tests/test_execution_boundary.py tests/test_contained_linux.py
python -m pytest -q
```

Linux CI requires real active binaries and isolated provider fixtures on Python
3.12/3.13. The existing Ubuntu/Windows matrix is retained. Gitleaks and jsluice
also have real local-artifact tests; see the recorded execution results for which
binaries/platforms were actually exercised. Provider fixture execution does not
establish live-provider availability, completeness or service rate behavior.

## Outputs and compatibility

No database migration is required. Existing collision-safe run directories,
checkpoints, normalization, artifact hashes, rankings and analyst decisions remain.
The output paths are unchanged:

- `RUN/recon.sqlite`
- `RUN/raw/TOOL/INVOCATION/`
- `RUN/reports/index.html`, `coverage.json`, `stage-results.json`
- `RUN/graph/endpoint-tree.txt`, `asset-graph.json`, `asset-graph.dot`, `asset-map.html`

Process identities, real engines, exit codes, completed-input counts, accumulated
request usage and coverage limitations accompany the collected evidence.

See [execution architecture and limitations](EXTERNAL_EXECUTION.md) and the
[progress and verification record](EXTERNAL_EXECUTION_PROGRESS.md). No merge to
`main` is performed automatically.
