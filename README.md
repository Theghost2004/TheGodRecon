# reconmap V1

A local Python CLI for explicitly authorized reconnaissance. It creates a scoped asset map, durable SQLite evidence, static-analysis leads and a searchable offline HTML report. No account, paid service, LLM or telemetry is required. There are no exploitation, credential-validation, form-submission or resource-claiming features.

## Installation: Linux x86-64

Use Python **3.12 or newer** with `venv` and pip on Ubuntu/Debian/Kali. Distribution versions may ship older Python: check `python3.12 --version` first and install Python through your distribution's documented package manager if needed. Core runtime does not require administrative privileges, Bash utilities or external recon binaries.

From this repository's root:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.lock
.venv/bin/python -m pip install --no-deps -e .
.venv/bin/reconmap doctor
.venv/bin/reconmap demo --output-root ./recon-output
```

Alternatively, with uv installed: `uv sync --frozen --extra test`, then `uv run --frozen reconmap demo`. `uv.lock` pins cross-platform dependencies; `requirements.lock` is the hash-pinned pip equivalent including the test dependencies. Installation never changes the locks. Updating them is an explicit maintenance action.

## Installation: native Windows x86-64 / PowerShell

Install official Python 3.12+ x86-64 with its launcher. Neither WSL nor Docker is necessary for the core. From the repository root in PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements.lock
.\.venv\Scripts\python.exe -m pip install --no-deps -e .
.\.venv\Scripts\reconmap.exe doctor
.\.venv\Scripts\reconmap.exe demo --output-root .\recon-output
```

These commands do not require running an activation script or changing PowerShell execution policy. Use the executable path above instead of `reconmap` in the examples below. Keep the checkout/output root short (for example `C:\dev\reconmap`) on systems without long paths enabled. New Windows run folders receive a current-user-only ACL using the built-in `whoami` and `icacls`; if that fails, collection refuses to write sensitive artifacts. Raw artifacts are not suitable for public web hosting. Linux directories use mode 0700 and content files 0600.

Linux/Python 3.12 has actually been tested in this cloud. Native Windows and Python 3.13 are **not yet execution-verified**; a Linux/Windows CI matrix covers both versions, installation, core/localhost tests, process cleanup and offline Gitleaks. macOS and ARM64 are unverified additional platforms, not claimed support. Optional external binary compatibility is separate from Python compatibility; see [TOOLS.md](docs/TOOLS.md) and [compatibility.json](compatibility.json).

## Configure and run

Every new real scan needs an explicit YAML scope. `init` creates an exact-host configuration and refuses overwriting an existing config. Replace the illustrative hostname with your separately authorized target and review the written scope before scanning:

```text
reconmap init --target example.com --config scope.local.yaml
reconmap scan --target example.com --config scope.local.yaml --output-root ./recon-output --mode standard
reconmap scan --target example.com --config scope.local.yaml --mode passive --modules subfinder,urlfinder,analysis
reconmap scan --target example.com --config scope.local.yaml --max-requests 100 --max-urls 50 --depth 1 --per-host-rps 1 --timeout 10
```

These example commands are instructions only; **no authorization to scan example.com is implied**. During development use `demo` or loopback fixtures. Demo's example.com URLs are in-memory synthetic fixtures: no DNS, target HTTP or discovery-provider traffic occurs. The default modules are `http,crawl,analysis,checks`. Passive providers and offline binary enrichments are opt-in; for example set `modules: [http, crawl, analysis, checks, subfinder, urlfinder, gitleaks]`. Missing selected tools produce explicit degraded stages and exit 2; `--strict-tools` fails preflight with exit 4. Use `doctor --tool "gitleaks=C:/Tools With Spaces/gitleaks.exe"` or YAML `tools` overrides. Doctor never silently installs or updates tools.

YAML fields and defaults are in [examples/scope.yaml](examples/scope.yaml). Exact hosts do not authorize subdomains. To authorize subdomains explicitly, add `*.example.com` and retain `example.com` separately if the apex is allowed. `exclude_hosts` and `exclude_paths` win. `paths` are case-sensitive, segment-boundary prefixes; `/api` does not allow `/apix`. `ports` and `schemes` are separate restrictions. Lab mode is deliberately loopback-only. Local files can be analyzed using `local_inputs: ['fixtures/app.js', 'fixtures/app.js.map']`, including in passive mode; their contents remain local. Relative paths are interpreted from the invoking working directory, so keep that directory consistent on resume.

All budget fields are configurable in YAML. CLI overrides include `--modules`, `--mode`, `--max-requests`, `--max-urls`, `--depth`, `--timeout`, `--retries`, `--per-host-rps`, `--overall-rps`, `--max-response-bytes`, `--max-artifact-bytes`, `--max-minutes`, `--dns-budget`, `--provider-results` and `--provider-seconds`. Scope permissions are never broadened by a CLI budget override. A concise effective scope/budget summary appears before collection. Explicit valid scan commands proceed without repeated confirmations.

## Output folders and interrupted runs

The normalized seed hostname chooses the folder; `www` is retained. Scheme, port, path and query stay in the manifest. The default root is `./recon-output`, relative to your invoking directory. New invocations produce:

```text
recon-output/example.com/
recon-output/1_example.com/
recon-output/2_example.com/
```

The smallest positive unused prefix is chosen atomically when the plain name is occupied. Existing files, directories and symlinks are never overwritten or merged. Each run includes `manifest.json`, `config.effective.json`, `tools.json`, `recon.sqlite`, `assets`, `raw`, `evidence`, `normalized`, `logs`, `checkpoints`, `reports`, `diff` and `tmp`. Safely hashed raw bodies/source maps remain in `assets`; redacted exports are in `normalized` and `reports`. Tool installations and caches live separately, as documented in TOOLS.md.

```text
reconmap scan --resume ./recon-output/example.com
reconmap report --run ./recon-output/example.com
reconmap diff --baseline ./recon-output/example.com --current ./recon-output/1_example.com
```

Ctrl+C and SIGTERM preserve a readable partial report. Resume reuses the same folder, config, counters and completed jobs. Config/scope/budget/mode or executable changes require a new run. A hard kill may need `--break-lock` after the old process is confirmed stopped; a live local process cannot be unlocked. Hard-killed unfinished GETs can repeat; completed jobs do not. Already consumed request/time caps stay consumed, so increase caps only in a new run. Reports can be regenerated while offline. Baseline files are read-only; absence in a diff means “not observed this time,” never proof of unavailability.

The security fixes introduced execution policy revision **2**. Runs created before this revision remain available for report generation and comparison, but cannot resume their older request queues: start a new run using the same YAML. Current runs resume normally. Existing run folders must contain regular files and directories; report/resume commands reject symlinks, Windows junctions, hard-linked files, unsafe artifact paths and inconsistent manifest/configuration data. Keep these folders private; these checks do not isolate another process running as your OS account.

Open `RUN_DIR/reports/index.html` from disk. Search across routes, statuses, sources, confidence and priority; filter record sections and expand evidence/relationships. `summary.md`, `snapshot.json`, `findings.json`, `findings.csv`, `urls.csv`, `parameters.csv` and per-table JSONL exports are also generated for zero-finding and interrupted runs. Findings have unassessed severity and require manual review. Record an explicit analyst action with:

```text
reconmap validate --run ./recon-output/example.com --finding FINGERPRINT --status "needs manual validation" --note "Reviewed local evidence; authorization context still unknown"
```

## Local fixtures and verification

The tests start their own loopback HTTP servers and use synthetic tool/provider outputs. No public target is requested. A manual loopback smoke run works in both terminals using these commands in separate windows (substitute platform-specific Python/reconmap paths):

```text
python tools/lab_server.py --port 8765
reconmap init --target http://127.0.0.1:8765 --config lab.local.yaml --lab
reconmap scan --target http://127.0.0.1:8765 --config lab.local.yaml --depth 3
```

```bash
.venv/bin/python -m pytest -q
RECONMAP_TEST_GITLEAKS=/workspace/tooling/bin/gitleaks RECONMAP_TEST_JSLUICE=/workspace/tooling/bin/jsluice .venv/bin/python -m pytest -q
```

PowerShell equivalents for optional installed tools:

```powershell
$env:RECONMAP_TEST_GITLEAKS = (Resolve-Path .\.tools\bin\gitleaks.exe).Path
.\.venv\Scripts\python.exe -m pytest -q
```

The real-binary tests skip explicitly when their environment paths are absent. Tests cover collision races/files/symlinks, resume locks and incompatible config, interrupted manifest replacements, exact/wildcard/IDNA/path/port scope, DNS rebinding and CNAME scope, grouping semantics, budgets/rates/throttling, subprocess cancellation and tree cleanup, 403/redirect/soft-404/duplicate JS/local source maps, credential redaction, hostile HTML/JSON and CSV, analyst actions, immutable baseline diffs and complete demos. [PROGRESS.md](PROGRESS.md) records the exact latest executed results and output locations.

Additional security regressions cover duplicate-slash exclusion bypasses, multicast address rejection, quoted/dynamic JavaScript methods, non-GET source-map routes, real jsluice method disagreements, complete PEM/authorization/environment-secret redaction, hostile run-folder links, malformed input recovery, exact/oversized response bodies, truncated compression and continuous subprocess output. Ambiguous paths and unresolved HTTP methods remain observations; they are not scheduled for fetching. A hash-based content security policy permits only the report's bundled script.

Exit codes: **0** completed/command succeeded; **2** partial or incompatible comparison; **3** configuration/operation error; **4** strict dependency preflight failure; **130** interrupted. A zero finding count does not imply exhaustive coverage. The core has no authenticated-session or browser runtime coverage. Source-map external/indexed content, dynamic expressions, broad CVE scanning, active upstream tool parity and complete secret redaction are outside current verified coverage. DNS/provider service access and native Windows execution remain separate checks. See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for scheduling, evidence, scoring and disk-accounting limits.
