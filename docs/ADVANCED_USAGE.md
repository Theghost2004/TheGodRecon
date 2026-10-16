> Advanced V3 reference retained for compatibility. For the current beginner workflow, version 3.1.0 and automated setup, see [README](../README.md) and [release notes](V3_1_RELEASE.md).

# TheGodRecon V3 (reconmap 0.3.0)

A local Python CLI for explicitly authorized reconnaissance. It creates a scoped asset map, durable SQLite evidence, static-analysis leads and a searchable offline HTML report. No account, paid service, LLM or telemetry is required. There are no exploitation, credential-validation, form-submission or resource-claiming features.


## V3: tool-first collection and an evidence-backed shortlist

Explicitly selected, compatible **Subfinder, URLFinder, jsluice and Gitleaks** run
before their available fallbacks. Unselected installed tools never execute.
JavaScript and secret tools checkpoint each captured artifact: successful inputs
are not reprocessed on resume or on later crawl waves. A failed/partial tool keeps
its valid output, then uses the existing native analyzer for unfinished inputs.
The Tree-sitter method check still vetoes unsafe scheduling even when jsluice
succeeds. Source maps use the native embedded-source parser as a complementary
capability. Native-only module selections retain their existing behavior.

**dnsx/httpx/Katana/Nuclei remain blocked as independent active subprocesses.**
There is no verified Linux or Windows containment backend enforcing their DNS/IP,
HTTPS path, redirect, method and aggregate request policies. Their selected stages
use the existing native scheduler and record the exact blocker and actual engine.
A fallback never changes scope, resets budgets, permits POSTs, or grants provider
access. Subfinder has no equivalent native enumerator. URLFinder can fall back to
CDX only when `wayback` was already explicitly enabled; successful URLFinder
collection skips redundant CDX enumeration. Missing/failed requested external
coverage remains visible as partial (exit 2), even when fallback is useful.

The offline dashboard now focuses on **Live Assets**, **Interesting Endpoints**,
**Potential Exposures**, and **All Results**. Each candidate explains its
classification, reachability, coarse review score, evidence confidence, sources,
and suggested non-destructive manual check. Raw findings, analyst decisions,
tool accounting, history, technologies and evidence remain accessible in details
and exports. Local processing requires no additional dependency or service.

Contextual classification uses path segments, MIME, response status, forms and
preserved signatures. `/assets/css/adminlte.min.css` stays low-value inventory;
`/admin/login` is an application lead; 401/403 is a restriction, never proof of an
access-control failure. Matching current `.git/HEAD` evidence can outrank names.
Soft 404s, errors, redirects, static/build assets and synthetic observations are
downranked. Historical, inferred and reused parent evidence never establish fresh
liveness. Known HTTP methods, explicit ports, path case, query values/repetitions
and authorization-context identities remain separate.

Normalization, grouping and investigation ranking are now core local processing,
including when `--enrich none` is used. The existing `dedup`/`priority` selectors
remain accepted; `tech`, `asn` and `wayback` stay opt-in. Existing priority weight
keys/config digests are preserved; output records identify scoring rule **2**.
Scores use five-point steps and separate review interest, confidence, reachability,
impact assessment and unassessed vulnerability severity. Groups hide repeated
cards, preserve every exact member and never delete source evidence. Methodless
tool duplicates link to known requests without inventing a method or response.

Useful additional outputs:

- `reports/investigation.json`: run summary, shortlist and complete request inventory.
- `reports/stage-results.json`: selected/actual engines, executable identity,
  fallback, errors, limitations, artifacts, duration and measurable counters.
- `normalized/normalized_records.jsonl` and `investigation_candidates.jsonl`:
  traceable exact request records and rankings; corresponding CSV exports exist.
- SQLite **2→3** migration adds only these derived records and stage results;
  versions 1/2/3 remain readable. Original evidence and analyst decisions survive.

To verify V3 without contacting targets or providers:

```text
reconmap demo --output-root ./v3-output
reconmap demo --tools all --enrich all --output-root ./v3-output
reconmap scan --resume ./v3-output/example.com
reconmap report --run ./v3-output/example.com
reconmap rerun --from ./v3-output/example.com --modules analysis --mode offline
python -m pytest -q
```

The full-selection demo intentionally returns exit 2 for unavailable/blocked tools.
Install reviewed offline binaries and pass `--tool NAME=PATH` to exercise them.
See [V3 architecture and limitations](V3_ARCHITECTURE.md) and
[verification checklist](V3_PROGRESS.md) for actual execution evidence.


## Selection, plans and profiles

The permanent registry IDs are **1 Subfinder, 2 URLFinder, 3 dnsx, 4 ProjectDiscovery httpx, 5 Katana, 6 jsluice, 7 Gitleaks, 8 Nuclei**. `--tools` selects executables; singular `--tool NAME=PATH` configures their paths. A selection runs only those external tools and necessary internal safety/analysis/native alternatives. Selecting Subfinder alone does not start HTTP crawling. Selecting local tools alone needs `local_inputs` or a parent run; missing inputs are reported as skipped.

```text
reconmap tools list
reconmap tools doctor --tool "httpx=C:/Tools With Spaces/httpx.exe"
reconmap plan --target authorized.example --config scope.yaml --tools all --enrich all --json
reconmap scan --target authorized.example --config scope.yaml --tools 1
reconmap scan --target authorized.example --config scope.yaml --tools 1,3,5,7
reconmap scan --target authorized.example --config scope.yaml --tools 1-4
reconmap scan --target authorized.example --config scope.yaml --tools quad
reconmap scan --target authorized.example --config scope.yaml --profile full
reconmap scan --target authorized.example --config scope.yaml --tools all --enrich all
reconmap scan --target authorized.example --config scope.yaml --tools web --enrich tech,dedup,priority
reconmap scan --target authorized.example --config scope.yaml --profile passive
reconmap scan --target authorized.example --config scope.yaml --profile offline --enrich tech,dedup,priority
reconmap demo --enrich tech,dedup,priority
```

Replace the illustrative `authorized.example` and review its YAML scope before any real scan. Plan previews validate scope and inspect binary version/help only; they do not resolve or request target hosts or providers. Expressions accept names, IDs, ascending ranges, `quad` (1–4), `passive` (1–2), `offline` (6–7), `web` (4–5) and `all` (1–8). Optional `1+2+3` means `1,2,3`. Duplicates disappear and registry order is deterministic.

**Direct dnsx/httpx/Katana/Nuclei execution remains blocked.** Each tool has a reviewed binary/schema and a separate persisted `blocked-by-policy` status; native DNS/HTTP/crawling/two reviewed exposure checks run instead when selected. Full selection therefore produces useful native/local results with exit **2** for incomplete external coverage. `--strict-tools` instead exits **4** before allocating a run. Installation or a preset never removes this restriction. In this cloud the user network-namespace isolation check failed; HTTPS CONNECT alone cannot enforce excluded paths or prevent scanner bypasses. No privileged, Docker/WSL or unsafe bypass is introduced. See [TOOLS.md](TOOLS.md) for individual reasons.

Profiles define defaults: `standard` keeps the V1 native workflow; `passive` selects 1–2 without target HTTP/DNS; `offline` selects 6–7 plus native artifact analysis; `full` selects all tools, their native alternatives and all enrichments. CLI `--tools` or `--modules` overrides a YAML profile/tool selection; CLI `--profile` overrides YAML profile defaults. CLI `--enrich` overrides YAML enrichment selection. An explicit YAML `enrichments` list overrides its YAML profile's enrichment default. `--tools` and `--modules` together are rejected, as are CLI `--profile` with `--tools`, `--modules` or `--mode`; use explicit selections instead. YAML profiles cannot also define `modules`, `mode` or `selected_tools`. Tool paths and budget overrides remain independent. V1 YAML is still accepted.

Accepted enrichment selectors are `asn,wayback,tech,dedup,priority` (V3 grouping/ranking always run locally); `--enrich all` and `--enrich none` are supported. Only an explicit enrichment/profile setting permits third-party metadata access. Demo, offline and loopback lab modes contact no providers. Tech/grouping/priority use captured evidence only. ASN uses RIPE Stat for observed authorized public A/AAAA addresses; it never authorizes an ASN/CIDR scan. Wayback collects bounded CDX metadata for the seed host, never archived content; history is not current liveness. Owned provider GETs have separate pinned HTTPS endpoints, DNS checks, request/rate/time/output caps and persistent expiring caches. External Subfinder/URLFinder provider request counts remain unknown and are reported separately. Live provider collection has not been execution-verified in this cloud; local fixtures cover pagination, failures, schema validation, caching and destination controls.

Grouping preserves exact URLs and every source. Numeric/UUID route families and repeated parameter-name signatures are analytical groups: case, explicit ports, methods and exact query values remain distinct and are still independently schedulable. Priority is a versioned configurable 0–100 **review score** in five-point steps, with evidence confidence and component reasons. Inferred routes are capped at 30 and other unobserved routes at 20; scores never confirm a vulnerability. Report sections and CSV/JSONL exports include tools, infrastructure, historical URLs, technologies, route groups and prioritized endpoints.

## Reruns and database compatibility

```text
reconmap rerun --from ./recon-output/authorized.example --tools 6,7 --enrich tech,dedup,priority
reconmap rerun --from ./recon-output/authorized.example --tools 4,5 --config current-scope.yaml
reconmap rerun --from ./recon-output/authorized.example --profile full --config current-scope.yaml
reconmap scan --resume ./recon-output/1_authorized.example
reconmap report --run ./recon-output/1_authorized.example
```

Rerun always creates a separate folder using the same collision-safe convention. Local-only selection automatically uses offline mode, verifies every copied artifact hash/size, and makes independent file copies. The stopped/unlocked parent and its analyst decisions remain unchanged. New findings start as candidates; parent decisions remain available in lineage metadata. Fresh active recollection revalidates current scope, uses new counters/queues/locks, and does not treat parent discoveries as authorization. A synthetic/demo parent requires a current YAML config before any real network recollection; its generated fixture scope grants no real authority. Provider traffic is not inherited implicitly by rerun; select it explicitly again. Existing `local_inputs` paths are not reread unless a current YAML is supplied. New/parent run IDs, selected tools, versions/hashes, config digest, copied/new artifact hashes, request counts, stage completion and finding comparison are recorded. Interrupted copying has its own checkpoint: resume verifies the same parent/config/artifact set and completes atomic copies, with copying time retained in the run budget. Offline reused HTTP observations retain their parent collection timestamp and do not establish new liveness.

SQLite migrations **1→2→3** only add tables; original evidence, findings and analyst decisions are retained. V1 manifests/configurations remain readable and may be reused by rerun. Report regeneration or a compatible resumed write adds the new schema transactionally; immutable parent/diff reads never migrate the baseline. Unknown schemas fail closed. Resume continues existing completed work and remaining budgets; rerun creates new work. Reports do not require rerun. See [examples/scope.yaml](../examples/scope.yaml), [v2-full.yaml](../examples/v2-full.yaml) and [v2-offline.yaml](../examples/v2-offline.yaml).

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

If a Debian/Ubuntu interpreter reports that `ensurepip` is unavailable, install its matching `python3.x-venv` package through your distribution, or create the environment with `uv venv --seed --python python3.12 .venv` when uv is installed and `.venv` does not yet exist. In this cloud use `UV_CACHE_DIR=/workspace/.cache/uv` and `PIP_CACHE_DIR=/workspace/.cache/pip` for writable caches.

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

Linux/Python **3.12.14 and 3.13.5** have actually been tested in this cloud (268 tests each, including real offline tools). Native Windows is **not yet execution-verified**; a Linux/Windows CI matrix covers both versions, installation, core/localhost tests, process cleanup and offline Gitleaks. macOS and ARM64 are unverified additional platforms, not claimed support. Optional external binary compatibility is separate from Python compatibility; see [TOOLS.md](TOOLS.md) and [compatibility.json](../compatibility.json).

## Configure and run

Every new real scan needs an explicit YAML scope. `init` creates an exact-host configuration and refuses overwriting an existing config. Replace the illustrative hostname with your separately authorized target and review the written scope before scanning:

```text
reconmap init --target example.com --config scope.local.yaml
reconmap scan --target example.com --config scope.local.yaml --output-root ./recon-output --mode standard
reconmap scan --target example.com --config scope.local.yaml --mode passive --modules subfinder,urlfinder,analysis
reconmap scan --target example.com --config scope.local.yaml --max-requests 100 --max-urls 50 --depth 1 --per-host-rps 1 --timeout 10
```

These example commands are instructions only; **no authorization to scan example.com is implied**. During development use `demo` or loopback fixtures. Demo's example.com URLs are in-memory synthetic fixtures: no DNS, target HTTP or discovery-provider traffic occurs. The default modules are `http,crawl,analysis,checks`. Passive providers and offline binary enrichments are opt-in; for example set `modules: [http, crawl, analysis, checks, subfinder, urlfinder, gitleaks]`. Missing/incompatible selected tools and policy blocks produce explicit coverage statuses and exit 2; `--strict-tools` fails preflight with exit 4. Use `doctor --tool "gitleaks=C:/Tools With Spaces/gitleaks.exe"` or YAML `tools` overrides. Doctor never silently installs or updates tools.

YAML fields and defaults are in [examples/scope.yaml](../examples/scope.yaml). Exact hosts do not authorize subdomains. To authorize subdomains explicitly, add `*.example.com` and retain `example.com` separately if the apex is allowed. `exclude_hosts` and `exclude_paths` win. `paths` are case-sensitive, segment-boundary prefixes; `/api` does not allow `/apix`. `ports` and `schemes` are separate restrictions. Lab mode is deliberately loopback-only. Local files can be analyzed using `local_inputs: ['fixtures/app.js', 'fixtures/app.js.map']`, including in passive mode; their contents remain local. Relative paths are interpreted from the invoking working directory, so keep that directory consistent on resume.

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

The expanded V3 pass completed **268 tests on each Linux interpreter (3.12/3.13)**
and **15 browser checks**. See the [scenario matrix, fixes and actual screenshots](V3_REGRESSION.md).
Filters reveal matches inside collapsed sections and accept individual correlated
sources. Structured contexts, extension methods and raw evidence remain attached;
MIME case and old soft-404 observations no longer distort the current shortlist.

A reproducible end-to-end check starts and stops its own loopback server, exercises
demo collisions, caps, resume and immutable rerun, and writes reviewable reports:

```text
python tools/verify_local_workflow.py --output-root ./recon-output/workflow-check-1
```

Choose a new output root for each check. Supply optional `--tool NAME=PATH` overrides
to exercise reviewed local binaries; missing tools use the existing fallbacks.
The optional `tools/check_report_browser.cjs` checks actual browser visibility and
captures screenshots; its separate Playwright requirements are in the linked
verification guide.

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

The real-binary tests skip explicitly when their environment paths are absent. Tests cover collision races/files/symlinks, resume locks and incompatible config, interrupted manifest replacements, exact/wildcard/IDNA/path/port scope, DNS rebinding and CNAME scope, grouping semantics, budgets/rates/throttling, subprocess cancellation and tree cleanup, 403/redirect/soft-404/duplicate JS/local source maps, credential redaction, hostile HTML/JSON and CSV, analyst actions, immutable baseline diffs and complete demos. [PROGRESS.md](../PROGRESS.md) records the exact latest executed results and output locations.

Additional security regressions cover duplicate-slash exclusion bypasses, multicast address rejection, quoted/dynamic JavaScript methods, non-GET source-map routes, real jsluice method disagreements, complete PEM/authorization/environment-secret redaction, hostile run-folder links, malformed input recovery, exact/oversized response bodies, truncated compression and continuous subprocess output. Ambiguous paths and unresolved HTTP methods remain observations; they are not scheduled for fetching. A hash-based content security policy permits only the report's bundled script.

Exit codes: **0** completed/command succeeded; **2** partial or incompatible comparison; **3** configuration/operation error; **4** strict dependency preflight failure; **130** interrupted. A zero finding count does not imply exhaustive coverage. The core has no authenticated-session or browser runtime coverage. Source-map external/indexed content, dynamic expressions, broad CVE scanning, active upstream tool parity and complete secret redaction are outside current verified coverage. DNS/provider service access and native Windows execution remain separate checks. See [ARCHITECTURE.md](ARCHITECTURE.md) for scheduling, evidence, scoring and disk-accounting limits.
