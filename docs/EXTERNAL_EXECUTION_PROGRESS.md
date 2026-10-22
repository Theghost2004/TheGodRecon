# V3.1.1 execution and verification record

Branch: `feature/v3.1.1-external-tool-execution`, based on `main` at `edf772a`.
Release: **TheGodRecon V3.1.1 — Linux-First Eight-Tool Execution Engine**.

- [x] Audit registry, adapters, strict preflight, scheduler, evidence and reporting.
- [x] Verify reviewed binaries and command-line syntax.
- [x] Implement Linux namespace/seccomp isolation and central HTTP/DNS enforcement.
- [x] Execute real dnsx, httpx, Katana and reviewed Nuclei checks against local HTTP/HTTPS/DNS fixtures.
- [x] Execute real Subfinder/URLFinder against isolated provider responses, and real jsluice/Gitleaks against local artifacts.
- [x] Verify scope, shared budgets, HTTPS, cancellation, output bounds and partial evidence.
- [x] Preserve reports, graph relationships, strict semantics and zero-request resume.
- [x] Run full local suites on Python 3.12 and 3.13.
- [x] Pass Windows Python 3.12/3.13 CI after preserving template LF bytes.
- [x] Finish browser checks, release documentation and a reviewable PR description.
- [ ] Create the PR through GitHub API (connection currently returns Forbidden).

## Actual execution evidence

The [Linux CI run at c5897e2](https://github.com/Theghost2004/TheGodRecon/actions/runs/39652260314)
passed both Python 3.12 and 3.13 jobs: **45 tests per job**, with isolation required.
This includes actual process execution, structured parsing and SQLite evidence for
the four active tools, HTTP and HTTPS fixtures, report/graph generation and resume.
Real Subfinder and URLFinder use fixture-backed provider responses inside the same
production boundary. No public provider or public scan target is contacted.

| Tool | Binary verified | Real process executed | Results parsed | Linux evidence |
|---|---|---|---|---|
| Subfinder 2.17.0 | Yes | Yes | Yes | Isolated HackerTarget response; hostname persisted |
| URLFinder 0.0.3 | Yes | Yes | Yes | Isolated AlienVault response; historical URL persisted |
| dnsx 1.3.1 | Yes | Yes | Yes | Local DNS responses through counted broker |
| httpx 1.12.0 | Yes | Yes | Yes | Local HTTP/HTTPS through shared scheduler |
| Katana 1.8.0 | Yes | Yes | Yes | Local HTML, JavaScript and API route collection |
| jsluice pinned 0ddfab1 | Yes | Yes | Yes | Real local-artifact endpoint/method extraction |
| Gitleaks 8.30.1 | Yes | Yes | Yes | Real local-artifact synthetic-secret detection |
| Nuclei 3.11.1 | Yes | Yes | Yes | Reviewed local exposure signature and preserved evidence |

These are integration results across controlled fixtures, not a claim of a public
eight-tool scan or live-provider completeness. Kali itself has not been run in this
workspace. The production active boundary was exercised on Ubuntu 24.04 CI.

Local Linux Python 3.12.14: **440 passed, 9 skipped** (24.17s).
Local Linux Python 3.13.5: **440 passed, 9 skipped** (24.58s).
The nine skipped cases require user namespaces; this cloud host rejects uid-map
setup. Those same cases are required, not skipped, by the dedicated Linux job.
Actual offline Gitleaks/jsluice tests were enabled in both local suites.

Exact local test commands from the repository root:

```sh
RECONMAP_TEST_GITLEAKS=/workspace/tooling/bin/gitleaks RECONMAP_TEST_JSLUICE=/workspace/tooling/bin/jsluice .venv/bin/python -m pytest -q --tb=short --junitxml=/workspace/v311-validation/final-python312.xml
RECONMAP_TEST_GITLEAKS=/workspace/tooling/bin/gitleaks RECONMAP_TEST_JSLUICE=/workspace/tooling/bin/jsluice /workspace/reconmap-v3-py313/bin/python -m pytest -q --tb=short --junitxml=/workspace/v311-validation/final-python313.xml
```

The [core CI run at d33db5f](https://github.com/Theghost2004/TheGodRecon/actions/runs/39713285705)
passed **all four Ubuntu/Windows × Python 3.12/3.13 jobs**, including locked install,
bootstrap, actual Gitleaks, full regression tests, CLI smoke, demo, resume, report,
offline rerun and God Mode fixtures. The [contained run at the same commit](https://github.com/Theghost2004/TheGodRecon/actions/runs/39713285627)
also passed both jobs. The subsequent map-title regression and fixture-harness
adjustments are included in the 440-test local results above.

## Defects found and fixed during real execution

- Katana requires `-list`; `-l` is not its supported input flag.
- Katana's `-omit-body` clears its response before JavaScript parsing in 1.8.0.
  Retaining the bounded response restored real script-derived route extraction.
- HTTPS CONNECT defaults to port 443; the broker now preserves implicit versus
  explicit port identities using the validated decrypted Host authority.
- Subfinder/URLFinder require their isolated configuration parent directories to
  exist. These are created before every invocation on Linux and Windows.
- URLFinder 0.0.3 cannot parse standard Common Crawl CDX lines. New configurations
  use the reviewed AlienVault source; explicit legacy selections remain valid
  but report partial coverage with a repair instruction.
- Windows Git CRLF conversion changed reviewed template hashes. `.gitattributes`
  now preserves their exact LF bytes. A fresh `core.autocrlf=true` checkout verified
  both hashes; no normalization or weakened hash acceptance was introduced.

## Scope and failure verification

Tests reject unauthorized hosts/subdomains, ports, schemes, paths, encoded
exclusions, credentials, destructive actions and non-GET requests before target
transport. Out-of-scope redirects remain unobserved references. Shared concurrent
reservations cannot exceed the remaining request ceiling. DNS queries are counted
and paced without hidden CNAME chasing. Direct child/descendant egress and VSOCK
are blocked; timeout, crash, output limit and cancellation preserve partial data
and clean up children. Strict mode never replaces a required external tool with
native execution; non-strict fallback retains the existing scope and budgets.

## Offline workflow and screenshots

The scoped localhost CLI workflow passed **21 checks** with **57 total GETs**
across its separate scan runs. Resume and immutable offline rerun made **zero**
additional requests. It covers normal scan, BlackBox, aliases, custom wordlists,
ranking, graph edges, output collisions and unavailable-tool fallbacks. The
fixture now pins intentionally missing active executables so installing a working
Linux boundary cannot accidentally change this fallback test into an active run.
Real active execution has its own required CI suite.

Chromium 154.0.8037.57 passed **17 report checks** and **10 asset-map checks**, with
no browser errors or external requests. Screenshot inspection found and fixed a
map title that could use an unrelated domain; it now uses the saved run target.
The regression checks target attribution, legacy exports and HTML escaping.

Exact commands:

```sh
XDG_CONFIG_HOME=/workspace/v311-validation/settings .venv/bin/python tools/verify_local_workflow.py --output-root /workspace/v311-validation/fallback-workflow --tool jsluice=/workspace/tooling/bin/jsluice --tool gitleaks=/workspace/tooling/bin/gitleaks
RECONMAP_CHROMIUM=/usr/bin/chromium node tools/check_report_browser.cjs /workspace/v311-validation/fallback-workflow/god-mode/127.0.0.1/reports/index.html /workspace/v311-validation/screenshots-report-verified
RECONMAP_CHROMIUM=/usr/bin/chromium node tools/check_asset_map_browser.cjs /workspace/v311-validation/example.com/graph/asset-map.html /workspace/v311-validation/screenshots-map-verified
```

Generated output is under `/workspace/v311-validation/`: `fallback-workflow/`
contains runs and `verification.json`; `example.com/` is the offline demo;
`screenshots-report-verified/` and `screenshots-map-verified/` contain screenshots
and browser verification JSON. These local test artifacts are not committed as
source code or claimed as live target evidence.

## Publication

The requested feature branch is pushed; `main` is unchanged. GitHub API PR creation
currently returns Forbidden through this connection. A review description and
branch comparison will be provided; no duplicate PR or automatic merge is made.
