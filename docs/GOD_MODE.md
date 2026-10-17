# God Mode: coverage, installation and reproducibility

God Mode is an advanced selection of the existing 3.1.0 workflow. `--god-mode` and `--full-coverage` select tools 1–8, all existing enrichments and bounded content discovery. Existing numbered tools, `--all-tool`, `--deep`, profiles, scope files and ordinary scans retain their meanings. God Mode cannot be combined with another selection preset; a YAML scope and explicit budget flags are supported. Its default depth is 3, with the existing 5,000-request/30-minute ceilings. YAML ceilings and explicit CLI overrides remain authoritative.

## Execution boundary

Subfinder and URLFinder run against reviewed providers only when explicitly selected, installed and compatible. Provider subprocess request counts are unknown; output, runtime and process cleanup are bounded. Demo, offline and loopback-lab modes skip providers. jsluice and Gitleaks process captured local artifacts. They use verified executable identities and bounded outputs; successful inputs are checkpointed before fallback. Empty jsluice output triggers native AST analysis and records this reason. Nonempty successful primary output avoids redundant native discovery.

Direct **dnsx, httpx, Katana and Nuclei remain blocked on Linux and Windows**. A normal HTTP proxy or CLI allowlist cannot prevent direct sockets, alternate DNS, HTTPS CONNECT requests to excluded paths, redirects or template subrequests. Enabling them would require verified process-level egress isolation plus a request broker that checks every scheme, hostname, resolved address, port, path, method, redirect, byte limit and shared reservation. No such portable boundary was verified in this implementation. There is no blanket God Mode exception.

Their actual engines remain native DNS, aiohttp, HTML crawling and limited reviewed GET checks. Reports show installation, compatibility, direct-execution permission, actual execution, fallback capabilities/limits, counts, duration and missing coverage separately. A policy-restricted external tool remains visibly restricted even when its native alternative completes. Native DNS has narrower enumeration; native checks add `.git/HEAD` and `.env` probes plus bounded signatures on already captured responses, not Nuclei's template collection. No credentials, scripted browser actions or exploit attempts run.

Two independent passive or local tool tasks may run concurrently. An async semaphore bounds these tasks; each tool processes artifacts sequentially, enforces existing time/output limits and cleans up child processes on cancellation. Routine input/tool failures do not abort the other capability. SQLite is the durable bounded target-request queue; HTTP remains sequential with shared counters and rate limits. Increasing `--max-concurrent-jobs` does not increase HTTP concurrency. Values 1–2 are supported.

## SecLists provenance and setup

The bundled manifest pins official SecLists **2026.1**, commit `190c6f7bd58c847ceadfe57d9853592737f059e8`, and SHA-256/byte counts for:

- `Discovery/Web-Content/common.txt`
- `Discovery/Web-Content/api/api-endpoints.txt`
- `Discovery/Web-Content/raft-small-directories.txt`
- `Discovery/DNS/subdomains-top1million-5000.txt`
- The upstream MIT `LICENSE`

Setup retrieves these immutable files from `raw.githubusercontent.com/danielmiessler/SecLists/COMMIT/...`. Total download: **237,235 bytes**. This reviewed subset reduces installation cost; it is not the complete SecLists distribution. Every selected path was checked against the pinned upstream tree and its actual downloaded content. The source manifest is packaged with the wheel.

`python tools/bootstrap.py` installs locked Python dependencies, the project and reviewed optional tools. Existing virtual environments without pip are repaired through Python’s bundled ensurepip. Linux also selects the small SecLists subset by default. `--skip-wordlists` skips it; `--skip-tools` gives core-only setup unless `--with-seclists` is also supplied. `reconmap setup` asks for optional downloads in an interactive terminal, and declining wordlists leaves the core usable. Automation uses `reconmap setup --with-seclists --yes`. Windows can use the same explicit command after native Python setup.

Existing matching installations are checked in the registered path, managed data path, `/usr/share/seclists`, then `/usr/share/wordlists/seclists`. A full checkout is reusable when the selected files and license match the reviewed hashes. Unreviewed/mismatched copies are never silently trusted or overwritten. `--seclists-path PATH` registers an existing verified copy.

Managed data uses Linux XDG data conventions and Windows LOCALAPPDATA. `RECONMAP_CONFIG_DIR` deliberately relocates dictionaries under that portable settings root. Setup checks free disk space, rejects symlink/junction paths, downloads to private sibling staging, verifies all files and publishes by rename under an exclusive install lock. Ordinary exceptions/Ctrl-C remove staging; retry reuses completed installations. A hard process kill can leave an inert `.seclists-*` directory or `seclists.install.lock`: inspect it after confirming no installer is running, then remove that specific stale item before retry. Unrelated directories are preserved. No sudo is used.

`reconmap wordlists list`, `doctor`, and `update --yes` inspect or install the currently reviewed version. Update does not chase upstream HEAD or overwrite a modified installation. `doctor --fix --yes` also runs normal supported dependency repair. Setup may return 2 for other unavailable optional binaries even when wordlist installation succeeded; check the separate Wordlist Integrity result.

## Selection and discovery

`wordlists.py` validates UTF-8 literal dictionaries (2 MiB/file, up to eight custom paths), caches bounded parsing, deduplicates entries and rejects URL payload syntax, traversal, query actions and unsafe paths. No scan downloads wordlists. Candidate generation is separate from request scheduling:

1. Captured GET JavaScript routes, historical references and observed OpenAPI/Swagger GET paths are considered first. Dynamic expressions, templated parameters and non-GET operations remain evidence only. Captured API prefixes can propose a small number of documentation locations.
2. A small verified intersection of the common dictionary is selected. Observed APIs add the API list; captured JavaScript adds a small asset-directory subset. Current HTML/JSON application PHP header evidence can select `.php` entries. An unrelated static library does not establish application technology.
3. Explicit custom files take precedence over generic dictionaries in the same queue. Explicit wildcard authorization may permit up to 20 dictionary hostname proposals, further limited by DNS and discovery budgets. Exact-host scope never grants subdomain authorization.
4. Each proposal is persisted with source, hash/version, confidence and scheduling reason. Current completed requests and existing jobs are not repeated. Scope, exclusions, non-destructive action rules, static-media filters, depth and host quotas are enforced before scheduling; destination validation runs before traffic.

The discovery allocation is `min(discovery.request_budget, budgets.requests // 5)`. Its default is 100, and the configured maximum is 2,000. Requests still consume the global budget. Retries, redirects, captured-script routes and descendants of dictionary probes retain a durable allocation marker. Exhausted dictionary jobs become deferred; resume cannot move them into the ordinary budget. Zero allocation sends no dictionary probes. Unscheduled proposals remain visible as untested evidence.

A selected dictionary is snapshotted under `raw/wordlists/SHA256.txt`. Hash-verified snapshots support resume when the original is removed or modified. Resume keeps saved settings and remaining counters; a new rerun allocates a separate folder. Offline reruns of God Mode collections disable active discovery, reuse evidence and establish no current liveness. No schema migration was needed: existing observations, jobs, stage results and metadata store the additions. Configurations without discovery retain their original digest.

```yaml
# Add to an existing authorized scope/configuration.
discovery:
  enabled: true
  god_mode: false
  wordlists: []       # Linux: /home/me/paths.txt; Windows: C:/Users/me/paths.txt
  request_budget: 100
  max_entries: 500
  max_concurrent_jobs: 1
```

Use CLI `--god-mode` to select all capabilities. `discovery.god_mode` in a hand-written YAML records that selection; the boolean alone does not replace a YAML tool/module selection. `--wordlist PATH` enables content discovery on its own. Advanced overrides: `--wordlist-budget`, `--max-wordlist-entries` (1–10,000), `--max-concurrent-jobs` (1–2). Effective settings are saved in every run.

## Crawler and analyst coverage

HTML `<base>` links, relative scripts, robots Sitemap references, sitemap indexes and URL sets feed the existing scheduler. Sitemap DTD/entity declarations are rejected. JavaScript/source-map routes retain their parent depth, including when proposed later by content discovery. No browser is introduced: DOM actions and runtime-generated SPA routes remain a coverage limitation. robots Allow/Disallow entries are not automatically brute-forced; they do not grant authorization.

A request ceiling is not a request target. A small site, strict path scope, shallow depth, absent dictionaries or few eligible links may legitimately produce few requests. `reports/coverage.json` and the terminal/report summary show actual discovered/scheduled/tested URLs, response counts, redirects, restrictions, static filtering, out-of-scope references, depth limits, failures, pending/deferred jobs and the stop reason. Response counts include retry observations; distinct tested URLs are separate from reserved attempts. Failed requests can consume a reservation without producing a response.

The original four report views remain. Enhanced runs also show JavaScript Discoveries, Wordlist Discoveries and Tool Execution and Coverage. JSON, CSV, JSONL and SQLite preserve source provenance, current status versus untested proposals, content hashes, ranking and grouping. `401/403`, a dictionary match or an admin-themed name is never a vulnerability conclusion. Existing soft-404 correlation, duplicate grouping and static-resource penalties remain in force. Untested dictionary/prefix-only guesses stay in inventory, and multiple dictionaries count as one source family rather than independent corroboration. The offline report's CSP, escaping, download-only evidence handling and CSV protections are retained.

Verification and publication status: [progress checklist](GOD_MODE_PROGRESS.md).
