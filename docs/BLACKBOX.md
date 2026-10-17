# BlackBox workflow and endpoint map

The application/package version remains **3.1.0**. BlackBox extends the existing scanner, SQLite store, normalization, ranking, report and resumable job queue. It does not add a scanner, browser crawler, service, AI dependency or Graphviz requirement.

## Two workflows

```bash
reconmap blackbox https://example.com
reconmap blackbox https://example.com --config authorized-scope.yaml --max-requests 5000 --depth 3 --max-minutes 30
reconmap scan https://example.com --tools subfinder,httpx,katana
reconmap scan https://example.com --tools 1,3,4,5 --exclude-tools 1
reconmap scan https://example.com --exclude-tools 7,8
reconmap scan https://example.com --tools 4,5,6 --engine jsluice=native
reconmap scan https://example.com --wordlist custom.txt --wordlist api.txt
reconmap scan https://example.com --auto-wordlists --exclude-wordlist assets
reconmap scan https://example.com --formats json,csv --no-graph
reconmap resume recon-output/example.com
```

Targets here are illustrative; validation uses offline fixtures and explicitly scoped localhost. BlackBox sets all eight capability IDs, all existing enrichments, bounded content discovery and graph generation. Existing YAML scope and budgets remain authoritative. Its default depth is 3 for a new default configuration, with up to two independent passive/local jobs. Target HTTP remains centrally serialized.

`--god-mode` and `--full-coverage` print compatibility guidance and select the same BlackBox profile. `--all-tool`/`--all-tools` retain their existing meaning: select eight capabilities without automatically adding discovery/enrichment. `--deep` remains the existing larger budget/native-and-local-tool preset. These are selections into **one pipeline**, not separate engines.

Normal `scan` defaults remain native and lightweight. Explicit `--tools` selects only those capabilities and their corresponding native alternatives. With no explicit selection/configuration, `--exclude-tools` starts from all eight; with YAML/profile/`--tools`, it excludes from that selection. Excluding from native YAML retains native execution preferences rather than turning those modules into permission for new executables. Empty selection is allowed.

Crawling and fresh exposure checks require HTTP collection. Selecting Katana or Nuclei without httpx does not silently add HTTP work: their active work is skipped with a missing-prerequisite reason and the run is partial. Offline analyzers use existing/local artifacts and explain absent inputs. Native secret and JavaScript analysis are gated separately, including inline scripts, local inputs and reruns. DNS resolution required to validate HTTP destinations remains a transport safety operation; it is not reported as execution of unselected dnsx.

`--engine TOOL=auto` prefers a verified external implementation where permitted and falls back when appropriate. `--engine TOOL=native` does not invoke that executable, even for version/help checks; installed/compatible state is consequently **not checked**, not reported as missing. Native-only choices may have reduced coverage. There is no unsafe/external-force option. `--tool NAME=PATH` and saved registrations continue to work. Reviewed passive sources can be selected with repeated `--provider-source subfinder=crtsh`, equivalent to YAML `provider_sources`. Arbitrary subprocess arguments are not accepted.

`--formats html,json,csv` controls presentation exports. Canonical JSON evidence/summary and SQLite remain available even when presentation HTML/CSV are omitted. BlackBox always generates all formats and its graph. Normal scans generate graphs by default, or accept `--no-graph`. Report regeneration uses the saved configuration; it does not change collection authorization.

## Execution flow and transparency

1. Verify configuration and selected dependencies; record informational environment diagnostics.
2. Record the seed and available passive host/history references.
3. Run selected DNS observations and controlled HTTP collection.
4. Crawl selected HTML/base/script/form/sitemap references through the existing durable queue.
5. Analyze captured JavaScript and secrets using selected offline tools/native alternatives; eligible inferred GETs return to that queue.
6. Propose evidence-derived paths and selected local dictionaries, then schedule only eligible work within the discovery allocation.
7. Normalize, correlate, group and rank evidence using existing modules.
8. Finalize the existing report plus the graph cache and five graph exports, including partial/interrupted runs.

| ID | Capability | Eligible external engine | Native alternative / limit |
|---|---|---|---|
| 1 | Host discovery | Subfinder | Seed/captured references only; no equivalent passive enumeration |
| 2 | Historical discovery | URLFinder | Approved CDX enrichment when enabled; historical evidence stays historical |
| 3 | DNS analysis | dnsx remains restricted | Native bounded DNS observations |
| 4 | HTTP analysis | httpx remains restricted | Native aiohttp with destination, method and request controls |
| 5 | Crawling | Katana remains restricted | Native HTML/base/scripts/sitemap crawler; no browser actions |
| 6 | JavaScript analysis | Verified jsluice | Native Tree-sitter and embedded source-map parsing |
| 7 | Secret review | Gitleaks | Native secret patterns; no credential validation |
| 8 | Exposure review | Nuclei remains restricted | Limited reviewed signatures and bounded GET probes; no templates/exploitation |

`reports/coverage.json`, the report, dashboard and final paths identify selected versus unselected capabilities, actual engines, executable identity/version where checked, external invocation, input/output references, processed local-artifact counts, discovered-record counts, duration and limitations. Shared native request/time counters are not additive across stages. Unknown provider request counts remain unknown. `environment.json` and `doctor --json` show OS/user identity, effective Linux capability bits/Seccomp information where readable, executable permissions and available sandbox command paths. These observations do not establish containment or enable more tools.

Direct active external tools still cannot prove enforcement of excluded HTTPS paths, DNS/IP destinations, child/subrequests, methods, redirects, decompression and shared ceilings. No verified cross-platform execution broker was introduced. Native fallbacks retain those controls. A successful installed binary check does not mean an external scan ran. Exit 2 can coexist with useful complete native collection and missing external coverage.

## SecLists and discovery

The existing setup downloads a **237,235-byte reviewed four-list subset plus license** from official SecLists 2026.1, commit `190c6f7bd58c847ceadfe57d9853592737f059e8`. The packaged manifest pins exact file paths, sizes and SHA-256. This is not the full SecLists distribution. Existing compatible installations, including `/usr/share/seclists`, are reused after selected-file verification. Installation remains transactional, user-local and optional; scans never download dictionaries.

- Linux: `$XDG_DATA_HOME/thegodrecon/wordlists/seclists`, normally `~/.local/share/thegodrecon/wordlists/seclists`.
- Windows: `%LOCALAPPDATA%\thegodrecon\wordlists\seclists`.
- Portable settings: `RECONMAP_CONFIG_DIR/wordlists/seclists` when that override is set.

```bash
python tools/bootstrap.py
reconmap setup --with-seclists --yes
reconmap wordlists list
reconmap wordlists doctor
reconmap wordlists update --yes
```

Setup can omit optional wordlists with `--skip-wordlists`; mismatched/unrelated installations are preserved. `wordlists update` installs/revalidates the reviewed pin, not arbitrary upstream HEAD. Windows still needs native Python and may need Go/C compiler setup for optional jsluice; the core Tree-sitter fallback remains available.

Automatic selection uses small common paths, observed API routes/documentation, captured JS assets and current application technology evidence. Library filename keywords alone do not select PHP/framework dictionaries. Evidence candidates precede dictionary guesses. Explicit custom paths replace automatic dictionaries, including automatic DNS lists. Repeated `--wordlist` provides multiple lists; CLI lists replace YAML lists. `--exclude-wordlist` accepts catalog names (`common`, `api`, `assets`, `php`, `dns`) or an exact custom path. Exclusion of DNS lists never widens exact-host scope.

Candidates preserve source revision, path, hash, selection reason, exact entry, URL, requested state, response and ranking. The HTTP allocation defaults to 100 and cannot exceed 20% of the global request ceiling; redirects, retries and descendants consume it. Completed requests are reused. Normal scans enable this stage only through explicit discovery configuration, a custom wordlist or `--auto-wordlists`. Missing lists retain evidence-only discovery with a coverage limitation. See [God Mode implementation details](GOD_MODE.md) for the existing installer/queue safeguards.

New configuration fields (all backward-compatible defaults):

```yaml
workflow: scan                 # blackbox is persisted by the canonical command
execution_engines: {jsluice: native}
graph: true
report_formats: [html, json, csv]
discovery:
  enabled: true
  wordlists: [custom.txt]
  exclude_wordlists: [assets]
```

Existing configurations remain valid; default new fields are excluded from legacy digests. Non-default earlier God Mode digests also remain valid. Resume does not reset budgets or silently change selected dictionaries; recorded snapshots and artifact hashes are reused. Use a rerun for changed configuration.

## Graph schema and interpretation

SQLite **schema 4** additively introduces `graph_nodes(id,type,data)` and `graph_edges(id,source,destination,type,data)`, with source/destination indexes. Migrations 1→2→3→4 preserve original observations, relationships, findings, artifacts and analyst actions. Read-only older databases remain unmodified. Graphs are derived caches rebuilt atomically from `normalized_records`, investigation candidates and the existing provenance tables. The normalized records remain authoritative; this is not a second URL parser or ranking model.

Graph JSON schema version is 1. IDs are deterministic SHA-256 identities. Resource IDs depend on canonical URL, not changing live/historical classification. Request IDs preserve canonical URL, method, authorization context, explicit ports, path case, query values/order/repetition. Graph export redaction can hide sensitive values in labels; distinct identities remain separate in the restricted SQLite evidence.

Nodes include domains/subdomains, origins, structural path groups, webpage/JS/static/API/form/external/historical resources, HTTP request identities, parameters, artifacts, discovery sources, historical observations and investigation/exposure candidates. A resource can carry multiple evidence labels. Its request children retain exact method-specific status. Historical data and JS inference never manufacture a current response. Current 301/403/404 observations are observations, not proof of functional access or a vulnerability.

Edges include `contains_path`, `shares_origin`, `links_to`, `loads_script`, `references_api`, `redirects_to`, `submits_to`, `historically_observed`, `discovered_by`, plus structural `contains_host`, `has_request`, `has_parameter`, `has_evidence`, and `has_candidate`. Each records source/destination, semantics, confidence, provenance and available timestamps/artifact references. Structural path edges are explicitly distinct from observed references and static inference. Missing provenance timestamps remain absent rather than invented. Shared scripts, cycles and multiple parents retain their edges; a content hash never collapses distinct requests. Script extraction records its source URL to avoid falsely connecting a shared body with unrelated base contexts.

The text hierarchy traverses structural containment only, with original endpoints and request variants retained. It does not pretend that URL prefixes were fetched or that a directory exists. Prefix grouping is limited to 64 levels per URL; the complete original URL stays in the graph/tree. Relationship navigation handles cycles without recursively expanding the whole graph. Existing investigation ranks and analyst validation attach to candidates; there is no second severity score.

## Outputs and offline map

```text
recon-output/example.com/
  recon.sqlite
  config.effective.json
  environment.json
  normalized/
  reports/index.html
  reports/coverage.json
  graph/endpoint-tree.txt
  graph/asset-graph.json
  graph/asset-graph.dot
  graph/graph-summary.json
  graph/asset-map.html
```

Subsequent runs use `1_example.com`, `2_example.com`, etc. Partial/interrupted runs use the same layout. The existing report retains its four main investigation views and adds a link to the standalone map. The map supports expansion, search, type/source/state filters, relationship navigation and evidence inspection. It renders at most 60 inventory nodes and 40 relationships per page; full evidence stays in JSON/SQLite. The UI displays references as text, uses hash-pinned script/CSP, disables network access and escapes embedded JSON/HTML. Raw artifacts are not embedded. Optional Graphviz can render DOT separately.

## Verification

```bash
python -m pytest -q
python tools/verify_local_workflow.py --output-root recon-output/blackbox-check
```

The workflow helper requires a new output directory, starts its own loopback server with explicit lab scope, verifies canonical/customized scans and produces an example graph. Optional `--tool jsluice=PATH --tool gitleaks=PATH` executes those verified local analyzers. Provider tools and direct active tools are never exercised against public targets.

Optional browser verification needs an already installed Playwright/Chromium:

```bash
node tools/check_asset_map_browser.cjs recon-output/blackbox-check/blackbox/127.0.0.1/graph/asset-map.html recon-output/blackbox-map-browser
```

Set `RECONMAP_PLAYWRIGHT_MODULE` and `RECONMAP_CHROMIUM` for existing nonstandard installations. It checks pagination, filters, relationship navigation, escaping/network isolation and mobile layout, and saves screenshots. See [the progress/validation record](BLACKBOX_PROGRESS.md) for actually executed tests and remaining platform verification.

## Verified example

[Controlled localhost graph exports](examples/blackbox/README.md) and [map screenshot](images/blackbox-map.png) show an actual fixture run. The [JavaScript relationship view](images/blackbox-javascript.png) links captured script evidence to inferred routes.
