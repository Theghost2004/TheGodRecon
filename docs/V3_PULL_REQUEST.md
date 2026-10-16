# V3: tool-first execution, traceable evidence and a useful investigation shortlist

## Problem and resulting behavior

The V2 collector could repeat native analysis before selected external tools and
rank superficial URL keywords as meaningful leads. V3 attempts selected compatible
tools first, preserves partial results, checkpoints each artifact and evaluates
native fallback within the same scope and remaining budgets. Missing or incomplete
coverage is visible in durable stage results and reports.

For example, `/assets/css/adminlte.min.css` remains inventory, `/admin/login` is a
manual investigation lead, and a current matching `.git/HEAD` response ranks above
an asset filename. None of these classifications automatically confirms a
vulnerability. Historical and inferred URLs never establish current reachability.

## Changes

- Add structured execution results with selected/actual engines, binary identity,
  artifacts, failure/fallback reasons, counters, duration and coverage limits.
- Execute jsluice/Gitleaks first per captured artifact, retain successful partial
  output and reuse checkpoints. Retain the native method/options scheduling veto,
  embedded source-map parser and all existing native-only workflows.
- Normalize into exact URL/method/context identities, preserving original URLs,
  ports, path case, repeated query values, evidence and source provenance. Add
  SQLite schema 2→3 tables without replacing original evidence or analyst decisions.
- Correlate exact/content/route/parameter/source evidence, suppress duplicate cards
  without deleting members, and rank with inspectable signals and coarse scores.
  Separate interest, confidence, reachability, potential impact and severity.
- Present Live Assets, Interesting Endpoints, Potential Exposures and All Results;
  retain detailed evidence, secure offline rendering and existing machine exports.
- Preserve CLI IDs/presets/configs, collision-safe outputs, integrity checks and
  resume/rerun. Namespace imported observation identities so fresh rerun HTTP
  evidence cannot collide with parent observations.

## Validation actually executed

- Final expanded Linux suites: **268 passed, zero failures/skips** on Python
  **3.12.14** (11.89 seconds) and **3.13.5** (12.17 seconds), with actual reviewed
  Gitleaks 8.30.1 and jsluice binaries. Earlier fresh hash-pinned installation
  verification also passed; dependency pins remain unchanged.
- Added 40 Python cases plus reproducible localhost/browser verification utilities.
  Fixed hidden filtered rows, combined-source filtering, lost structured-context
  or extension-method evidence, stale soft-404 penalties, and MIME/extension case
  handling. No scope permission, schema or policy revision was changed.
- Offline full-selection demo and scoped localhost collection: **13 GETs**, no
  forbidden POSTs, excluded endpoints or out-of-scope redirects. Resume and offline
  rerun sent zero new requests; rerun preserved parent bytes and directory entries.
- Headless Chromium 154.0.8037.57 passed **15 browser checks**, including visible
  filters, nested evidence, empty reports and narrow layout, with zero browser/console
  errors and external requests. Direct file navigation was
  blocked by the managed browser; this used Playwright `setContent`.
- Compilation, dependency consistency and Git whitespace checks passed. Source
  Gitleaks review found only the two existing deliberately synthetic fixture tokens.

Regression tests cover misleading paths, MIME/status conflicts, soft 404s,
historical/inferred/parent evidence, grouping/provenance, request identity,
signature ranking, partial scans, tool failure/timeout/cancellation, budget limits,
safe fallback, schema migration and native paths with spaces.

## Intentional limits

Direct dnsx/httpx/Katana/Nuclei execution stays blocked. Neither platform has a
verified containment backend enforcing all DNS/IP, HTTPS-path/method, redirect,
secondary-request and aggregate-budget requirements. Existing controlled native
engines run instead; full selection truthfully reports partial coverage (exit 2).
No active binary target execution or live provider collection is claimed.

Native Windows 3.12/3.13, Windows console/process lifecycle and graphical
filesystem report navigation remain unverified. Existing CI covers Linux/Windows
3.12/3.13 but its results have not been inspected here. Subfinder has no equivalent
native enumeration; URLFinder uses CDX fallback only when explicitly enabled.
Process/file limits are cooperative monitoring, not OS resource quotas.

See `docs/V3_REGRESSION.md` for the scenario matrix, reproducible checks and actual
localhost screenshots; `docs/V3_PROGRESS.md` records exact output locations,
`docs/V3_ARCHITECTURE.md` for implementation details, and README for Linux/PowerShell
installation and local demo commands. This change builds on merged V2; dependency
versions and policy revision are unchanged.
