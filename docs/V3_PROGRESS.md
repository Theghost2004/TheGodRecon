# V3 implementation checklist

Version **0.3.0**, SQLite schema **3**, policy revision **2**. Work began at V2
`5ba7bb1`; the review branch `feature/thegodrecon-v3` now includes GitHub main's
V2 merge `ddaae1c`. No repository AGENTS.md was present. Development used offline
fixtures and explicitly scoped loopback only. No public target/provider scan ran.

## Completed implementation

- [x] Audit CLI/config/selection, adapters, orchestration, scope/DNS, storage,
  analysis/enrichments, reports/reruns, installer, compatibility and tests.
- [x] Phase 1–2: durable stage contract, selected primary-first local tools,
  immediate partial evidence, bounded native fallback, per-artifact checkpoints,
  executable/artifact identity checks and process cancellation.
- [x] Phase 3: additive normalization with exact request identities, provenance,
  historical/current/parent separation and redirect destination semantics.
- [x] Phase 4: shared contextual classification, noise caps, conservative grouping,
  source correlation and explainable investigation shortlist.
- [x] Phase 5: four main report views, readable supporting evidence, run/coverage
  summary, secure offline rendering and original plus new machine exports.
- [x] Phase 6: regression suite, real local-tool/demo/loopback/resume/rerun checks,
  clean installation, README/architecture/compatibility and verification evidence.

No new runtime dependencies or CLI switches. Existing tool IDs, profiles, YAML
versions/digests and native modules remain compatible. Raw observations, findings
and analyst decisions remain authoritative. SQLite migration only adds tables.
Imported parent observation IDs are namespaced so fresh recollection cannot
collide with and silently lose new HTTP observations.

## Executed verification — 2026-10-15

- Linux x86-64, Python **3.12.14**. V2 baseline **186 passed** in 8.27 seconds.
- Final full suite in `.venv`: **228 passed**, no skips, **11.98 seconds**.
- Final full suite in fresh `/workspace/reconmap-v3-install`: **228 passed**, no
  skips, **11.98 seconds**. Installed using hash-pinned `requirements.lock` then
  editable package `--no-deps`; `pip check` found no broken requirements.
- Both final suites used the actual reviewed Linux binaries with the command:

  ```bash
  RECONMAP_TEST_GITLEAKS=/workspace/tooling/bin/gitleaks RECONMAP_TEST_JSLUICE=/workspace/tooling/bin/jsluice .venv/bin/python -m pytest -q --tb=short
  ```

  The independent run substitutes `/workspace/reconmap-v3-install/bin/python`.
  Gitleaks is 8.30.1; jsluice's reviewed fingerprint is in `compatibility.json`.
- `uv sync --frozen --extra test`, Python compilation and Git whitespace checks
  passed. Dependency pins/hashes are unchanged; only the project version changed.
- Regression coverage includes misleading/static route names, MIME/status
  conflicts, historical/inferred/parent liveness, soft 404s, signature ranking,
  exact query/method/context/port identity, content/route/source grouping, and
  methodless correlation. Existing folder-collision, scope, DNS, redirect,
  interruption/resume and cross-platform path tests also passed.
- Orchestration fixtures cover missing/incompatible/changed executables,
  successful primary without redundant native work, crash/malformed/partial
  output, timeout/output caps, file-size monitoring, cancellation/resume,
  exhausted shared budgets, method vetoes, excluded redirects, opt-in provider
  fallback and schema-2 additive migration. The subprocess descendant test now
  waits up to two seconds for the OS exit transition after pipe closure.
- Real full-selection synthetic demo and controlled loopback scan ran actual
  jsluice/Gitleaks. Four active binaries stayed policy-blocked; passive providers
  were skipped. Expected exit **2** reports incomplete requested external coverage.
- Loopback made **13 GETs**, including `/admin/login`, `/bundle.js`, the extracted
  `/api/admin/users`, and a controlled `.git/HEAD` fixture. It did not request
  excluded endpoints, inferred POSTs or the out-of-scope redirect. Report showed
  **13 observed / 16 discovered assets**, **2 high-interest**, **4 manual-review**,
  **4 grouped duplicate cards** and **11 inventory candidates**. Counts describe
  request candidates, not confirmed vulnerabilities; categories may group members.
- Resume made **zero new requests**. Offline rerun made **zero target/provider
  requests**, reported zero newly observed assets and preserved all parent file
  hashes/directory entries during the operation. Reports were subsequently
  regenerated explicitly from retained evidence; no collection traffic occurred.
- Headless Chromium **154.0.8037.57** rendered the generated HTML and passed four
  view/search/filter checks: adminlte absent from shortlist but present in All
  Results; one correlated Git exposure card; zero browser errors/external requests.
  The managed browser blocks direct `file://` navigation, so HTML was read from
  the local file and rendered using Playwright `setContent`. This verifies browser
  DOM/script behavior, not native filesystem navigation or graphical Windows use.
- Gitleaks scanned all **64** source/review files present before final documentation
  updates. Its only two findings were the existing deliberate synthetic demo/test
  tokens. Generated outputs, environments and tool binaries are excluded from Git.

## Output locations

Root: `/workspace/TheGodRecon/recon-output/v3-validation/final/`.

- `example.com/reports/index.html`: synthetic full-selection demonstration.
- `127.0.0.1/reports/index.html`: actual controlled loopback collection.
- `1_127.0.0.1/reports/index.html`: immutable-parent offline reanalysis.
- Each report directory also contains `investigation.json`, `stage-results.json`,
  `summary.md`, `snapshot.json` and original exports; each run has SQLite, raw
  artifacts and `normalized/` JSONL/CSV records.
- `v3-local-verification.json`: request paths/counters and parent/resume assertions.
- `v3-lab.yaml`: recorded ephemeral-port scope; the local fixture server is stopped.
- `report-review.png`: headless browser screenshot of the loopback report.

Earlier V1/V2/debug/V3 runs are retained in their original folders. Installation
commands for Linux and native PowerShell are in the README. Default demo needs no
external binaries; full-selection demos report unavailable/blocked capabilities.

## Deliberate limits and pending verification

- [ ] Native Windows Python 3.12/3.13, Linux Python 3.13 and Windows console/process
  lifecycle execution. The existing CI matrix is configured, not verified here.
- [ ] Native graphical/browser filesystem navigation and live provider collection
  against separately authorized scope. No public target/provider calls were made.
- [ ] Direct active subprocess containment: no verified backend jointly enforces
  target DNS/IP, HTTPS paths/methods, redirects/secondary requests, aggregate caps
  and process trees on Linux/Windows. dnsx/httpx/Katana/Nuclei remain blocked;
  the existing controlled native engines provide useful limited coverage.
- Subfinder has no equivalent native enumerator. URLFinder can use CDX only when
  Wayback was already explicitly enabled. No provider budget reset or permission
  expansion is allowed on failure.
- Process output/file monitoring and disk reserves are cooperative bounds, not
  OS memory/disk quotas. A write may briefly exceed the monitored file limit.
  Same-account hostile filesystem tampering is outside the private-run model.
- Static inference, pattern redaction and scoring cannot establish vulnerabilities
  or complete coverage. Raw artifacts remain sensitive; confirmed analyst decisions
  stay separate. Real jsluice/Gitleaks execution does not validate live providers
  or the four blocked active integrations.

## Review publication

- [x] Committed implementation/tests/docs as `a20e7bdbcd9e0333978398f37449f0c6b011686d`
  on `feature/thegodrecon-v3`, based on merged V2 main `ddaae1c`.
- [x] Published the branch without force and verified GitHub's remote commit.
  Main remains `ddaae1c6ad4d3056915f6e4cc341fb3c5aa5c410`; no merge/deployment occurred.
- [x] Prepared the complete PR description in `docs/V3_PULL_REQUEST.md` and
  `/workspace/thegodrecon-v3-pr.md`.
- [ ] Draft PR creation was attempted but GitHub GraphQL returned
  `Post https://api.github.com/graphql: Forbidden`. **No PR was created**.
  GitHub Actions results could not be inspected through this API.

Review: https://github.com/Theghost2004/TheGodRecon/compare/main...feature/thegodrecon-v3

Create PR: https://github.com/Theghost2004/TheGodRecon/pull/new/feature/thegodrecon-v3

The final documentation commit records this outcome; generated scan artifacts and
installed binaries remain local and excluded from the branch.
