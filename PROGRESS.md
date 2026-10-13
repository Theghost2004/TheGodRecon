# reconmap V1 progress

The implementation brief is preserved at [docs/IMPLEMENTATION_BRIEF.md](docs/IMPLEMENTATION_BRIEF.md) (read completely). The repository was empty and had no AGENTS.md. No external targets are authorized for development. Use offline demo or explicit loopback fixtures only.

## Decisions

- Python 3.12+, argparse, Pydantic, aiohttp, SQLite, native paths and subprocess argument arrays.
- One atomic directory per invocation; scope and budgets are immutable on resume.
- Sequential active requests share one scheduler. DNS results are checked and pinned by the connection resolver; redirects re-enter scope checks.
- Active external tools that cannot enforce all restrictions are disabled with reasons; core probing/crawling replaces them. No mandatory browser.
- Tree-sitter JavaScript parsing is the native Linux/Windows analysis path; jsluice/Gitleaks are optional offline enrichments.
- No LLM, telemetry, automatic credential validation, exploitation, or state-changing submissions.
- API release metadata was blocked; official GitHub release pages were reachable. Release versions and source flags are being reviewed separately from installed-tool verification.

## Milestones

- [x] M1: package, CLI, validated config, scope, atomic folders, schema, doctor — core tests and CLI ran
- [x] M2: typed adapters, controlled collection, provenance, partial failures — real localhost and real offline binary tests ran
- [x] M3: AST/local analysis, maps, secrets, exposure checks, ranking — synthetic fixture tests ran
- [x] M4: reports/exports, resume, baseline comparisons, deterministic demo — complete CLI demos, resume/report/diff and interruption ran
- [x] M5 delivery: Linux execution, Windows CI, locks, platform/install documentation
- [ ] M5 pending verification: native Windows/Python 3.12/3.13 runner; Linux Python 3.13; Windows console Ctrl+C; live provider requests against separately authorized scope

Update this file with commands actually executed, results, unresolved limitations, and output paths before ending a session. Never infer Windows execution from CI configuration.

## Executed evidence — 2026-10-13

- Python 3.12.14, Linux x86-64: `uv sync --frozen --extra test` succeeded; hash-pinned pip installation in fresh `/workspace/reconmap-install-check` and editable package install succeeded.
- `RECONMAP_TEST_GITLEAKS=/workspace/tooling/bin/gitleaks RECONMAP_TEST_JSLUICE=/workspace/tooling/bin/jsluice .venv/bin/python -m pytest -q`: **62 passed**, no skipped tests, latest run 5.25 seconds. Earlier fresh pip environment ran the then-current 61-test suite successfully; the additional POSIX SIGTERM test ran in the main environment.
- Real Gitleaks 8.30.1 detected a high-entropy synthetic token, returned configured findings exit 10, and redacted its report. Real jsluice at pinned source commit extracted a synthetic endpoint from a filename containing spaces. Subfinder 2.17.0 and URLFinder 0.0.3 actual help/version checks passed; public discovery queries were not run.
- The explicit Python tool installer successfully reverified Linux archive checksums and preserved existing matching binaries. Checksum mismatch and existing-different-binary refusal are covered by tests. Simulated Windows archive tests are not native Windows execution.
- Actual CLI SIGTERM produced exit 130, an interrupted manifest/checkpoint/HTML report and no live run lock. Coroutine cancellation/resume preserved already completed jobs. Missing/unsupported strict tools failed before allocating output.
- Offline report JavaScript passed Node syntax checking and DOM-fixture checks for search/status/confidence/priority/changes filters. A full graphical browser was not available; this is not a browser execution claim.
- CLI `demo`, `scan --resume`, `report`, and `diff` succeeded. Baseline bytes stayed unchanged; deterministic fixture runs had no changes. Pattern-redacted report exports were checked for the synthetic token.
- A real manual standard-mode loopback scan using `tools/lab_server.py --port 8765`, `init --lab`, and the documented scan command completed. The fixture process was stopped after validation. No real public target or discovery provider was scanned.

## Delivery locations

- Source/documentation/locks/tests/CI: `/workspace/TheGodRecon`.
- Clean offline runs: `/workspace/TheGodRecon/recon-output/example.com`, `1_example.com`, `2_example.com`. All completed, 18 offline fixture HTTP operations each; 12/12/13 candidate leads respectively. Third run includes the real offline Gitleaks stage.
- Open any run's `reports/index.html`; `reports/summary.md`, `reports/snapshot.json`, findings JSON/CSV and normalized JSONL are alongside it. The second run includes an unchanged baseline comparison under `diff/comparison.json`.
- Real localhost run: `/workspace/TheGodRecon/recon-output/127.0.0.1`. Local scope: `/workspace/reconmap-validation/manual-lab-scope.yaml`.
- Earlier incremental development outputs remain under `/workspace/reconmap-validation`. Its initial `example.com` run records a fixed development defect and is not the delivery demo. These outputs were not silently overwritten or removed.
- Optional verified binaries/receipts: `/workspace/tooling/bin`. Go compiler/cache/package downloads: `/workspace/tooling/go`, `/workspace/tooling/go-cache`, `/workspace/tooling/go-packages`; Python caches: `/workspace/.cache`.

## Known limitations / next session

- Run native Windows CI after source is available to a Windows runner. Windows paths/ACL/process implementations and CI are supplied; parity is unverified. POSIX SIGTERM is deliberately skipped on Windows; real console Ctrl+C remains a manual check.
- Active external dnsx/httpx/Katana/Nuclei execution is disabled when scope/budget controls cannot be enforced together. Core native modules work; the reviewed Nuclei-compatible two-template allowlist is implemented natively. No upstream bulk template coverage is claimed.
- Discovery provider traffic needs selected provider egress and explicit authorization; current cloud package-manager access does not prove target/provider connectivity. Runtime native HTTP deliberately does not use target egress proxies.
- No authenticated/browser runtime crawling, arbitrary internal networks, dynamic JavaScript evaluation, indexed/external-source-map fetching, automatic credential validation, resource claiming, or broad CVE/exploit checking.
- Redaction is pattern-based; raw local artifacts remain sensitive. Disk cap reserves report space but is not a filesystem quota; minimum finalization/WAL overhead can exceed impractically tiny caps. Hard-killed incomplete GETs can repeat on resume; consumed caps remain consumed.
- Source files are present for review in the existing checkout; no commit or push has been performed. Environment draft persistence/publication must be reported separately from current-machine validation.

## Reusable environment configuration

`install_script` and `start_skill` were successfully saved to the cloud environment draft. No repository membership, secret requirements or network allowlist were changed. The install script is also at `tools/setup_cloud.sh`; it installs frozen dependencies, explicitly verifies pinned optional release binaries and runs useful checks. Startup uses the existing isolated checkout and CLI, with no daemon and no worktree. Draft save returned `requires_publish: true`: review/save in environment settings and publish to retain the prepared snapshot. Publication and restoration in a new task were not performed or verified by this session.

The exact saved setup script was executed successfully: **61 passed, 1 skipped** in 5.16 seconds. Its optional jsluice test skipped because that script deliberately binds only the installed release Gitleaks path; the separate full-suite command above binds the retained source-built jsluice and passed all **62** tests. This distinction is intentional and recorded rather than treating a skipped integration as passed.

## Debugging and security fixes — 2026-10-13

The entries above describe the initial delivery. This section records the subsequent requested debugging pass.

- [x] Re-ran the original baseline: **62 passed** on Linux/Python 3.12.14.
- [x] Reproduced and fixed path-exclusion bypasses using duplicate/encoded slashes; rejected multicast and other non-unicast public-policy addresses.
- [x] Replaced regex HTTP-method guesses with AST option parsing. Quoted POST, dynamic methods/options, XHR methods and local source-map non-GET routes remain unfetched. A real jsluice probe demonstrated its dynamic-options GET fallback; native restrictions now veto those adapter candidates too.
- [x] Redacted complete/truncated PEM blocks, Bearer/Basic values, short secrets and common environment secret names from routine exports. Report scripts now use an exact SHA-256 CSP allowlist, and Markdown stage details are escaped.
- [x] Rejected symlinks, Windows junctions, hard-linked files, special files, database sidecar links, unsafe artifact paths and inconsistent saved metadata before operating on existing runs. Corrupt databases/metadata produce actionable nonzero CLI errors.
- [x] Bounded doctor output and handled invalid executables; corrected subprocess cleanup for full pipes and POSIX descendants whose parent exited. Windows tool configuration/cache environment variables now point inside the tool working directory.
- [x] Preserved response prefixes at byte caps, distinguished exact-size responses from truncation, and rejected incomplete compressed bodies. HTTP/adapter timeouts respect remaining scan time; exhausted 429/500/502/503/504 retries produce partial coverage.
- [x] Made optional binary publication atomic without replacing matching existing executables; refused unsafe destinations and bounded release reads/extraction. Fixed blank checksum lines and the localhost server's `--port 0` origin.
- [x] Preserved per-artifact jsluice captures and sent newly fetched artifacts through selected offline adapters. Local input reads are bounded regular-file reads. Analyst status and audit-note changes commit together.
- [x] Full expanded suite in `.venv`: **113 passed**, no skips, 5.45 seconds. Command: `RECONMAP_TEST_GITLEAKS=/workspace/tooling/bin/gitleaks RECONMAP_TEST_JSLUICE=/workspace/tooling/bin/jsluice .venv/bin/python -m pytest -q`.
- [x] Repeated the expanded suite in the independent hash-pinned pip environment retained from initial installation, `/workspace/reconmap-install-check/bin/python`: **113 passed**, no skips, 5.62 seconds, with both real offline tool paths supplied.
- [x] `uv pip check --python .venv/bin/python`: all **24** installed packages compatible. `python -m compileall -q src tools` succeeded. These are compatibility/syntax checks, not an external vulnerability-database audit.
- [x] Actual doctor checks passed for the reviewed Subfinder, URLFinder, Gitleaks and jsluice binaries. Unsupported active binaries retain their documented native fallbacks.
- [x] Fresh CLI demo with real Gitleaks, resume, report regeneration, a second collision-safe demo and baseline diff all succeeded. Request counters and baseline database bytes remained unchanged by resume/diff respectively.
- [x] Fresh real standard-mode localhost scan with Gitleaks and jsluice completed: **18 HTTP requests**, every selected stage completed. `tools/lab_server.py --port 0` supplied an actual ephemeral loopback port; the server was stopped afterward.
- [ ] Native Windows/Python 3.13, Windows Ctrl+C/process lifecycle and graphical-browser verification remain unexecuted. Windows symlink tests may skip if the runner lacks creation privileges. No live public target or provider query was run.

New execution policy revision: **2**. Earlier run reports and comparisons remain usable; old queued requests cannot resume after these policy fixes. New runs resume normally. Dependencies and saved cloud setup commands did not change; no deployment, commit, push or publication was performed.

Fresh output locations (earlier runs preserved):

- `/workspace/TheGodRecon/recon-output/debug-validation/example.com/reports/index.html` — offline demo with Gitleaks, resumed and regenerated.
- `/workspace/TheGodRecon/recon-output/debug-validation/1_example.com/reports/index.html` — second offline demo; unchanged comparison in `diff/comparison.json`.
- `/workspace/TheGodRecon/recon-output/debug-validation/127.0.0.1/reports/index.html` — real localhost HTTP + Gitleaks + jsluice run. Its scope is `recon-output/debug-validation/lab.yaml`; the recorded ephemeral server port is no longer listening.

Remaining limitations are those listed above: static inference and pattern redaction do not guarantee complete coverage, raw artifacts remain sensitive, disk caps are not filesystem quotas, and same-account concurrent filesystem tampering is outside the private-run-directory trust model.
