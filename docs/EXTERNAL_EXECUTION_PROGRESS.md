# Contained external execution progress

Branch: `feature/v3.1.1-external-tool-execution`, based on `main` at `edf772a`.

- [x] Audit registry, adapters, strict preflight, scheduler, evidence and reporting.
- [x] Confirm installed reviewed binaries and their supported argument syntax.
- [x] Implement Linux network/PID/filesystem isolation and an HTTP/DNS broker.
- [x] Integrate dnsx, httpx, Katana and reviewed Nuclei templates.
- [x] Require genuine external execution in strict mode; preserve eligible non-strict fallbacks.
- [x] Preserve normalized evidence, graph relationships and resume checkpoints.
- [ ] Exercise scope, budgets, HTTPS, cancellation and partial-output regressions.
- [ ] Execute real binaries in an isolated Linux environment and existing platform CI.
- [ ] Document prerequisites, limitations, verification commands and PR results.

Development uses local fixtures only. This cloud host currently rejects bubblewrap
user-namespace setup (`setting up uid map: Read-only file system`). Runtime probes
must report that failure; it must never trigger an uncontained execution path.
Windows retains native fallback until an equivalent backend is implemented and tested.

Local Linux Python 3.12 regression: **432 passed, 6 skipped** (22.25s), including
real offline Gitleaks/jsluice fixtures. The six skipped cases require the optional
Linux isolation backend. Real active execution has not yet been validated.

CI iteration evidence:

- `c99c6b7`: Linux namespace probes and real dnsx/httpx/Nuclei localhost execution
  completed. Katana failed because its input flag is `-list`, not `-l`; the HTTPS
  adversarial fixture exposed implicit-port reconstruction. Neither failure was
  hidden by fallback (the integration uses strict tools).
- `4a72dc4`: corrected both defects, retained explicit port/case/query identities,
  added a real local TLS proxy regression and improved bounded failure diagnostics.
- CI annotations expose fixture failures because this connection cannot read
  authenticated Actions logs. GitHub API PR creation currently returns Forbidden;
  the branch is pushed and the PR description is prepared locally.

Priority amendment applied: release metadata is now **3.1.1** and the existing
branch was renamed to `feature/v3.1.1-external-tool-execution` (same history; no
duplicate PR). Added isolated real Subfinder/URLFinder fixture integrations.
Kali/Linux execution has priority; the Windows native/core matrix remains intact.
