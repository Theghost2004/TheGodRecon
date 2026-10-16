God Mode now selects the existing tool pipeline plus bounded evidence-led content discovery, so a full selection can explore useful local dictionaries while explaining exactly what ran and why collection stopped. `--god-mode` and `--full-coverage` share the profile; ordinary scans, `--all-tool`, stored configurations, per-target folders and resume remain compatible.

Setup installs or reuses a SHA-256-verified, pinned SecLists 2026.1 subset (four dictionaries plus license, 237 KB). Scans use local snapshots only. Generated candidates retain provenance and pass through the existing scope/destination policy and HTTP queue. Their persistent allocation is capped at 20% of the global request ceiling, including retries and descendants. Untested dictionary guesses remain inventory instead of flooding manual review.

The change also adds bounded passive/local tool concurrency, HTML-base and sitemap-index handling, depth-preserving JavaScript discovery, native analysis after empty jsluice output, accurate execution/fallback diagnostics, and dedicated report views/exports. Bootstrap repairs an existing virtual environment lacking pip through bundled ensurepip. No schema migration or new runtime dependency is required.

Validation:

- 361 passing tests on Linux Python 3.12 and 3.13, with actual jsluice/Gitleaks offline integration.
- 16 offline/localhost workflow checks; enhanced scan used 18 GETs including 5 discovery requests. Resume/offline rerun added zero target requests.
- Actual pinned SecLists download, repeated setup, ordinary bootstrap, wheel build/import and 17 Chromium checks passed.
- Browser inspection caught and corrected shortlist pollution from dictionary guesses. Regression tests also cover interrupted discovery, depth preservation, installation integrity, failed-spawn accounting and cancellation.

Direct dnsx/httpx/Katana/Nuclei execution remains policy-restricted: enforceable cross-platform egress containment has not been verified. Native alternatives preserve shared scope and budgets. Windows execution and remote CI results are not claimed; the existing Windows/Linux CI matrix includes the new cases. No public-target or provider reconnaissance was performed.

See [God Mode behavior and limitations](https://github.com/Theghost2004/TheGodRecon/blob/feature/god-mode-coverage/docs/GOD_MODE.md), [validation checklist](https://github.com/Theghost2004/TheGodRecon/blob/feature/god-mode-coverage/docs/GOD_MODE_PROGRESS.md), [tool coverage screenshot](https://github.com/Theghost2004/TheGodRecon/blob/feature/god-mode-coverage/docs/images/god-tool-coverage.png), and [wordlist screenshot](https://github.com/Theghost2004/TheGodRecon/blob/feature/god-mode-coverage/docs/images/god-wordlists.png).
