## Summary

A complete reconnaissance selection previously required overlapping flags and produced an investigation report without a durable application relationship map. This change adds `reconmap blackbox TARGET` to the existing engine, selecting all eight capabilities, local wordlists, evidence correlation, the existing report and five graph exports. `scan` remains customizable and now gates native fallbacks by the actual selected capability.

For example, `scan TARGET --tools httpx,katana` captures/crawls authorized HTTP without silently analyzing secrets or JavaScript. Selecting Katana without HTTP collection produces a clear missing-prerequisite coverage result rather than enabling unselected HTTP work. `--god-mode` and `--full-coverage` map to the shared BlackBox profile; all-tool and deep retain their narrower existing meanings.

## Implementation

- Add tool exclusions, native execution preferences, reviewed provider-source selection, export preferences, automatic/manual dictionary selection and exclusions. Explicit manual lists replace automatic choices and remain under the existing shared discovery budget.
- Preserve source response hashes and JavaScript source URL contexts. Add informational environment diagnostics and selected/unselected execution, JS and input accounting.
- Add SQLite migration 3→4 for derived graph nodes/edges. Request identity preserves URL case, explicit ports, repeated/query values, methods and authorization context. Structural path groups, observed links, redirects, historical records and static inference remain distinct.
- Export endpoint text, JSON, Graphviz DOT, summary and a standalone paginated map with offline CSP, safe text rendering and no target-resource loads. Existing report rankings and analyst states remain authoritative.
- Print report/tree/map paths and retain outputs for partial/interrupted/resumed runs. Keep package version 3.1.0 and old configuration digests.

This branch includes the preceding God Mode/SecLists infrastructure commits because they are not yet on main. The BlackBox-specific change is isolated in its own commit and documented in `docs/BLACKBOX.md` and `docs/BLACKBOX_PROGRESS.md`.

## Validation performed

- Linux Python 3.12.14: **395 passed**, zero skips, with verified real jsluice and Gitleaks integration tests.
- Linux Python 3.13.5: **395 passed**, zero skips, with the same offline integrations.
- Controlled localhost workflow: **21 checks passed**, covering custom/BlackBox selection, scope/method/redirect restrictions, ranking, provenance, partial budgets, immutable reruns and request reuse.
- Chromium: **18 report checks + 10 asset-map checks**, zero browser errors and zero external requests. Includes empty partial reports, map pagination, relationship navigation, filters, hostile text rendering and mobile layout.
- Graphviz parsed fixture and adversarial-label DOT exports; 2,000-request graph and deep-prefix bounds exercised.
- Wheel built as 3.1.0 with graph/environment/schema modules and pinned SecLists manifest; dependency checks passed.
- Committed controlled-fixture graph exports and screenshots under `docs/examples/blackbox` and `docs/images`.

## Limits and review focus

Direct dnsx/httpx/Katana/Nuclei remain policy restricted; no verified cross-platform egress/request broker exists. Their native alternatives remain the actual engines. Subfinder/URLFinder provider execution was not tested against public providers. SecLists download/recovery tests use mocked official-source fixtures; this upgrade retains the reviewed subset installer. No target scope, request budget or method restriction was relaxed.

Windows-specific path/fallback tests ran on Linux, but native Windows execution still requires the existing Windows CI/manual run. The map pages its DOM while loading the full graph JSON in memory. Prefix groups are capped at 64 levels per URL; original endpoints remain intact. Derived graph exports do not represent complete application coverage, and inferred/historical references do not imply reachability or vulnerability.
