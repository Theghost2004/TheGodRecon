## Summary

Everyday use previously required YAML, repeated tool paths and manual installation steps, with little terminal feedback. Release 3.1.0 adds `reconmap scan HOST`, `--all-tool`, bounded presets, verified bootstrap/setup, persistent discovery, accurate live progress, an optional menu and latest-report access while retaining the existing V3 engine and safety controls.

- Share the existing selection resolver, registry, installer and report interfaces. Preserve advanced CLI forms, YAML compatibility, schema 3, scoring, scope/budgets, collision folders and resume/rerun behavior.
- Install seven pinned official tool releases and optionally build pinned jsluice with source/dependency verification and a local functionality check. Persist path/hash/build provenance separately from registration; reject unknown jsluice fingerprints before running help. Keep Tree-sitter as the verified fallback.
- Report actual stage/engine status and measured counters. Preserve partial coverage, checkpoints and terminal cleanup. Open only verified stopped-run reports; browser failures do not fail scans.
- Simplify README and preserve detailed documentation. Add Linux/PowerShell wrappers and CI bootstrap/CLI checks.

## Validation

- Linux Python 3.12.14: 318 passed, zero failures/skips (15.15s).
- Linux Python 3.13.5: 318 passed, zero failures/skips (15.38s).
- Fresh bootstrap passed in space/Unicode paths; all seven official release binaries and pinned jsluice installed and checked. Repeated setup reused all eight binaries without downloading them again.
- Actual jsluice source build: Go 1.27.2/GCC 14.2.0; local extraction fixture and offline integration passed.
- Controlled localhost: 13 checks, 13 GETs; zero-request resume/rerun, immutable parent. Chromium: 15 report checks, zero browser errors/external requests. Real Linux PTY: 31 redraws, cursor restoration and report prompt passed.
- Frozen uv installation, compilation, Node syntax and Git whitespace checks passed.

## Limits

Native Windows execution/builds/console behavior remain unverified; CI is configured. dnsx/httpx/Katana/Nuclei direct target execution remains policy-blocked. Public provider scans were not performed. No secondary JS analyzer was integrated without an independently verified dependency/containment review. Browser tests used local HTML setContent because managed Chromium blocks file navigation. Full commands, evidence paths and screenshots: docs/V3_1_RELEASE.md.
