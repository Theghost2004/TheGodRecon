# Recon V1 — Codex implementation prompt

Use this entire document as the implementation brief. It specifies a new personal reconnaissance tool; it does not authorize scanning any real external target while developing it.

## 1. Objective and working approach

Act as the engineer implementing a usable V1 of a local reconnaissance tool for authorized bug bounty research. Working project and CLI name: reconmap. Check for a naming conflict in the existing repository before settling on that name.

Turn an explicitly scoped web target into a structured asset map, a searchable offline report, and a prioritized queue of investigation leads. Reduce repetitive discovery and analysis without claiming exhaustive coverage or confirmed vulnerabilities from weak evidence.

Inspect the existing repository and its instructions first. Preserve unrelated work. Record a concise implementation plan, assumptions, and milestone status in project documentation. Ask focused questions only when missing information changes authorization, scope, data retention, or an irreversible architectural choice. The defaults in this brief resolve ordinary design choices.

Implement and verify working milestones. Continue through the V1 requirements rather than stopping after a scaffold or a plan. Use localhost fixtures and synthetic tool output during development; external target scans require a separately supplied target and scope. Do not fabricate adapter output, successful tests, tool availability, or scan coverage.

## 2. Product and platform decisions

- A command-line application with an offline, searchable HTML report is the V1 interface.
- Use Python 3.12 or later, a normal pyproject.toml package, a src layout, type annotations, and SQLite.
- Prefer small maintained dependencies: Typer or argparse for CLI, Rich where useful, Pydantic for validated records/configuration, and an appropriate asynchronous HTTP client.
- Support native Linux and native Windows on x86-64 as first-class targets. Document Ubuntu/Debian/Kali setup and PowerShell setup. Check external binary availability separately from Python compatibility.
- Use pathlib, argument-array subprocess execution, and platform-aware process cancellation. Normal execution must not depend on Bash, grep, sed, GNU utilities, sudo, or shell pipelines.
- WSL2 and Docker can be documented alternatives; do not make them mandatory for the native Windows core.
- Treat macOS and ARM64 as additional platforms only where actually verified. Do not claim "runs on any machine" without specifying prerequisites and the tested matrix.
- The runtime must work without an LLM API, paid service, account subscription, or telemetry. Optional provider API keys may improve coverage.
- Keep the architecture small: a Python coordinator, adapters, one database per run, local artifacts, and reporting. Avoid mandatory Redis, Celery, Kubernetes, or a separate database server.

## 3. Scope and scan boundaries

A target seed does not automatically authorize every related domain.

Provide a validated scope configuration supporting exact hostnames, explicit wildcard hostnames, allowed ports and URL/path restrictions, exclusions, selected modules, and request budgets. Exclusions take precedence. Exact host matching is the default. A wildcard such as *.example.com covers its subdomains; include example.com separately if the apex is allowed.

Parse URLs structurally. Normalize hostname case and IDNA representation; retain case-sensitive paths. Reject userinfo and unsupported schemes. Do not use substring matching: example.com.attacker.test must never match example.com.

Every actively requested discovery must pass scope validation, including redirects, JavaScript URLs, source-map URLs, and browser requests. Record external references without automatically fetching them. A shared IP or a CNAME destination does not authorize scanning another hostname or that IP directly.

Deny loopback, private, link-local, and metadata destinations in ordinary public-target mode, including after DNS resolution. A clearly separate localhost lab configuration must permit fixture tests. Handle DNS changes and redirects deliberately rather than checking only the initial input.

For each external tool, verify the scope controls actually available in the installed version. Disable unsafe expansion and automatic redirects when necessary, and handle follow-up requests through controlled code. If an adapter cannot enforce a requested restriction, use a verified bounded fallback or mark that adapter unsupported for that scope. Do not silently weaken scope.

Provide three modes:
- passive: query allowed discovery providers and analyze local material; make no HTTP/TLS requests to the target;
- standard: bounded DNS/HTTP validation, crawling, local content analysis, and the selected basic checks;
- demo: deterministic offline/localhost demonstration without public discovery-provider traffic.

For V1, exclude password guessing, credential stuffing, state-changing form submission, aggressive fuzzing, automatic resource claiming, exploitation, and automatic validation of discovered credentials. Treat logout, purchase, deletion, and similar actions as non-crawl actions. These exclusions are part of the V1 product scope.

## 4. Per-target output folders — mandatory exact behavior

Default output root: ./recon-output, overridable with --output-root.

Use the normalized seed hostname for the directory name. Preserve a real www prefix. Do not use scheme, query, fragment, or URL path in directory names. Keep port/path details in the manifest. One new scan invocation creates one run directory.

Required example:
- First run for example.com: recon-output/example.com/
- Next new run for the same hostname: recon-output/1_example.com/
- Next new run: recon-output/2_example.com/
- Next: recon-output/3_example.com/

The number is a PREFIX, not a suffix.

Choose the smallest positive unused numeric prefix when the unprefixed name is occupied. Treat existing files, directories, and symlinks as occupied names. Never delete, overwrite, or merge an existing run to make room. Use atomic directory creation with collision retries so concurrent starts cannot select the same directory.

Sanitize for Windows and Linux: invalid characters, reserved device names, trailing spaces/dots, Unicode normalization, path length, and path traversal. Preserve the original target in the manifest. Map any non-hostname labels, such as a lab IP, deterministically and safely.

--resume RUN_DIR must reuse an existing valid run directory after checking its manifest and acquiring an exclusive run lock. Resume must not allocate a new numeric prefix. Incompatible scope/tool/config changes must be explained; require a new run when they would invalidate the prior work.

All generated scan output belongs beneath that run directory: database, effective configuration, manifests, tool stdout/stderr, downloaded content, normalized data, findings, reports, screenshots if enabled, checkpoints, temporary scan artifacts, and errors. Tool installations and reusable dependency caches may live outside it, but document their locations. Do not leave target-specific output in the repository or a tool's default home directory.

Suggested run artifacts:

| Path | Purpose |
| --- | --- |
| manifest.json | Run ID, original/normalized target, timestamps, state, schema version |
| config.effective.json | Redacted effective scope and configuration |
| tools.json | Installed versions, capabilities, executable identities, template revision |
| recon.sqlite | Assets, relationships, observations, findings, and job state |
| raw/TOOL/ | Tool records and captured output, with sensitive logging redacted |
| normalized/ | Documented JSONL exports |
| assets/js/ and assets/maps/ | Safely named downloaded analysis inputs |
| evidence/ | Restricted evidence and redacted excerpts |
| logs/ | Human-readable and structured logs |
| checkpoints/ | Durable resumable state |
| reports/index.html | Offline interactive report |
| reports/summary.md | Human-readable summary |
| reports/findings.json and reports/findings.csv | Portable findings exports |
| diff/ | Comparison output when a baseline is selected |
| tmp/ | Bounded temporary scan work |

Content-derived filenames must be hashes or safe generated identifiers. Never write files directly using paths supplied by a target or source map.

## 5. Collection adapters and dependency management

Preferred tools and responsibilities:
- ProjectDiscovery Subfinder: passive hostname discovery.
- ProjectDiscovery URLFinder: passive/historical URL collection. gau may be an optional alternative; avoid duplicate default collection.
- ProjectDiscovery dnsx: DNS observations and wildcard classification.
- ProjectDiscovery httpx: HTTP metadata/fingerprints and optional screenshots.
- ProjectDiscovery Katana: bounded crawling, forms, links, and JavaScript discovery.
- BishopFox jsluice: structured JavaScript endpoint/context extraction.
- Gitleaks: offline secret detection over collected text.
- ProjectDiscovery Nuclei: explicitly selected exposure checks.

Check current official releases, flags, output schemas, licenses, and platform support at implementation time. Do not blindly assume old command examples still work.

Implement typed adapter boundaries: availability, version, capabilities, command construction, execution, parsing, and normalization. Prefer JSON/JSONL. Document meaningful nonzero exit codes, including "findings detected" versus "execution failed." Keep parsing errors visible.

Provide reconmap doctor with a capability table and actionable Windows/Linux installation guidance. Accept executable path overrides. Distinguish the ProjectDiscovery httpx binary from unrelated packages or executables with the same name.

Handle .exe paths, spaces, Unicode paths, executable permissions, timeouts, cancellation, and process-tree cleanup. Never interpolate target-controlled strings into a shell. Avoid administrative privileges and silent global installers. Project-specific virtual environments and user-local verified binaries are preferred.

Keep tested dependency versions in a lock/compatibility manifest; record actual versions per run. Updates must be an explicit maintenance step, not a silent mid-scan action.

A missing tool must produce an explicit degraded/failed module status. Independent stages should still run when useful. --strict-tools should fail preflight when a requested dependency is unavailable.

Provide functioning native core fallbacks for basic HTTP probing, bounded HTML/link/script discovery, and parameter extraction where feasible. JavaScript extraction must have a tested Windows path: use an available jsluice build or a maintained AST parser with supported distribution packages. A regex-only fallback must be labelled reduced coverage and must not masquerade as equivalent parsing. Do not declare native Windows parity without running its tests.

## 6. Discovery, validation, and crawling

Process discovered assets incrementally so useful results appear before the whole scan completes:

1. Collect passive hostnames and historical URLs, with provider provenance and errors.
2. Validate scope and deduplicate scheduling candidates while preserving every observation.
3. Record DNS results, including A/AAAA/CNAME where permitted, and wildcard evidence.
4. Probe permitted HTTP/HTTPS origins. Do not rely on ICMP ping.
5. Record status, title, content type, response size/hash, redirect information, TLS/connectivity outcomes, technology indicators, and timestamps.
6. Crawl bounded links and collect robots/sitemap references where applicable.
7. Extract forms, parameter names, script references, and likely API routes without submitting forms.
8. Analyze collected content locally and schedule permitted newly discovered URLs within the remaining budget.

Keep reachable, restricted, redirected, failed, unresolved, historical-only, and untested states distinct. A 401/403/500 response is not a dead host. A timeout is not proof that an asset does not exist. Distinguish an HTTP 200 soft-404/login shell from a unique page using bounded baseline requests and similarity.

Headless/browser collection is optional in V1 and off by default. If implemented, use isolated browser profiles, bound its network traffic, avoid action clicks/form submissions, and enforce scope for redirects and subresources. Ordinary DOM capture cannot be advertised as complete runtime coverage. Prefer keeping this optional module disabled to offering unenforced scope.

## 7. JavaScript, HTML, source maps, and secrets

Collect external scripts, inline scripts, embedded configuration, comments, and referenced source maps. Hash bodies and analyze identical content once while retaining all source-page relationships.

Extract URLs, methods when present, query/body parameter names, environment references, and relevant source context. Label each endpoint as observed in traffic, fetched successfully, inferred from code, or historical. Retain unresolved expressions as unresolved; do not invent working URLs.

Bound source-map size, decompression, and parsing. Analyze embedded source content without writing untrusted source paths or automatically fetching out-of-scope sources.

Run offline secret detection and store rule identity, source artifact hash, location, redacted excerpt, confidence, and deduplication fingerprint. Mark synthetic examples and likely public configuration appropriately. A variable named apiKey, a public client identifier, or an exposed map is not sufficient proof of a security issue.

Do not contact a credential provider to test a discovered secret in V1. Do not upload target content to an external analysis service.

Preserve useful provenance such as:
application -> page -> JavaScript artifact -> inferred endpoint -> candidate finding.

## 8. Basic checks and finding semantics

Implement a small reviewed Nuclei template allowlist, pinned to an identified revision. Check its actual requests, redirects, protocols, and side effects. Severity labels, signatures, and "info" tags do not establish that a template is suitable for this profile.

The starter checks should cover bounded detection of:
- potentially exposed configuration, source-control metadata, or debug artifacts;
- sensitive information in collected responses;
- directory listings or unintended management surfaces;
- technology-specific non-destructive exposure signatures;
- dangling DNS/service references as candidates;
- API documentation and undocumented routes as reconnaissance leads.

Do not download complete exposed repositories, backups, or large data sets. Capture only enough bounded evidence for the initial lead.

CORS and known-vulnerability indicators require context. Record what was observed and what remains unverified. Keep these separate:
- investigation priority;
- detector confidence;
- assessed severity, which can remain unassessed;
- validation status: informational, candidate, needs manual validation, manually confirmed, or dismissed.

Only an explicit analyst action may set manually confirmed. Store that action and its note.

## 9. Noise reduction and prioritization

Retain original observations. Filtering should affect display and scheduling rather than erase the evidence trail.

Maintain both an original URL and a conservative grouping key. Do not collapse HTTP/HTTPS, meaningful ports, case-sensitive paths, trailing slashes, repeated query keys, or parameter values without evidence. Preserve fragments as client-side route observations where relevant even though they are not sent in HTTP requests.

Group exact and near-duplicate responses, repeated assets, soft errors, and application shells. Similarity is a hint, not proof that different authorization contexts are equivalent.

Deprioritize repetitive static media, analytics, and duplicated informational pages. Keep restricted routes, JavaScript, source maps, API routes, and interesting historical paths.

Use a simple documented scoring policy with explicit reasons. Useful factors include novelty, unique application content, current evidence, sensitive functionality such as account/invitation/upload/import/export routes, and multiple independent supporting observations. Avoid presenting a priority score as an exploit probability.

## 10. Budgets, reliability, and resumability

Proposed conservative defaults, all configurable and subordinate to target rules:
- maximum 2 target HTTP requests/second/host;
- maximum 10 target HTTP requests/second overall;
- crawl depth 2;
- maximum 500 fetched URLs/host;
- maximum 5,000 target HTTP requests/run;
- 15-second request timeout and at most one retry;
- 10 MiB maximum response body and 1 GiB scan-artifact budget;
- 30-minute run time budget.

Treat these as ceilings, not throughput goals. Separate DNS/provider budgets from target HTTP budgets. Honor Retry-After and back off on throttling and repeated service errors. Record every cap reached as incomplete coverage.

Use shared scheduling for application-owned requests. Account for subprocess traffic and browser subrequests; independent per-tool rate flags do not automatically create a global limit. Serialize active adapters or partition their budgets when necessary. If a tool cannot enforce a requested limit, use a bounded fallback or disable that mode with an explicit reason. Do not describe estimated counts as measured request totals.

Persist job and stage state transactionally. Support cancellation with final checkpoints and a readable partial report. Resume without duplicating observations or rerunning completed unchanged work unnecessarily. One failed provider or missing binary must not erase successful output.

Cache expensive local analysis by content hash. Fresh runs must still revalidate liveness; an unchanged cached asset is not permanent proof of current behavior.

## 11. Database, history, and comparisons

Design a versioned SQLite schema containing runs, scope/config snapshots, hosts, DNS observations, origins/services, URLs, parameters, artifacts, relationships, findings, stage outcomes, and jobs/checkpoints.

Use stable normalized identities plus separate timestamped observations. Keep source provenance, parser/tool versions, evidence locations, and confidence. Use parameterized queries and explicit migrations.

A new run gets its own directory and database. --baseline RUN_DIR and a diff command compare compatible snapshots without modifying the older run.

Highlight new/changed assets, endpoints, content hashes, findings, and access behavior. Separate "not observed this time" from "confirmed unavailable"; different scope, missing providers, timeouts, and scan caps can explain apparent disappearances.

## 12. Reporting, local data handling, and CLI

Build an offline HTML report with embedded/bundled assets and no external CDN dependencies. It must open from disk and offer search/filtering for hosts, routes, statuses, findings, priority, confidence, source, and changes.

Include:
- scan overview and effective scope;
- module successes, failures, skipped work, and coverage limits;
- grouped applications and an expandable relationship view;
- prioritized leads with evidence and next manual checks;
- artifact/source links and scan statistics;
- comparison results when requested.

Provide HTML, Markdown, JSON/JSONL, and CSV exports. Produce reports even for a zero-finding or interrupted scan.

Treat all scanned content as hostile data. Escape HTML and embedded JSON, prevent stored script execution and unsafe URL schemes, neutralize spreadsheet formula injection in CSV, and avoid loading target pages/resources automatically from a report.

Keep provider credentials in environment variables or excluded local configuration. Never record them in effective configs, ordinary logs, command histories, or reports. Redact discovered credentials in routine output. Raw downloaded analysis inputs remain local restricted artifacts with documented retention and platform-appropriate access controls; clearly distinguish them from shareable redacted reports.

Provide these commands or an equally clear equivalent:

    reconmap doctor
    reconmap init --target example.com --config scope.yaml
    reconmap scan --target example.com --config scope.yaml --output-root ./recon-output --mode standard
    reconmap scan --target example.com --config scope.yaml --mode passive
    reconmap scan --resume ./recon-output/example.com
    reconmap report --run ./recon-output/example.com
    reconmap diff --baseline ./recon-output/example.com --current ./recon-output/1_example.com
    reconmap demo --output-root ./recon-output

init writes an editable scope configuration; it must not silently include all subdomains. Show a concise effective scope and budget summary at scan start. An explicit scan command with valid configuration may proceed without repeated interactive confirmations. Never expand permissions to finish a stage.

Document exit codes for success, partial completion, configuration errors, dependency errors, and interruption.

## 13. Verification and acceptance criteria

Add meaningful tests for behavior that can lose data, exceed scope, mislead the analyst, or break cross-platform execution:

- Directory sequence example.com, 1_example.com, 2_example.com; concurrent allocation; existing files/symlinks; invalid names; no overwrite.
- Resume locking, valid manifests, interrupted writes, scope/config compatibility.
- Exact/wildcard scope, exclusions, IDNA, deceptive suffixes, ports, paths, redirects, and private-IP handling.
- URL grouping preserving semantically different requests.
- Adapter argument construction and parsing, version differences, finding exit codes, missing binaries, malformed output, timeouts, and cancellation.
- Budget enforcement and throttling behavior.
- Local test pages with a soft-404, a 403, redirects, duplicate JS, inferred endpoints, embedded configuration, and synthetic secret fixtures.
- Secret redaction, report HTML/JSON escaping, path traversal, and CSV formula handling.
- Diff behavior when current coverage is incomplete.
- A complete demo run that creates its folder, database, exports, and report.

Create a CI matrix for Linux and Windows covering installation, core tests, CLI smoke tests, and demo behavior. Add real external-binary smoke/integration checks against localhost for the supported pinned tool/platform combinations where feasible; fake-adapter tests alone do not establish native compatibility.

Report exactly which checks actually ran. A proposed CI workflow or simulated Windows path test is not a successful Windows execution. If an OS runner or tool is unavailable, record that limitation and provide a repeatable command.

## 14. Implementation milestones and delivery

Milestone 1: package, CLI, validated configuration, scope policy, atomic run folders, database, and doctor.
Milestone 2: adapters, bounded discovery/probing/crawling, provenance, and partial-failure handling.
Milestone 3: local JS/source-map/secret analysis, reviewed basic checks, ranking, and correlation.
Milestone 4: offline reports, exports, resume, comparisons, and deterministic demo.
Milestone 5: Windows/Linux verification, dependency documentation, and final review.

Keep a progress checklist so work can continue across sessions. Complete real vertical slices and verify each before expanding. Do not leave user-facing placeholder functions presented as completed features.

Deliver source, dependency locks, example configuration, supported-tool manifest, tests, CI configuration, Windows and Linux setup instructions, architecture notes, a demo report, and a concise list of remaining limitations.

At the end, explain how to install, run doctor, edit scope, run the localhost demo, start an authorized scan, resume it, and find the numbered output folders. Report test evidence and any platform differences honestly.

## Official tool references

Verify current behavior against these upstream projects:
- https://github.com/projectdiscovery/subfinder
- https://github.com/projectdiscovery/urlfinder
- https://github.com/projectdiscovery/dnsx
- https://github.com/projectdiscovery/httpx
- https://github.com/projectdiscovery/katana
- https://github.com/BishopFox/jsluice
- https://github.com/gitleaks/gitleaks
- https://github.com/projectdiscovery/nuclei
- https://github.com/projectdiscovery/nuclei-templates
- https://github.com/lc/gau

Begin by inspecting the workspace and stating the short implementation plan and material assumptions. Then implement the V1 described above.
