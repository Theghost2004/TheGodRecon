# CODEX IMPLEMENTATION REQUEST — THEGODRECON V2

## Role and mission

Act as a senior Python software architect, application security engineer, and security-tooling developer.

You are working directly in my existing GitHub repository:

**Repository:** `Theghost2004/TheGodRecon`
**Branch:** `main`
**Existing package:** `src/reconmap`
**Existing CLI:** `reconmap`
**Supported Python:** 3.12+

Your task is to upgrade the existing application into **TheGodRecon V2: a modular, configurable, security-conscious reconnaissance orchestration platform**.

This is an implementation task, not a request for a design proposal.

Inspect the actual repository, implement the changes, add tests, update documentation, and prepare the work for review in GitHub.

Do not replace the current project with an unrelated implementation.

### Primary objectives

1. Integrate all eight previously identified reconnaissance tools into the execution framework.
2. Support individual, combined, preset, and full-tool execution through an intuitive numbered CLI.
3. Implement ASN/IP enrichment, Wayback Machine URL collection, technology fingerprinting, URL deduplication/parameter grouping, and intelligent endpoint prioritization.
4. Introduce a reliable workflow for rerunning selected tools.
5. Preserve and improve the existing project's scope restrictions, request controls, evidence integrity, data protection, resumability, and cross-platform compatibility.
6. Make execution efficient, observable, deterministic where possible, and resistant to unnecessary duplicate work.
7. Deliver working implementations, not fake adapters, placeholder outputs, or documentation-only promises.

**Most important constraint: do not sacrifice security to achieve feature completeness.**

If a requested external tool cannot be executed without violating mandatory controls, fail closed, report the exact reason, and preserve the functioning native implementation.

---

# 1. Inspect the existing repository first

Read and understand these files before modifying implementation:

- `src/reconmap/cli.py`
- `src/reconmap/config.py`
- `src/reconmap/scope.py`
- `src/reconmap/engine.py`
- `src/reconmap/adapters.py`
- `src/reconmap/dnschecks.py`
- `src/reconmap/analysis.py`
- `src/reconmap/storage.py`
- `src/reconmap/security.py`
- `src/reconmap/reporting.py`
- `tools/install_tools.py`
- `compatibility.json`
- `docs/ARCHITECTURE.md`
- `docs/TOOLS.md`
- `README.md`
- `PROGRESS.md`
- All relevant tests.

Identify the features already implemented and reuse them.

The current application provides:

- Explicit YAML scope restrictions.
- Native DNS and HTTP collection.
- Controlled crawling and static JavaScript analysis.
- SQLite persistence.
- Immutable, uniquely named scan directories.
- Interrupted-run recovery.
- Source and evidence relationships.
- Offline HTML, CSV, JSON and Markdown reports.
- Selected external tool integrations.
- Tool compatibility checking.
- Conservative network restrictions.
- Security regression tests.

Preserve these guarantees.

Do not change existing public CLI behavior unnecessarily.

Use small, focused modules instead of expanding `engine.py` or `cli.py` into oversized files.

---

# 2. Integrate all eight external reconnaissance tools

Create a central tool registry with the following permanent numerical identifiers.

| ID | Tool | Primary responsibility |
|---|---|---|
| 1 | Subfinder | Passive subdomain discovery |
| 2 | URLFinder | Historical URL discovery |
| 3 | dnsx | DNS resolution and record enrichment |
| 4 | ProjectDiscovery httpx | HTTP probing and service metadata |
| 5 | Katana | Bounded web crawling and URL discovery |
| 6 | jsluice | Offline JavaScript analysis |
| 7 | Gitleaks | Offline secret-pattern detection |
| 8 | Nuclei | Restricted, reviewed exposure checks |

Do not change these IDs between program versions.

### Requirements for every adapter

Each tool integration must provide:

- Stable numerical ID and canonical name.
- Capability and execution-risk classification.
- Binary discovery and explicit executable-path override.
- Compatible version/feature verification.
- A reviewed command builder appropriate to the installed version.
- Input validation and scope validation.
- Timeout and resource controls.
- Structured output parsing.
- Safe stdout/stderr handling.
- Normalized result storage.
- Clear execution status.
- Cancellation and process-tree cleanup.
- Unit and integration tests.
- Provenance linking results to their originating tool.

Use argument-vector subprocess execution rather than interpolated shell commands.

Avoid `shell=True`.

Do not assume that CLI flags or JSON schemas remain compatible between tool versions. Verify reviewed versions against official documentation and observed help output.

Do not silently execute a different version when compatibility has not been verified.

### Important distinction

The existing project intentionally disables direct execution of dnsx, httpx, Katana and Nuclei because of security-control limitations.

V2 must investigate and implement safe direct execution paths where feasible.

These external tools can send independent network requests. Filtering their results *after execution* is not sufficient to enforce request-time scope restrictions.

For direct execution, demonstrate controls equivalent to the native engine's guarantees, including destination restrictions, request scope, and enforceable limits.

Use a properly implemented network mediation or isolation mechanism where necessary and feasible. A filtering proxy that cannot inspect HTTPS paths must not be described as enforcing path-level exclusions.

When enforcement cannot be demonstrated, block that direct execution mode and report why. Do not silently bypass controls or pretend the external binary executed.

Preserve native implementations as working alternatives.

### Tool-specific requirements

**1. Subfinder**

Use reviewed passive providers only. Preserve configured provider allowlists, rate controls, source attribution, and strict filtering of discovered hosts.

**2. URLFinder**

Collect historical URLs using reviewed sources. Normalize and scope-filter results before making them eligible for active HTTP requests.

**3. dnsx**

Integrate DNS records and resolution observations while preventing unapproved network expansion. Preserve DNS query budgets and destination protections. Do not automatically follow CNAME targets as authorized assets.

**4. httpx**

Support limited HTTP probing with structured metadata. Retain the native engine's protected request path whenever direct execution cannot satisfy the same scope and resource policy.

**5. Katana**

Support bounded, non-headless crawling with conservative settings. Disable automatic form submission, headless browser execution, authentication automation, unsafe JavaScript actions, and uncontrolled crawl expansion.

**6. jsluice**

Run against captured local JavaScript artifacts. Preserve the existing native Tree-sitter implementation, deduplicate artifacts by content hash, and record unresolved expressions accurately.

**7. Gitleaks**

Run only against authorized local artifacts. Do not perform repository credential verification or automatically test discovered tokens. Preserve redaction and restricted raw evidence handling.

**8. Nuclei**

Initially permit only the two existing reviewed exposure templates or equivalent reviewed GET-only checks.

Do not automatically download or run the entire upstream Nuclei template library.

Disable OAST/Interactsh, code execution, destructive templates, fuzzing, credential checks, payload workflows, network exploits and automatic template updates during scans.

Require explicit review before adding further templates.

Direct Nuclei execution must satisfy the same destination, scope, method and budget guarantees. Otherwise mark it blocked and use the existing native reviewed checks.

**Definition of successful integration:** an actual binary runs when the selected mode is supported and the safety requirements are enforceable. Merely registering a tool name is insufficient.

---

# 3. Implement a numbered and customizable CLI

I want fast execution selection without repeatedly editing YAML files.

Create a centralized parser and registry for tool selection.

### Supported commands

Use the following syntax:

    reconmap tools list

Display a readable table containing tool ID, name, capability, version, availability, execution support, and status.

Allow one tool:

    reconmap scan --target authorized.example --config scope.yaml --tools 1

Allow multiple tools:

    reconmap scan --target authorized.example --config scope.yaml --tools 1,2,3

Allow a range:

    reconmap scan --target authorized.example --config scope.yaml --tools 1-4

Allow arbitrary combinations:

    reconmap scan --target authorized.example --config scope.yaml --tools 1,3,5,7

Allow every tool:

    reconmap scan --target authorized.example --config scope.yaml --tools all

Allow presets:

    reconmap scan --target authorized.example --config scope.yaml --tools quad

Define `quad` as the first four registered tools, IDs 1–4.

Also support named presets:

- `passive`: IDs 1 and 2.
- `offline`: IDs 6 and 7.
- `web`: IDs 4 and 5.
- `all`: IDs 1 through 8.

These presets are selection shortcuts, not exemptions from execution restrictions.

For user convenience, optionally accept `1+2+3` as an additional expression, but document comma-separated IDs as the canonical syntax.

Do not introduce unusual one-dash flags such as `-1+2+3` or `-all`.

### Parser behavior

The parser must:

- Reject unknown tool IDs.
- Reject malformed ranges.
- Remove duplicates while preserving deterministic execution order.
- Support tool names as alternatives to IDs.
- Display helpful usage messages.
- Handle unavailable tools explicitly.
- Support `--strict-tools` for preflight failure.
- Never interpret target-supplied strings as shell commands.
- Preserve the existing `--tool NAME=PATH` executable override.
- Preserve existing `--modules` usage.

**Important:** `--tools` selects tools. The existing singular `--tool` continues to specify binary path overrides. Do not create an ambiguous collision.

Implement a clean compatibility layer between the new registry, legacy module settings and existing YAML configurations.

### Explain and preview execution

Add:

    reconmap plan --target authorized.example --config scope.yaml --tools all

This command should print the effective plan without scanning.

It must show:

- Selected tools.
- Execution order.
- Required dependencies.
- Requested enrichment stages.
- Scope boundaries.
- Network-active versus passive versus offline stages.
- Effective budgets.
- Unsupported or missing integrations.
- Whether the operation is safe to execute.

Optionally support `--json`.

A plan command must not send target requests.

---

# 4. Introduce an improved execution pipeline

Do not simply launch all eight tools simultaneously.

Implement an explicit dependency-aware orchestration graph.

Recommended logical stages:

**Stage A — Passive asset discovery**

- Subfinder.
- URLFinder.
- Wayback historical URL collection.
- ASN/IP intelligence enrichment.

**Stage B — DNS enrichment**

- dnsx when safely supported.
- Otherwise native DNS handling.

**Stage C — HTTP discovery**

- httpx when safely supported.
- Otherwise native HTTP probing.

**Stage D — Crawling**

- Katana when safely supported.
- Otherwise native crawling.

**Stage E — Offline analysis**

- Existing JavaScript analysis.
- jsluice.
- Gitleaks.
- Technology fingerprinting.
- Parameter extraction.

**Stage F — Exposure checks**

- Restricted Nuclei checks where safely executable.
- Existing native checks.

**Stage G — Normalization and reporting**

- Cross-tool deduplication.
- Endpoint classification.
- Prioritization.
- Persistence.
- Report generation.

Dependencies must be explicit.

For example, downstream HTTP scanning should not run against arbitrary unvalidated results returned by a passive source.

Do not run multiple network-active scanners against the same targets concurrently if that prevents enforcing shared request limits.

A single selected tool should not unexpectedly trigger other external tools. Internal parsing, validation, persistence and safety dependencies may run automatically.

If a selected tool needs input not yet available, provide an actionable diagnostic or use already validated data from the run.

### Performance requirements

- Cache normalized passive discovery results where appropriate.
- Deduplicate work before expensive stages.
- Avoid repeated HTTP requests when valid compatible evidence already exists.
- Use bounded producer-consumer queues.
- Use explicit stage dependencies.
- Preserve global and per-host budgets.
- Persist completed stage state.
- Honor HTTP 429 responses and retry hints conservatively.
- Use bounded exponential backoff for transient failures.
- Stop when scan budgets are exhausted.
- Cancel child processes reliably.
- Generate useful partial reports on interruption.

Do not optimize performance by weakening scope controls.

---

# 5. Add ASN and IP intelligence enrichment

Create a dedicated enrichment module.

Goals:

- Associate authorized discovered hosts with observed public IP addresses.
- Collect ASN numbers and AS organization information when trustworthy sources are available.
- Identify hosting/cloud-provider evidence.
- Preserve IPv4 and IPv6 information.
- Group discovered assets by observed infrastructure.
- Record data source and collection timestamp.
- Cache results with configurable expiry.
- Distinguish verified DNS observations from passive intelligence.

Do not automatically expand the scan scope to all IP addresses or CIDR ranges belonging to an ASN.

An ASN relationship is intelligence, not authorization.

Never scan unrelated addresses merely because they share a provider or network.

Use bounded, documented and reviewed data sources. If a provider is unavailable, record the enrichment stage as incomplete rather than fabricating data.

---

# 6. Add Wayback Machine URL discovery

Create a dedicated, optional historical URL adapter.

Requirements:

- Use a documented Internet Archive/CDX interface when available.
- Respect remote service rate limits.
- Apply bounded pagination and output caps.
- Support cancellation.
- Cache retrieved metadata where appropriate.
- Normalize returned URLs.
- Preserve original historical URLs and timestamps.
- Strictly distinguish historical discovery from current liveness.
- Drop out-of-scope candidates from active scheduling.
- Preserve safe metadata indicating excluded records.
- Avoid automatic downloading of archived sensitive content.

Do not assume that an archived endpoint still exists.

Historical results should only enter active probing after passing the exact scope and scheduler checks.

Report historical provenance independently from current HTTP observations.

---

# 7. Implement technology fingerprinting

Build a lightweight, explainable fingerprinting stage.

Start by analyzing already collected HTTP responses and local artifacts.

Possible evidence sources include:

- HTTP headers.
- Cookies and their names.
- HTML metadata.
- Script references.
- Known framework-specific response signatures.
- Recognizable JavaScript bundle markers.
- Existing captured content.

Record results with confidence levels:

- High.
- Medium.
- Low.
- Unknown.

Do not confidently identify a specific software version from weak evidence.

Do not introduce uncontrolled new HTTP requests merely to improve fingerprinting.

Technology detection must never automatically become CVE exploitation or vulnerability confirmation.

Provide filterable technology data in offline reports.

---

# 8. Implement URL deduplication and parameter grouping

This should become a major optimization feature.

There are two different problems to solve:

**Exact deduplication:** identical normalized requests discovered by different tools.

**Semantic grouping:** structurally similar URLs that may represent the same endpoint family.

Examples:

    /api/users/123
    /api/users/456

They may belong to the same route family.

Likewise:

    /search?q=hello
    /search?q=world

They may share a parameter structure.

But do not automatically assume different parameter values always produce equivalent behavior.

### Implementation requirements

- Maintain original raw URLs.
- Maintain conservative canonical URL identities.
- Group URLs by host, path structure and parameter-name signatures.
- Preserve HTTP methods where known.
- Preserve parameter location.
- Preserve parameter names and source references.
- Retain evidence from every discovery source.
- Support configurable grouping rules.
- Use conservative handling of case, encoding, path separators and query parameters.
- Avoid merging URLs with materially different security behavior.
- Do not discard data required for later manual review.

Use grouping to reduce repeated scheduling and report noise, not to destroy evidence.

Generate useful outputs for:

- Exact URLs.
- Parameterized URLs.
- Route families.
- Duplicate candidates.
- Source relationships.
- Endpoint coverage.

Distinguish scheduling deduplication from the analytical grouping layer.

---

# 9. Implement intelligent endpoint prioritization

Build an explainable rule-based prioritization system.

No paid AI API or language model should be required.

The goal is not to claim vulnerability severity, but to help the researcher decide which endpoints to review first.

Potential groups:

- Authentication and identity.
- Authorization-related routes.
- Account and profile management.
- Administrative interfaces.
- APIs and GraphQL.
- File upload/download functionality.
- Payment-related functionality.
- Debug and development interfaces.
- Documentation and schema endpoints.
- JavaScript-derived routes.
- Static assets.
- Low-information duplicate routes.

Use multiple factors such as:

- Route type.
- HTTP observations.
- Source provenance.
- Number of independent discovery sources.
- Technology context.
- Parameter structure.
- Existing finding evidence.
- Prior observations.
- Analyst configuration.

Define an explainable score on a 0–100 scale.

Scores must have documented reasoning and separate evidence confidence.

Do not automatically label high-priority endpoints as vulnerabilities.

Do not treat guessed paths as verified reachable endpoints.

Make scoring weights configurable, versioned and testable.

Preserve all discovered evidence. Lower-priority results may be hidden from the default dashboard, but must remain available.

Avoid making a path high-priority merely because its name contains a sensitive-looking word.

---

# 10. Implement safe reruns and incremental workflows

Introduce a dedicated command:

    reconmap rerun --from ./recon-output/authorized.example --tools 6,7

Additional examples:

    reconmap rerun --from ./recon-output/authorized.example --tools 4,5

    reconmap rerun --from ./recon-output/authorized.example --tools all

### Required behavior

Make `rerun` different from `resume`.

**Resume** continues an interrupted run under the same persisted configuration, identity and remaining budgets.

**Rerun** creates a new, separately identifiable execution.

The original run must remain unchanged.

Support two types of rerun:

1. Offline reanalysis of valid, stored artifacts.
2. Fresh authorized recollection for selected network-active stages.

For offline reruns, reuse existing validated evidence without contacting target hosts.

For active reruns, revalidate the current scope and use a new run identity, budgets, locks and checkpoints.

Do not treat previously collected artifacts as granting new network authorization.

### Output directories

Preserve the existing non-overwriting naming convention:

    recon-output/
      authorized.example/
      1_authorized.example/
      2_authorized.example/

Add structured lineage metadata recording:

- Parent run ID.
- Rerun ID.
- Selected tools.
- Configuration digest.
- Execution timestamp.
- Reused artifact hashes.
- Newly collected evidence.
- Tool versions.
- Changed findings.
- Stage completion information.

Never overwrite original raw evidence or manually recorded analyst decisions.

Do not force reruns just to regenerate a report; preserve the existing report command for that purpose.

---

# 11. Introduce execution profiles and enrichment selection

Keep existing default behavior as compatible as practical.

Add these conceptual profiles:

**standard**

Conservative existing native reconnaissance workflow.

**passive**

Authorized passive discovery with no target HTTP requests.

**offline**

Local artifact analysis only.

**full**

All eight registered external tools plus the five new enrichment capabilities, subject to strict capability preflight and enforceable security restrictions.

Support:

    reconmap scan --target authorized.example --config scope.yaml --profile full

And an explicit equivalent:

    reconmap scan --target authorized.example --config scope.yaml --tools all --enrich all

For custom runs, support named enrichment selection:

    --enrich asn,wayback,tech,dedup,priority

Allow `--enrich none`.

Offline enhancements should not secretly enable network access.

Enrichments requiring third-party network access must run only when explicitly selected by a profile or enrichment setting.

Define precedence between CLI selections, profiles and YAML configuration. Document it and reject ambiguous contradictory combinations.

All active execution modes must remain inside the same authorization policy.

---

# 12. Non-negotiable security requirements

Preserve the security posture described in `docs/ARCHITECTURE.md`.

### Scope and destination safety

- Require explicit authorization represented by user-provided scope configuration.
- Preserve exact and wildcard hostname rules.
- Preserve host exclusions, path exclusions, schemes and ports.
- Preserve case-sensitive path rules and traversal protections.
- Validate destinations before connections.
- Prevent DNS rebinding and unsafe IP transitions.
- Reject out-of-scope redirects before following them.
- Keep ordinary target scanning separate from provider API access.
- Preserve loopback-only lab mode.
- Prevent private, loopback, link-local, multicast and reserved network access during normal scans.
- Never interpret ASN ownership, historical URLs, passive discovery or CNAME references as new authorization.

No external scanner is exempt.

### Request safety

- Preserve GET-only target-request policy for the standard safe execution path.
- Do not submit forms.
- Do not perform credential spraying, login attempts or brute forcing.
- Do not perform exploitation or resource claiming.
- Do not enable automatic headless browser interactions.
- Do not enable general Nuclei fuzzing or exploit templates.
- Preserve known non-crawl action exclusions.
- Require manual exclusions for application-specific GET routes with side effects.
- No automatic vulnerability confirmation.

### Shared resource enforcement

The current native scheduler owns request budgets.

External active tools may not automatically inherit those controls.

For every direct execution path, document which guarantees are enforceable and how.

Do not claim aggregate request-count enforcement if a subprocess's requests cannot be measured accurately.

Do not claim private-IP exclusion based solely on a pre-scan DNS check if the subprocess can resolve or connect independently afterward.

Do not claim path-exclusion enforcement based solely on post-processing output.

If mandatory guarantees cannot be enforced, block that mode.

Avoid adding a bypass such as `--unsafe`, `--ignore-scope`, `--no-guardrails` or similarly broad overrides.

### Secrets and evidence

- Preserve restricted raw artifacts.
- Redact credentials and sensitive values from reports and routine logs.
- Do not upload raw evidence to external services.
- Prevent stored HTML/JSON/CSV injection.
- Prevent filesystem traversal and symbolic-link redirection.
- Keep local tool execution directories isolated.
- Do not echo secrets in CLI diagnostics.
- Do not send discovered secrets to validation services.
- Preserve local-only operation unless explicitly configured external providers are needed.

### Dependencies and updates

- No silent downloads during scans.
- No automatic external tool updates.
- Pin and verify supported external binaries.
- Preserve executable identity in run metadata.
- Refuse unknown or incompatible versions by default.
- Keep tool installation separate from target scan execution.
- Preserve Windows and Linux safeguards.

### Failure policy

Use explicit statuses such as:

- completed
- skipped
- unavailable
- incompatible
- blocked-by-policy
- partial
- failed
- interrupted

Never report an unexecuted tool as successful.

A partial run must remain inspectable.

---

# 13. Improve architecture without unnecessary rewriting

You may introduce modules such as:

    src/reconmap/
      tool_registry.py
      selectors.py
      orchestrator.py
      enrichment/
        asn.py
        wayback.py
        technology.py
        grouping.py
        prioritization.py
      integrations/
        subfinder.py
        urlfinder.py
        dnsx.py
        httpx.py
        katana.py
        jsluice.py
        gitleaks.py
        nuclei.py

This structure is a recommendation, not a requirement to rewrite existing functional modules.

Reuse `adapters.py`, `scope.py`, `engine.py`, `storage.py` and `reporting.py` where appropriate.

Do not create redundant abstraction layers merely to match this example tree.

### Data storage

Extend the existing SQLite database carefully.

Record:

- Tool execution identity and status.
- Adapter version and executable hash.
- Tool-specific structured observations.
- Enrichment provenance.
- Historical URL evidence.
- Technology fingerprints.
- URL groups.
- Priority explanations.
- Rerun ancestry.
- Stage metrics.
- Errors and degraded execution reasons.

Use explicit versioned schema migrations.

Do not break readability of existing V1 databases.

Do not destructively migrate V1 data.

Preserve existing run reports and comparisons where practical.

### Reporting

Improve the offline dashboard to include:

- Scan overview.
- Tool execution status.
- Discovered hosts and IPs.
- ASN grouping.
- Historical URLs.
- HTTP service observations.
- Technology fingerprints.
- API/route groups.
- Prioritized endpoints.
- Candidate exposure findings.
- Stage warnings and missing coverage.
- Rerun comparison and provenance.

Use searchable, filterable views.

Clearly distinguish:

- discovered
- verified reachable
- historical only
- restricted
- unresolved
- candidate finding
- manually confirmed

Keep local reports self-contained.

Do not include live remote scripts or tracking.

---

# 14. Tool installation and cross-platform support

Improve the optional tool installation and verification workflow.

Target platforms:

- Kali Linux.
- Ubuntu/Debian Linux.
- Windows 10/11 PowerShell.

Python 3.12+ remains the baseline.

A clean user installation must not require root permissions for the core package or local user-owned tool binaries.

Extend the existing checksum-verifying installer only where official, verifiable distribution artifacts are available.

Support explicit executable-path configuration.

Do not fabricate checksum values or silently download arbitrary releases.

For tools requiring native compilation, document tested and untested build paths and allow manual installation.

A useful command would be:

    reconmap tools doctor

It should show installation, compatible version, supported operating system, and execution-policy status for every tool.

Never imply Windows compatibility solely because a binary compiles on Linux.

Avoid Docker or WSL as mandatory dependencies for the core application.

If a specific guarded external execution method requires an unsupported platform capability, mark it unsupported on that platform rather than reducing protections.

---

# 15. Tests and verification

Expand the existing pytest suite.

All security-sensitive features require tests.

### CLI tests

Test:

- Single tool selection.
- Multiple IDs.
- Ranges.
- Presets.
- Unknown IDs.
- Duplicate IDs.
- Invalid syntax.
- Existing `--tool NAME=PATH` compatibility.
- Profile and YAML precedence.
- Strict tool preflight.
- `plan` producing no target requests.

### Integration tests

Use synthetic binaries, local fixtures and loopback HTTP servers.

Test:

- Structured tool-output parsing.
- Missing executables.
- Version mismatch.
- Invalid subprocess output.
- Tool timeout.
- Process-tree termination.
- Missing dependencies.
- Partial execution.
- Interrupted runs.
- Tool status persistence.
- Per-tool output provenance.

Use actual external binaries in separate optional integration tests when they are available.

Do not claim a tool has been execution-tested merely because a fake binary test passed.

### Security regression tests

Specifically test:

- Out-of-scope subdomains.
- Out-of-scope redirect targets.
- CNAME references outside scope.
- Private-address DNS resolutions.
- DNS rebinding.
- URL encoding and traversal tricks.
- Excluded paths.
- Tool-specific default behavior that broadens scope.
- Active subprocesses attempting unauthorized connections.
- Response and artifact size limits.
- Rate-limit enforcement.
- Malformed JSONL.
- Secret redaction.
- Hostile filenames.
- Symlink and hard-link attacks.
- CSV formula injection.
- HTML/script injection.
- Rerun data integrity.
- Interrupted-run recovery.
- Cross-platform path parsing.

For externally executed active tools, verify request-time enforcement rather than checking only their final results.

### Acceptance criteria

The implementation is acceptable when:

1. All eight tools are registered with stable IDs.
2. The CLI can select any valid subset.
3. Full and preset selection expands correctly.
4. Working adapters execute real tools where security conditions can be satisfied.
5. Unsafe or unverified direct execution is explicitly blocked, not hidden.
6. The five new enrichment functions are implemented and produce evidence-backed outputs.
7. Reruns work without overwriting earlier scans.
8. Historical and duplicate discoveries retain their provenance.
9. Reports accurately distinguish observations from candidate findings.
10. Existing important V1 behavior remains intact.
11. Automated tests cover new behavior and security boundaries.
12. Windows and Linux compatibility claims accurately reflect actual test evidence.
13. The README contains executable usage examples.
14. No uncontrolled active scanning is introduced.

---

# 16. Implement in manageable phases

Use this implementation order:

**Phase 1 — Registry and CLI**

Add stable tool IDs, selector parsing, profiles, and execution-plan preview.

**Phase 2 — Orchestration**

Implement stage dependencies, execution state, cancellation, resource accounting and error handling.

**Phase 3 — External adapters**

Integrate all eight tools. Evaluate active execution constraints individually and implement safe paths where demonstrably possible.

**Phase 4 — Enrichment**

Implement ASN/IP intelligence, Wayback collection, technology fingerprinting, deduplication and prioritization.

**Phase 5 — Reruns and persistence**

Add immutable rerun lineage, schema migrations, incremental offline analysis and comparisons.

**Phase 6 — Reports and usability**

Improve outputs, documentation, status visibility and CLI guidance.

**Phase 7 — Testing and release preparation**

Run the full relevant test suite, correct regressions, perform available cross-platform checks and document remaining limitations.

Deliver cohesive working changes rather than scattering partially connected features throughout the repository.

---

# 17. GitHub workflow and final deliverables

The repository is already connected to Codex through GitHub.

Inspect the current `main` branch first.

Create a dedicated implementation branch rather than directly overwriting `main`.

Use focused commits where practical.

Do not remove existing functionality merely because a new implementation is more convenient.

Update:

- `README.md`
- `docs/ARCHITECTURE.md`
- `docs/TOOLS.md`
- `PROGRESS.md`
- `compatibility.json`
- Example YAML configurations.
- Relevant installation instructions.
- Relevant automated tests.

After implementation, provide:

1. A summary of implemented features.
2. A summary of files created or modified.
3. A list of functioning external integrations.
4. A list of blocked, unverified or incomplete integrations, with reasons.
5. Verification commands and actual test results.
6. Example CLI invocations for single, combined, full and rerun workflows.
7. Any database migration details.
8. Relevant security limitations.
9. A GitHub pull request for review if the environment supports creating one.

Never claim tests passed unless they were actually executed.

Never claim that all eight active integrations work if some remain blocked by policy or platform limitations.

If the entire scope cannot be completed in one implementation pass, complete cohesive, testable phases and report the remaining work accurately. Do not leave a partially connected architecture presented as finished.

---

# 18. Final engineering principles

Prioritize these qualities in order:

1. Scope correctness and safe target interaction.
2. Evidence integrity and predictable execution.
3. Working, verified integrations.
4. Reliable recovery and reruns.
5. Cross-platform compatibility.
6. Useful, low-noise reconnaissance.
7. Performance.
8. CLI usability and maintainability.

The goal is a robust tool for legitimate, authorized bug bounty reconnaissance, not an uncontrolled multi-scanner.

I want **one well-orchestrated reconnaissance platform**, not eight disconnected command wrappers.

Implement the improvements against the real repository, preserve existing safeguards, and make TheGodRecon V2 practical to operate from a terminal on both Linux and Windows.
