# V3 orchestration and intelligence

V3 extends the existing coordinator. Python 3.12+, the CLI entry point, permanent
tool IDs, YAML versions 1/2, configuration digests, exact scope, durable jobs,
collision-safe folders and immutable reruns remain supported. There are no new
runtime dependencies, service accounts, LLMs or remote UI components.

## Execution and safety

`tool_registry.py` remains the source of tool identities and active execution
blocks. `orchestrator.py` keeps the dependency graph and adds a durable
`StageResult` per capability. It records selected primary tool, executable
version/path/hash, actual engines, primary/final state, failure reason,
input/output references, counters, duration, record count, fallback and coverage
limitations. Native stages can share a collection phase; those durations and
request counters are labeled shared and must not be summed as independent traffic.

`integrations.py` attempts selected, compatible passive/local tools first. It
rechecks executable SHA-256 at invocation and validates local artifact SHA-256
and size before processing. Commands are argument arrays, never shell strings.
Per-input checkpoints retain parsed output and failure status before fallback.
Successful inputs are reused; new source contexts can replay saved parsed records
without executing the binary again. A malformed/failed input can need whole-input
native analysis; successful records remain deduplicated by their evidence keys.
This is at-least-once processing across a hard kill, not exactly-once execution.

The subprocess runner retains bounded stdout/stderr prefixes on time/output
failure, kills process groups/trees and monitors Gitleaks report size while the
process is running. Monitoring can overshoot by a write before cancellation;
there is no OS disk/CPU/memory quota. Native analyzers have bounded inputs and
cooperative time checks. Raw captures and content are kept under the existing
private run-directory trust model.

jsluice owns selected JavaScript extraction. Native Tree-sitter still checks
request methods/options as a scheduling veto and parses embedded source maps,
which jsluice does not accept. Gitleaks owns selected secret detection. Only
failed/missing/incompatible inputs use native discovery/secret fallbacks. No
separate fallback network client exists: inferred eligible GETs enter the same
scope-aware jobs and request reservations. Cancellation or depleted global
budgets cannot start a fresh fallback budget. Native-only module selections
continue working, including inline scripts, local inputs and reused evidence.

Subfinder has no equivalent native subdomain enumerator; limited seed/reference
inventory is reported honestly. URLFinder uses CDX fallback only when Wayback
was explicitly enabled beforehand. A complete URLFinder stage skips redundant
CDX collection. Demo/offline/loopback modes never contact discovery providers.
Provider budget exhaustion remains a stop, not a reason to contact another
service outside the approved budget.

Direct dnsx/httpx/Katana/Nuclei remain blocked on all platforms. A safe active
backend would need enforceable isolation plus an application-aware request
broker covering *all* executable/child network traffic, approved DNS/IP,
host/path/port/scheme, redirects/secondary requests, methods/actions, exclusions,
shared reservations and cancellation. Scanner CLI flags and an optional HTTPS
CONNECT proxy cannot prove these controls. No such backend is verified for
Linux or Windows here. Native DNS, aiohttp, HTML crawling and reviewed limited
GET checks therefore remain the actual engines. The policy block is reported
separately from useful native completion; full selection can finish with exit 2.

## Evidence normalization and storage

SQLite migration 2→3 transactionally adds `stage_results`, `normalized_records`
and `investigation_candidates`. Versions 1 and 2 migrate through the existing
steps only on mutable opens. Read-only parent/report-comparison reads do not
migrate or create sidecars. Original observations, findings, artifacts,
relationships and analyst decisions are retained; unknown schemas still fail.

`normalization.py` derives records from that existing evidence. A request ID is
a SHA-256 of canonical wire URL, HTTP method and authorization-context identity.
The current collector sends unauthenticated GETs only; context separation also
preserves distinct explicit contexts in imported/inferred evidence. It does not
enable authenticated collection. URL fragments are retained as original
spellings, not separate wire requests. Raw query order/values/repeated names,
case-sensitive paths, encodings and explicit default ports stay distinct.

Each record links to observation IDs, source tools/timestamps, artifact hashes
and captures; it preserves original URLs, parameters, inferred code context,
DNS/infrastructure, historical metadata, errors and incomplete evidence. Current
status comes from an HTTP observation, never archive status or static inference.
Legacy summary-only status is labeled as such. Parent HTTP observations retain
collection timestamps and become `previously-observed`, not newly live. Imported
observation IDs include their parent run ID so fresh recollection cannot collide
with and suppress new observations. Redirect
chains use recorded responses only, stop at excluded destinations and retain
origin status separately from any actually observed final destination. This
processing performs no DNS, target or provider requests.

Derived JSON fields are decoded before structured redaction, preserving valid
JSON even when source excerpts include escaped quotes or credential-like text.
Raw database/content evidence is still restricted and may contain sensitive data.

## Classification, correlation and ranking

`enrichment/prioritization.py` shares its path/MIME classifier with native finding
detectors. Static extensions and MIME types take precedence over filename words;
route categories use exact segment boundaries. Query text is not route semantics.
A CSS `adminlte` filename cannot become an admin endpoint. Real route names are
leads; only response/form/signature context raises their evidence confidence.

Rule version 2 uses the existing configurable weight keys. Configuration's
`priority.version: 1` remains the compatible weight-settings schema, not the
output rule version. Defaults reward direct HTTP evidence, meaningful route
segments, restricted application surfaces, associated parameters, one capped
independent-source contribution, relevant high-confidence technology context,
and current password-form/bounded exposure signatures. Specific current Git
HEAD/environment signatures add 25 points; other reviewed response signatures
add 10, with generic markers capped at 55 and medium confidence. No source count
or keyword repetition multiplies score.

Negative evidence imposes inspectable caps: ordinary static assets 10,
tracking/documentation 20 (verified generated documentation 25), generated/library
assets 15, redirect-only responses
10 (20 with meaningful observed destination), error responses 10, generic/soft
404 pages 5, empty nonrestricted responses 15, inferred unobserved requests 30,
other unobserved requests 20, conflicting/truncated evidence 40, synthetic
observations 5 and scope-denied records 0. Scores are clamped 0–100 in steps of
five. A high-interest card needs at least 60 plus current successful/restricted
meaningful evidence; manual review needs at least 20 and relevant functionality
or code context. Others remain inventory. A score is an ordering aid, not a
probability, impact rating, or severity.

Reachability, endpoint interest, evidence confidence, potential impact and
vulnerability severity are separate fields. Severity remains unassessed. An
analyst's existing confirmation/dismissal stays on the original finding; detector
scores never automatically confirm a vulnerability. Dismissed response findings
do not add exposure signals to the derived shortlist. Strong signatures require
a current matching response hash/status. Generic markers in static libraries
cannot become strong exposures.

Deduplication has independent layers: exact request identity; same response bytes
(content groups); numeric/UUID route families; parameter-name multiplicity;
and source correlation. Content equality is not proof of authorization or
functional equivalence. Only same-family records with matching exact query,
method, context, status and classification share a shortlist representative.
Query-value differences and known methods stay separately reviewable. Methodless
tool duplicates link to known request identities and do not create extra cards.
Every member remains in the inventory. Member lists are stored on representative
records to avoid quadratic exported lists. Synthetic, inferred and historical
records cannot crowd out stronger current evidence through repetition.

## Reporting and verification

The primary dashboard has Live Assets, Interesting Endpoints, Potential
Exposures and All Results. The first means responses observed in this run;
401/403, redirects and errors are explicitly labeled. Candidate cards show
readable reasons and safe manual next checks, with supporting evidence expanded
on demand. Multiple secret detectors on one artifact share an exposure card;
all underlying fingerprints/analyst decisions remain available. Inventory,
history, tool executions, infrastructure, raw findings and comparisons are
accessible in secondary views/exports.

Reports retain escaped HTML, inert embedded JSON, script-hash CSP, no target
resources, formula-safe CSV and hash-only local artifact downloads. New exports
are `investigation.json`, `stage-results.json` and normalized/candidate CSV/JSONL.
The original exports are preserved. Core normalization/ranking always runs;
`--enrich none` disables optional enrichments, not the local report processing.

See [V3_PROGRESS.md](V3_PROGRESS.md) for exact test, installation, real-tool and
browser evidence. Native Windows/Python 3.13 and live providers require separate
execution verification. Configuration of a CI job is not evidence that it ran.
