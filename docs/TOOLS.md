> **3.1.0 setup:** `python tools/bootstrap.py`, `reconmap setup`, and `reconmap doctor --fix` now manage persistent discovery and verified installation. See [installation details](V3_1_RELEASE.md#installation-and-repair). The tool pins below remain applicable; active execution now requires the [verified Linux boundary](EXTERNAL_EXECUTION.md).

# Tool compatibility and installation

Official release pages and tagged source flags/output schemas/licenses were reviewed on 2026-10-13. GitHub API access was denied in this cloud, so release pages and HTTPS Git were used. All reviewed tools are MIT licensed. `compatibility.json` distinguishes reviewed source, installed/version-checked binaries, actual offline integrations and unexecuted platforms. No paid service, API key or LLM is required.

| Tool | Reviewed pin | Execution policy |
|---|---|---|
| Subfinder | 2.17.0 | Passive `-d -json -cs -s -rl -timeout -max-time -duc`; scope-filter returned candidates |
| URLFinder | 0.0.3 | Historical `-d -j -cs -s -fs fqdn -rl -timeout -max-time -duc`; scope-filter URLs |
| dnsx | 1.3.1 | Contained real DNS queries through the counted DNS broker; native fallback where unavailable |
| ProjectDiscovery httpx | 1.12.0 | Contained real HTTP probes through the central HTTP broker; native fallback where unavailable |
| Katana | 1.8.0 | Contained non-headless crawl through the central HTTP broker; native fallback where unavailable |
| jsluice | commit `0ddfab153e060a9eeaded4d8669233f7c071e7e4` | Offline `urls LOCAL_FILE`; unversioned binary fingerprint and help capabilities are recorded |
| Gitleaks | 8.30.1 | Offline `dir LOCAL_ASSETS --redact=100`; findings exit 10, execution error other nonzero |
| Nuclei | 3.11.1 | Contained execution of two hashed templates; native fallback where unavailable |
| nuclei-templates | 10.5.0 release page | Bulk templates are neither downloaded nor executed |

Subfinder/URLFinder version and flag checks ran on actual Linux release binaries. Public discovery traffic has **not** been exercised. Offline Gitleaks/jsluice integrations ran on synthetic fixtures. Native active replacements have real localhost integration tests. Fake process/parser tests do not establish Windows binary compatibility. Windows core/Gitleaks CI is supplied but has not run from this workspace. Tree-sitter is the Windows JavaScript path; jsluice requires a native C toolchain and is optional.

Active tools are evaluated at runtime for binary identity, reviewed flags, platform isolation, selected prerequisites and template scope. There is no unconditional tool-name denial. A failed boundary probe prevents uncontained execution. See [the execution contract and validation status](EXTERNAL_EXECUTION.md).

From the project root, Linux and PowerShell both support:

```text
python tools/install_tools.py --tool gitleaks --tool subfinder --tool urlfinder --directory .tools/bin
```

This is an explicit maintenance action. It downloads official pinned release archives, verifies their published SHA-256 checksums over verified TLS, extracts only the selected executable, and writes receipts under `.tools/bin`. It never installs globally. A differing existing binary requires an explicit preserve/remove decision. Use `--tool NAME=PATH` on doctor/scan, or YAML `tools: {gitleaks: 'C:/Tools/gitleaks.exe'}`. Spaces and Unicode paths are supported; quote the entire `NAME=PATH` argument in your shell. Windows binaries end in `.exe`. The similarly named Python httpx package is **not** ProjectDiscovery httpx and doctor detects the mismatch.

jsluice's official source build is optional (Linux needs Go and a C compiler; Windows needs a compatible native C compiler). Clone the official repository into a tool-install directory, checkout the exact commit above, then run `go build -o ./bin/jsluice ./cmd/jsluice` (Windows: `go build -o .\bin\jsluice.exe .\cmd\jsluice`). Do not change dependencies/checksums or disable Go verification. This cloud installed Go from an official checksum-verified archive and built the exact commit, with caches under `/workspace/tooling/go-cache` and `/workspace/tooling/go-packages`. Prepared Linux binaries are under `/workspace/tooling/bin`; these locations are outside all scan runs and contain no target artifacts.

Default providers are Subfinder `crtsh` (HTTPS `crt.sh`) and URLFinder `commoncrawl` (HTTPS `index.commoncrawl.org`). Reviewed optional choices are `hackertarget` (`api.hackertarget.com`) and `alienvault` (`otx.alienvault.com`). Configure network access for selected providers independently of target scope. The platform's current package-manager allowlist does not imply access to these providers or real target hosts. Never widen target scope to resolve an egress failure. Provider API credentials, if needed, belong in the tool's excluded local provider YAML; pass its path via `RECONMAP_SUBFINDER_PROVIDER_CONFIG` or `RECONMAP_URLFINDER_PROVIDER_CONFIG`. Values are not copied into scan configs or logs. Tools receive isolated local homes to prevent default output outside the run.

The Nuclei-compatible local allowlist is **two** reviewed templates under `src/reconmap/templates`: a single GET to `.git/HEAD` and a single GET to `.env`, status/signature matching, redirects off, 4096-byte evidence. `compatibility.json` pins each file by hash. The native profile implements those signatures under the shared scope/scheduler and also collects bounded OpenAPI/Swagger leads. CORS observations remain contextual; no CVE exploitation or automatic takeover validation is included. The contained Nuclei adapter executes only those two templates, verifies their hashes, and requires captured response signatures before adding exposure candidates. Bulk template parity is not claimed.


## V2 registry and verification

Permanent IDs: 1 Subfinder, 2 URLFinder, 3 dnsx, 4 ProjectDiscovery httpx, 5 Katana, 6 jsluice, 7 Gitleaks, 8 Nuclei. `reconmap tools list` / `tools doctor --json` show binary availability, verified version/features, policy status and fallback separately. Binary compatibility does not imply direct execution permission. All eight reviewed Linux executables were version/help checked on 2026-10-14. Actual Linux jsluice/Gitleaks local integrations ran; Subfinder/URLFinder live providers were not queried. At that historical checkpoint, dnsx/httpx/Katana/Nuclei target execution had not run; see the current boundary validation record for subsequent results.

The explicit installer now supports official checksum-verified release archives for all seven versioned tools:

```text
python tools/install_tools.py --tool subfinder --tool urlfinder --tool dnsx --tool httpx --tool katana --tool gitleaks --tool nuclei --directory .tools/bin
```

This works without root for a user-owned directory. Katana's authoritative checksum file uses `katana-VERSION-checksums.txt`, unlike the underscore names used by the other releases; the exact official release asset was inspected, not guessed. Linux installation/checksum/executable verification for all seven has run. The same release naming logic supports Windows archives; native Windows installation has not run. Binary and receipt publication is atomic, unsafe destinations are refused, existing matching binaries are not rewritten, and download/unpacked size caps apply. No maintenance downloads occur during scans.

For V3.1, use the verified source-build workflow in [V3.1 release notes](V3_1_RELEASE.md#jsluice-source-build-and-fallback). The following describes the older V2 policy: jsluice required a manual source build because it had no reviewed version-reporting release binary. Build the pinned commit as described above and inspect its SHA-256. V2 executes only hashes explicitly reviewed in `adapters.REVIEWED_JSLUICE_HASHES`; the retained tested Linux build is recognized. A different build (including an unverified Windows build) is incompatible until its origin/behavior is reviewed and its fingerprint is added in a code review. Help text alone cannot prove a pinned source commit. Native Tree-sitter remains usable on both core platforms. This avoids silently executing an unidentified jsluice build; no broad trust/unsafe override exists.

### Active execution boundary

The active adapters use `linux-bubblewrap-broker-v1`. Executable compatibility and
runtime permission are separate. All target requests pass through the existing
scheduler and resolver, with TLS terminated inside the isolated network namespace
so HTTPS paths can be checked. Direct socket egress has no target route.

Strict execution refuses missing/incompatible tools, unavailable backends and
incompatible template scope before output allocation. Runtime failure or absent
inputs yields partial coverage; strict mode cannot call native substitutes.
Non-strict scans retain the existing eligible native fallbacks.

See [architecture, commands and limitations](EXTERNAL_EXECUTION.md). Historical
verification statements in V2/V3 release notes describe those releases, not the
new boundary. Successful real-binary verification is tracked separately from
unit tests and help/version checks.

### Provider metadata sources

Wayback: documented Internet Archive CDX interface (`https://web.archive.org/cdx/search/cdx`), exact seed host match, timestamp/original/statuscode/mimetype/digest fields, bounded pages/results, resume keys and no archive-content fetch. RIPE Stat: `https://stat.ripe.net/data/network-info/data.json` and `as-overview/data.json`, queries only already observed authorized public addresses/ASNs. Source documentation: https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server and https://stat.ripe.net/docs/data_api . These adapters do not need paid APIs/LLMs and never turn infrastructure ownership into scope. Provider failures produce partial stages. Local fixtures are verified; live service egress, schemas/rate limits and collection remain untested in this cloud.


## V3 execution contract

Selected compatible passive/local tools run first. Local inputs are hashed and
processed once per tool/input; late-discovered source contexts reuse the saved
parsed output. Executable SHA-256 is rechecked immediately before launch. Argument
arrays, timeout/process-group cleanup, stdout/stderr caps and monitored Gitleaks
report-size limits apply without a shell. File-size monitoring is cooperative,
not an OS disk quota: one write can overshoot before the monitor kills the process.

Timeout/output-cap exceptions retain their bounded stdout/stderr prefixes. Valid
complete records are persisted before a failed input gets native fallback. A
partially malformed input may require native reanalysis of that whole artifact;
exact observation/finding keys avoid duplicate results. Completed artifacts and
completed target jobs are reused. Global time, disk, DNS and request budgets never
reset. Scope-denied URLs, unsafe methods and exhausted budgets remain denied.

`reports/stage-results.json` distinguishes `selected_primary_tool`,
`actual_execution_engines`, `primary_status`, overall `status`, fallback and
coverage limitations. Native web functions share the same request owner: their
`shared_counters_not_additive` accounting group must not be summed across stages.
Provider subprocess request counts are unknown; owned CDX/RIPE counters are separate.
The primary binary's actual version, path, hash and compatibility are retained.

No selected external subdomain enumerator means no native equivalent enumeration;
only existing seed/reference inventory is available. CDX requires prior explicit
Wayback selection. The four active binaries require the verified Linux boundary. Windows currently
has no equivalent backend and therefore retains non-strict native fallbacks. Unreviewed jsluice builds retain the native fallback;
there is no automatic trust/download update.
