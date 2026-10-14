# Tool compatibility and installation

Official release pages and tagged source flags/output schemas/licenses were reviewed on 2026-10-13. GitHub API access was denied in this cloud, so release pages and HTTPS Git were used. All reviewed tools are MIT licensed. `compatibility.json` distinguishes reviewed source, installed/version-checked binaries, actual offline integrations and unexecuted platforms. No paid service, API key or LLM is required.

| Tool | Reviewed pin | V2 execution policy |
|---|---|---|
| Subfinder | 2.17.0 | Passive `-d -json -cs -s -rl -timeout -max-time -duc`; scope-filter returned candidates |
| URLFinder | 0.0.3 | Historical `-d -j -cs -s -fs fqdn -rl -timeout -max-time -duc`; scope-filter URLs |
| dnsx | 1.3.1 | Disabled direct execution; native DNS observations/resolution enforce destination checks |
| ProjectDiscovery httpx | 1.12.0 | Disabled direct execution; native HTTP provides shared budgets, DNS pinning and path enforcement |
| Katana | 1.8.0 | Disabled direct execution; native bounded HTML/JS link crawl replaces it |
| jsluice | commit `0ddfab153e060a9eeaded4d8669233f7c071e7e4` | Offline `urls LOCAL_FILE`; unversioned binary fingerprint and help capabilities are recorded |
| Gitleaks | 8.30.1 | Offline `dir LOCAL_ASSETS --redact=100`; findings exit 10, execution error other nonzero |
| Nuclei | 3.11.1 | Disabled direct execution; native reviewed exposure profile replaces it |
| nuclei-templates | 10.5.0 release page | Bulk templates are neither downloaded nor executed |

Subfinder/URLFinder version and flag checks ran on actual Linux release binaries. Public discovery traffic has **not** been exercised. Offline Gitleaks/jsluice integrations ran on synthetic fixtures. Native active replacements have real localhost integration tests. Fake process/parser tests do not establish Windows binary compatibility. Windows core/Gitleaks CI is supplied but has not run from this workspace. Tree-sitter is the Windows JavaScript path; jsluice requires a native C toolchain and is optional.

The direct active tools have useful scope/rate flags, but cannot jointly prove this platform's preconnection private-IP checks, case-sensitive path exclusions, shared remaining request count and decompressed response limits. Selecting one records an explicit `blocked-by-policy` stage. Select `http,crawl,analysis,checks` for the functioning native workflow. `--strict-tools` refuses requested missing or unsupported adapters before creating a run.

From the project root, Linux and PowerShell both support:

```text
python tools/install_tools.py --tool gitleaks --tool subfinder --tool urlfinder --directory .tools/bin
```

This is an explicit maintenance action. It downloads official pinned release archives, verifies their published SHA-256 checksums over verified TLS, extracts only the selected executable, and writes receipts under `.tools/bin`. It never installs globally. A differing existing binary requires an explicit preserve/remove decision. Use `--tool NAME=PATH` on doctor/scan, or YAML `tools: {gitleaks: 'C:/Tools/gitleaks.exe'}`. Spaces and Unicode paths are supported; quote the entire `NAME=PATH` argument in your shell. Windows binaries end in `.exe`. The similarly named Python httpx package is **not** ProjectDiscovery httpx and doctor detects the mismatch.

jsluice's official source build is optional (Linux needs Go and a C compiler; Windows needs a compatible native C compiler). Clone the official repository into a tool-install directory, checkout the exact commit above, then run `go build -o ./bin/jsluice ./cmd/jsluice` (Windows: `go build -o .\bin\jsluice.exe .\cmd\jsluice`). Do not change dependencies/checksums or disable Go verification. This cloud installed Go from an official checksum-verified archive and built the exact commit, with caches under `/workspace/tooling/go-cache` and `/workspace/tooling/go-packages`. Prepared Linux binaries are under `/workspace/tooling/bin`; these locations are outside all scan runs and contain no target artifacts.

Default providers are Subfinder `crtsh` (HTTPS `crt.sh`) and URLFinder `commoncrawl` (HTTPS `index.commoncrawl.org`). Reviewed optional choices are `hackertarget` (`api.hackertarget.com`) and `alienvault` (`otx.alienvault.com`). Configure network access for selected providers independently of target scope. The platform's current package-manager allowlist does not imply access to these providers or real target hosts. Never widen target scope to resolve an egress failure. Provider API credentials, if needed, belong in the tool's excluded local provider YAML; pass its path via `RECONMAP_SUBFINDER_PROVIDER_CONFIG` or `RECONMAP_URLFINDER_PROVIDER_CONFIG`. Values are not copied into scan configs or logs. Tools receive isolated local homes to prevent default output outside the run.

The Nuclei-compatible local allowlist is **two** reviewed templates under `src/reconmap/templates`: a single GET to `.git/HEAD` and a single GET to `.env`, status/signature matching, redirects off, 4096-byte evidence. `compatibility.json` pins each file by hash. The native profile implements those signatures under the shared scope/scheduler and also collects bounded OpenAPI/Swagger leads. CORS observations remain contextual; no CVE exploitation or automatic takeover validation is included. Direct Nuclei execution and upstream bulk template parity are not claimed.


## V2 registry and verification

Permanent IDs: 1 Subfinder, 2 URLFinder, 3 dnsx, 4 ProjectDiscovery httpx, 5 Katana, 6 jsluice, 7 Gitleaks, 8 Nuclei. `reconmap tools list` / `tools doctor --json` show binary availability, verified version/features, policy status and fallback separately. Binary compatibility does not imply direct execution permission. All eight reviewed Linux executables were version/help checked on 2026-10-14. Actual Linux jsluice/Gitleaks local integrations ran; Subfinder/URLFinder live providers were not queried. dnsx/httpx/Katana/Nuclei target execution did not run; native alternatives were exercised against loopback fixtures. Windows remains execution-unverified.

The explicit installer now supports official checksum-verified release archives for all seven versioned tools:

```text
python tools/install_tools.py --tool subfinder --tool urlfinder --tool dnsx --tool httpx --tool katana --tool gitleaks --tool nuclei --directory .tools/bin
```

This works without root for a user-owned directory. Katana's authoritative checksum file uses `katana-VERSION-checksums.txt`, unlike the underscore names used by the other releases; the exact official release asset was inspected, not guessed. Linux installation/checksum/executable verification for all seven has run. The same release naming logic supports Windows archives; native Windows installation has not run. Binary and receipt publication is atomic, unsafe destinations are refused, existing matching binaries are not rewritten, and download/unpacked size caps apply. No maintenance downloads occur during scans.

jsluice remains a manual source build because it has no reviewed version-reporting release binary. Build the pinned commit as described above and inspect its SHA-256. V2 executes only hashes explicitly reviewed in `adapters.REVIEWED_JSLUICE_HASHES`; the retained tested Linux build is recognized. A different build (including an unverified Windows build) is incompatible until its origin/behavior is reviewed and its fingerprint is added in a code review. Help text alone cannot prove a pinned source commit. Native Tree-sitter remains usable on both core platforms. This avoids silently executing an unidentified jsluice build; no broad trust/unsafe override exists.

### Direct active execution assessment

| Tool | Why direct execution is blocked | Working alternative |
|---|---|---|
| dnsx | Subprocess resolver queries/retries cannot share measured operation reservations or a verified egress sandbox | Scoped native A/AAAA and bounded CNAME/wildcard observations |
| httpx | Independent DNS/connections can evade address pinning; aggregate request/response caps and HTTPS path exclusions cannot be proved | Native GET service observations through the shared scheduler |
| Katana | Crawl expansion/subrequests cannot jointly enforce method/action/path/DNS/shared-budget policy | Native non-headless HTML/static-JS crawler |
| Nuclei | Template allowlisting alone does not enforce subprocess destinations, redirects, decompression or shared request accounting | Two reviewed native GET exposure checks; no bulk templates/OAST |

Structured JSONL parsers cover the reviewed tool schemas, including dnsx host/records, httpx URL metadata, Katana request.endpoint and Nuclei matched-at. These parsers are tested fixtures and are not proof of direct network execution. The command gate blocks these four tools even if a caller supplies a falsely supported ToolInfo; an armed active binary fixture never received a scan invocation. Plan/list/report show the exact policy reason. `--strict-tools` refuses selected missing/incompatible/blocked integrations before creating output; otherwise native alternatives run and incomplete external coverage remains exit 2.

### Provider metadata sources

Wayback: documented Internet Archive CDX interface (`https://web.archive.org/cdx/search/cdx`), exact seed host match, timestamp/original/statuscode/mimetype/digest fields, bounded pages/results, resume keys and no archive-content fetch. RIPE Stat: `https://stat.ripe.net/data/network-info/data.json` and `as-overview/data.json`, queries only already observed authorized public addresses/ASNs. Source documentation: https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server and https://stat.ripe.net/docs/data_api . These adapters do not need paid APIs/LLMs and never turn infrastructure ownership into scope. Provider failures produce partial stages. Local fixtures are verified; live service egress, schemas/rate limits and collection remain untested in this cloud.
