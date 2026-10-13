# Tool compatibility and installation

Official release pages and tagged source flags/output schemas/licenses were reviewed on 2026-10-13. GitHub API access was denied in this cloud, so release pages and HTTPS Git were used. All reviewed tools are MIT licensed. `compatibility.json` distinguishes reviewed source, installed/version-checked binaries, actual offline integrations and unexecuted platforms. No paid service, API key or LLM is required.

| Tool | Reviewed pin | V1 execution policy |
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

The direct active tools have useful scope/rate flags, but cannot jointly prove this V1's preconnection private-IP checks, case-sensitive path exclusions, shared remaining request count and decompressed response limits. Selecting one records an explicit degraded stage. Select `http,crawl,analysis,checks` for the functioning native workflow. `--strict-tools` refuses requested missing or unsupported adapters before creating a run.

From the project root, Linux and PowerShell both support:

```text
python tools/install_tools.py --tool gitleaks --tool subfinder --tool urlfinder --directory .tools/bin
```

This is an explicit maintenance action. It downloads official pinned release archives, verifies their published SHA-256 checksums over verified TLS, extracts only the selected executable, and writes receipts under `.tools/bin`. It never installs globally. A differing existing binary requires an explicit preserve/remove decision. Use `--tool NAME=PATH` on doctor/scan, or YAML `tools: {gitleaks: 'C:/Tools/gitleaks.exe'}`. Spaces and Unicode paths are supported; quote the entire `NAME=PATH` argument in your shell. Windows binaries end in `.exe`. The similarly named Python httpx package is **not** ProjectDiscovery httpx and doctor detects the mismatch.

jsluice's official source build is optional (Linux needs Go and a C compiler; Windows needs a compatible native C compiler). Clone the official repository into a tool-install directory, checkout the exact commit above, then run `go build -o ./bin/jsluice ./cmd/jsluice` (Windows: `go build -o .\bin\jsluice.exe .\cmd\jsluice`). Do not change dependencies/checksums or disable Go verification. This cloud installed Go from an official checksum-verified archive and built the exact commit, with caches under `/workspace/tooling/go-cache` and `/workspace/tooling/go-packages`. Prepared Linux binaries are under `/workspace/tooling/bin`; these locations are outside all scan runs and contain no target artifacts.

Default providers are Subfinder `crtsh` (HTTPS `crt.sh`) and URLFinder `commoncrawl` (HTTPS `index.commoncrawl.org`). Reviewed optional choices are `hackertarget` (`api.hackertarget.com`) and `alienvault` (`otx.alienvault.com`). Configure network access for selected providers independently of target scope. The platform's current package-manager allowlist does not imply access to these providers or real target hosts. Never widen target scope to resolve an egress failure. Provider API credentials, if needed, belong in the tool's excluded local provider YAML; pass its path via `RECONMAP_SUBFINDER_PROVIDER_CONFIG` or `RECONMAP_URLFINDER_PROVIDER_CONFIG`. Values are not copied into scan configs or logs. Tools receive isolated local homes to prevent default output outside the run.

The Nuclei-compatible local allowlist is **two** reviewed templates under `src/reconmap/templates`: a single GET to `.git/HEAD` and a single GET to `.env`, status/signature matching, redirects off, 4096-byte evidence. `compatibility.json` pins each file by hash. The native profile implements those signatures under the shared scope/scheduler and also collects bounded OpenAPI/Swagger leads. CORS observations remain contextual; no CVE exploitation or automatic takeover validation is included. Direct Nuclei execution and upstream bulk template parity are not claimed.
