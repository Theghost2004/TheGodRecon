# TheGodRecon V3.1.0

A local reconnaissance coordinator for authorized security research. Map a scoped target, combine tool evidence, and get a clear shortlist for manual investigation. Everything stays in local scan folders.

## Features

- Simple commands, optional interactive menu, and live terminal progress.
- Eight selectable tool capabilities with verified setup and native fallbacks.
- Exact-host scope, bounded requests, resumable scans, and separate folders for every run.
- Evidence-backed endpoint ranking, offline reports, and a separate navigable application relationship map.

## Requirements

Python **3.12+**, Linux or Windows 10/11, and Git. Setup needs internet access to official package/tool sources. Go and GCC are optional for jsluice; native Tree-sitter works without them. Reviewed automatic binary installation supports x86-64; other architectures retain the Python core where its dependencies are available.

## Installation

### Linux

```bash
git clone https://github.com/Theghost2004/TheGodRecon.git
cd TheGodRecon
python3 tools/bootstrap.py
source .venv/bin/activate
reconmap doctor
```

### Windows — PowerShell

```powershell
git clone https://github.com/Theghost2004/TheGodRecon.git
cd TheGodRecon
py -3.12 tools\bootstrap.py
.\.venv\Scripts\Activate.ps1
reconmap doctor
```

Bootstrap creates `.venv`, installs locked Python packages, and attempts verified optional tool installation. It reports missing components without claiming success for them. It never installs OS packages or requests administrator access.

Activation is once per terminal. Without activation, use `./reconmap` on Linux or `.\reconmap.cmd` in PowerShell. These wrappers also work when PowerShell activation is restricted. The CLI is **not installed globally**.

## Quick Start

The following target is illustrative. Scan only a target you are authorized to test; the effective scope and budgets are printed before execution.

```bash
reconmap setup
reconmap blackbox https://authorized.example
reconmap scan https://authorized.example --tools subfinder,httpx,katana
reconmap report
```

Try it without target or provider traffic:

```bash
reconmap demo
```

Run `reconmap` with no arguments in a terminal for the interactive menu. In scripts it prints help without prompting.

## Commands

| Command | Purpose |
|---|---|
| `reconmap blackbox URL` | All eight capabilities, intelligent discovery, report and endpoint map |
| `reconmap scan HOST` | Balanced native scan; customize with `--tools` and `--exclude-tools` |
| `reconmap scan HOST --quick` | Smaller request and depth limits |
| `reconmap scan HOST --deep` | Larger bounded scan with local analysis tools |
| `reconmap scan HOST --god-mode` | Compatibility alias for BlackBox; also `--full-coverage` |
| `reconmap scan HOST --all-tool` | Select all eight capabilities; same as `--tools all` |
| `reconmap scan HOST --config scope.yaml` | Use your reusable authorization and scan settings |
| `reconmap scan HOST --no-progress` | Plain stage logs |
| `reconmap resume RUN_FOLDER` | Continue with saved scope and remaining budgets |
| `reconmap doctor` | Check dependencies and execution restrictions |
| `reconmap doctor --fix` | Repair supported optional dependencies with consent |
| `reconmap report` | Open the most recent valid report, or print its path |
| `reconmap tools register jsluice PATH` | Remember an executable path; trust checks still apply |
| `reconmap settings --set auto_open true` | Opt into opening reports after scans |

`--standard`, `--preset quick/standard/deep`, and `--all-tools` are also supported. Existing `--target`, `--profile`, `--tools`, `--modules`, `plan`, `rerun`, `diff`, and `report --run` commands remain available. Use `reconmap --help` or a command's `--help` for details.

## BlackBox and Customized Scans

Use comprehensive coverage on an explicitly authorized target:

```bash
reconmap blackbox https://example.com
reconmap blackbox https://example.com --max-requests 5000 --depth 3 --max-minutes 30
```

BlackBox coordinates all eight capabilities, local JavaScript/secret analysis, evidence-driven SecLists selection, correlation, the existing report and a separate endpoint relationship map. Every request stays within the configured scope and shared budgets. Restricted external tools use protected native implementations; the coverage summary names the actual engines and limitations.

For direct control, use the same engine through `scan`:

```bash
reconmap scan https://example.com --tools subfinder,httpx,katana
reconmap scan https://example.com --tools all --exclude-tools 7,8
reconmap scan https://example.com --tools 4,5,6 --engine jsluice=native --depth 3
reconmap scan https://example.com --auto-wordlists --exclude-wordlist assets
```

Unselected capabilities do not run. Crawling and active exposure checks require selected HTTP collection (`httpx`); absent prerequisites are explained. `--god-mode` and `--full-coverage` map to BlackBox. `--all-tool` remains eight-tool selection without automatic enrichment/discovery; `--deep` remains a budget preset. All use one pipeline. [Workflow, YAML, graph schema and verification details](docs/BLACKBOX.md).

## SecLists

Linux bootstrap/setup installs or reuses **four reviewed SecLists dictionaries plus their license** (about 237 KB), rather than the complete collection. Use `python tools/bootstrap.py --skip-wordlists` to decline, or explicitly install on either supported platform:

```bash
reconmap setup --with-seclists --yes
reconmap wordlists doctor
reconmap wordlists list
reconmap scan example.com --wordlist /path/to/custom.txt
```

The managed location is `$XDG_DATA_HOME/thegodrecon/wordlists/seclists` (normally `~/.local/share/thegodrecon/wordlists/seclists`) on Linux and `%LOCALAPPDATA%\thegodrecon\wordlists\seclists` on Windows. A matching `/usr/share/seclists` copy is reused. `RECONMAP_CONFIG_DIR` makes settings and wordlists portable together.

BlackBox selects small common paths, supplements observed APIs, and uses captured JavaScript or current application fingerprints to choose relevant entries. Exact-host scope never expands into subdomains. Explicit custom UTF-8 lists replace automatic dictionaries, can be repeated, and use the same scope and discovery limits. `--exclude-wordlist NAME_OR_PATH` excludes a catalog list or exact custom path. Scans only read local lists; missing lists are an optional coverage limitation. [Detailed behavior and YAML options](docs/GOD_MODE.md).

## How the Tool Works

Selected tools run when compatible and permitted. Missing or failed tools use applicable native fallbacks within the same scope and remaining budgets. The dashboard distinguishes primary tool status from the actual executing engine. Redirected output uses plain text.

**dnsx, ProjectDiscovery httpx, Katana and Nuclei remain restricted from direct active execution.** Their native alternatives enforce the central request policy. Installing a binary does not grant permission to run it. Subfinder has no equivalent native enumeration; URLFinder's CDX alternative requires explicitly enabled Wayback enrichment.

## Viewing Reports

Each scan gets a new folder: `recon-output/example.com`, then `1_example.com`, `2_example.com`, and so on. Previous runs are preserved.

The HTML report is in **`RUN_FOLDER/reports/index.html`**. It provides Live Assets, Interesting Endpoints, Potential Exposures, and All Results, with supporting evidence and exports available in detail views. A candidate is a lead for manual review, not a confirmed vulnerability.

```bash
reconmap report
reconmap report --run recon-output/example.com
```

BlackBox and normal scans also produce `graph/endpoint-tree.txt`, `graph/asset-graph.json`, `graph/asset-graph.dot`, `graph/graph-summary.json`, and `graph/asset-map.html`. The report links to the offline map; the final terminal summary prints absolute paths. Normal scans can opt out with `--no-graph`. Graphviz is optional.

The first command opens the latest known valid report when a browser is available. The second regenerates a specified report. Headless systems print an absolute file path. Automatic browser opening after scans is off by default.

## Troubleshooting

- **Command not found:** activate `.venv`, or use the platform wrapper above.
- **Missing Python packages / pip / venv:** install Python with pip and venv support, then rerun `python tools/bootstrap.py`. No privileged repair is attempted.
- **Optional tools missing:** run `reconmap doctor --fix`; use `--yes` for explicit noninteractive consent. Compatible binaries are reused.
- **jsluice rejected:** `reconmap setup --yes --go PATH_TO_GO --cc PATH_TO_GCC` can build the reviewed source revision. An arbitrary local build stays untrusted. Tree-sitter remains available.
- **Custom binary incompatible:** repair it and register its path again, or use `reconmap tools unregister NAME` before setup to select a managed installation. Setup preserves custom files.
- **Partial run / exit code 2:** inspect coverage and limits. A blocked tool or exhausted ceiling does not mean evidence was lost. Resume does not reset budgets.
- **Interrupted:** the run path is printed. Use `reconmap resume RUN_FOLDER`.

Native Windows execution is covered by the CI matrix but has not been verified in the Linux development environment. See the release notes for exact validation results.

## Safety and Scope

Default scans authorize only the supplied hostname, with the existing scheme/port, IP, redirect, GET-only action and budget restrictions. They do not add wildcards or network ranges. Use a reviewed YAML file for a custom scope. Localhost tests require explicit lab scope. Deep scans remain bounded; all-tool selection does not enable prohibited execution or additional enrichment providers.

Keep raw evidence private. Do not scan public targets without authorization.

## Advanced Documentation

- [BlackBox workflow, graph model and validation](docs/BLACKBOX.md)
- [BlackBox implementation checklist](docs/BLACKBOX_PROGRESS.md)
- [3.1.0 release, installation and verification details](docs/V3_1_RELEASE.md)
- [Advanced commands, YAML, budgets, resume and exports](docs/ADVANCED_USAGE.md)
- [Tool pins, installation and safety boundaries](docs/TOOLS.md)
- [V3 architecture and intelligence pipeline](docs/V3_ARCHITECTURE.md)
- [V3 regression scenarios and screenshots](docs/V3_REGRESSION.md)
- [3.1.0 progress checklist](docs/V3_1_PROGRESS.md)
