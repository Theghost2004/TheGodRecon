# TheGodRecon V3.1.0

A local reconnaissance coordinator for authorized security research. Map a scoped target, combine tool evidence, and get a clear shortlist for manual investigation. Everything stays in local scan folders.

## Features

- Simple commands, optional interactive menu, and live terminal progress.
- Eight selectable tool capabilities with verified setup and native fallbacks.
- Exact-host scope, bounded requests, resumable scans, and separate folders for every run.
- Evidence-backed endpoint ranking, duplicate grouping, and offline HTML reports.

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
reconmap scan authorized.example
reconmap scan authorized.example --all-tool
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
| `reconmap scan HOST` | Balanced scan with exact-host defaults |
| `reconmap scan HOST --quick` | Smaller request and depth limits |
| `reconmap scan HOST --deep` | Larger bounded scan with local analysis tools |
| `reconmap scan HOST --god-mode` | All capabilities plus bounded evidence/wordlist discovery; alias `--full-coverage` |
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

## God Mode

Use maximum supported coverage on an explicitly authorized target:

```bash
reconmap scan example.com --god-mode
reconmap scan example.com --full-coverage --max-requests 5000 --depth 3 --max-minutes 30
```

Both aliases combine passive discovery, HTTP mapping, crawling, JavaScript analysis, secret detection, curated content discovery and evidence-based reporting. Scope and shared budgets still apply. The discovery allocation defaults to 100 requests and never exceeds 20% of the global ceiling, including retries and descendants. Restricted executables retain their native fallbacks; coverage reports explain what actually ran. Standard scans remain lightweight.

## SecLists

Linux bootstrap/setup installs or reuses **four reviewed SecLists dictionaries plus their license** (about 237 KB), rather than the complete collection. Use `python tools/bootstrap.py --skip-wordlists` to decline, or explicitly install on either supported platform:

```bash
reconmap setup --with-seclists --yes
reconmap wordlists doctor
reconmap wordlists list
reconmap scan example.com --wordlist /path/to/custom.txt
```

The managed location is `$XDG_DATA_HOME/thegodrecon/wordlists/seclists` (normally `~/.local/share/thegodrecon/wordlists/seclists`) on Linux and `%LOCALAPPDATA%\thegodrecon\wordlists\seclists` on Windows. A matching `/usr/share/seclists` copy is reused. `RECONMAP_CONFIG_DIR` makes settings and wordlists portable together.

God Mode selects small common paths, supplements observed APIs, and uses captured JavaScript or current application fingerprints to choose relevant entries. Exact-host scope never expands into subdomains. Custom UTF-8 lists use the same scope and discovery limits. Scans only read local lists; missing lists are an optional coverage limitation. [Detailed behavior and YAML options](docs/GOD_MODE.md).

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

- [3.1.0 release, installation and verification details](docs/V3_1_RELEASE.md)
- [Advanced commands, YAML, budgets, resume and exports](docs/ADVANCED_USAGE.md)
- [Tool pins, installation and safety boundaries](docs/TOOLS.md)
- [V3 architecture and intelligence pipeline](docs/V3_ARCHITECTURE.md)
- [V3 regression scenarios and screenshots](docs/V3_REGRESSION.md)
- [3.1.0 progress checklist](docs/V3_1_PROGRESS.md)
