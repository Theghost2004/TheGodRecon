# Contained external execution (3.1.0)

BlackBox still selects all eight registered capabilities. Customized scans still
select only their requested capabilities. No database or package version change
is required. Existing reports, graphs, analyst state and evidence layout remain.

## Linux prerequisites and verification

On Kali/Debian x86-64, an administrator can provision the optional system boundary:

```sh
sudo apt-get install bubblewrap openssl python3
python tools/bootstrap.py
reconmap doctor
reconmap tools doctor --json
```

Run reconmap as your ordinary user. The kernel/host policy must permit unprivileged
user, network and PID namespaces. Doctor probes the actual namespaces, interfaces,
capabilities, no-new-privileges and seccomp status. Installing bubblewrap alone is
insufficient. Containers with a read-only uid map, restricted hosts, Windows and
other architectures report a precise backend-unavailable reason. There is no
unsafe override, and setup does not change host security settings.

For a separately authorized target and scope:

```sh
reconmap blackbox https://authorized.example --config scope.yaml --strict-tools
reconmap scan https://authorized.example --config scope.yaml --tools 3,4,5,8 --strict-tools
```

`strict_tools: true` in YAML is equivalent. `execution_engines: {}` leaves external
selection automatic. An explicit native preference conflicts with strict tools.
Every selected binary must pass identity/version/flag checks and runtime
prerequisites **before** run allocation. Missing inputs or later execution
failures produce partial coverage; they cannot silently invoke native substitutes.
Non-strict scans prefer the external adapter and allow existing safe fallbacks
within remaining scope/budgets. Demo/offline modes prohibit active external
traffic; loopback labs disable public discovery providers.

## Network and process contract

`execution_boundary.py` mounts a private rehashed executable snapshot into a
bubblewrap user/network/PID/IPC/UTS namespace. The child sees read-only system
runtime files, input lists, optional reviewed templates and a fresh 64 MiB tmpfs.
Its environment and home are isolated. No host network interface, route, home or
runtime socket is exposed. Its only mounted IPC endpoint is a private Unix socket
connected to the Python broker.

`isolated_worker.py` runs a namespace-local HTTP proxy and DNS responder. HTTPS
CONNECT terminates TLS locally; it is **not** a blind tunnel. Every decrypted URL
and method reaches the broker before any upstream connection. The broker accepts
only unauthenticated, body-free GET requests. It uses the existing ScopePolicy,
SafeResolver, response decompression limits and shared scheduler. Request budgets,
per-host quotas, rates, time, exclusions, IP validation and redirects retain their
existing enforcement. Unknown secondary requests need existing eligible jobs or
captured JavaScript method/depth evidence. Caller-supplied Referer cannot reset
depth. Cookies and authorization are not replayed.

The child has zero capabilities and inherits no-new-privileges and a seccomp
filter denying alternate socket families (including VSOCK), alternate syscall
ABIs, io_uring and namespace changes. Timeouts/cancellation kill the process group;
the PID namespace also removes remaining descendants. The per-process address
space cap is 4 GiB, file-size cap 16 MiB, descriptor cap 256 and process limit 256.
These are not an aggregate cgroup memory quota. Output is bounded by the configured
response-byte ceiling; active invocations use the existing provider-seconds
subprocess ceiling and the remaining global time, whichever is smaller. Katana
also waits its request-timeout for queue quiescence per input root; many roots can
therefore exhaust a short process ceiling even when individual requests are fast.
Such runs retain their evidence and report partial coverage; the deadline is not
silently raised.

## Actual adapters

| Tool | Assigned work | Evidence and accounting |
|---|---|---|
| dnsx | Scoped A/AAAA/CNAME queries through namespace DNS | Broker forwards one counted/rate-limited UDP query at a time; no hidden CNAME chasing or TCP retry; actual records and wire digest retained |
| ProjectDiscovery httpx | Queued URLs, input scheme only, GET | Real JSONL metadata plus broker-captured response; existing bodies reused across tools |
| Katana | Non-headless HTML/JS crawling | Structured references plus captured relationships; proposed secondary requests still require scope, method, depth and queue admission |
| Nuclei | Two hashed local templates (`/.git/HEAD`, `/.env`) | No OAST, bulk templates, redirects or arbitrary paths; matches require actual captured signature evidence and remain investigation candidates |
| Subfinder / URLFinder | Existing approved passive-provider adapters | Returned references scope-filtered; provider request counts remain unknown |
| jsluice / Gitleaks | Existing verified offline artifact adapters | Hashed local input checkpoints, bounded process output, source provenance |

HTTP tools receive synthetic namespace DNS routing hints, which are never stored
as target infrastructure. Proxy TLS/certificate/IP telemetry is not authoritative
upstream infrastructure evidence. Current reachability comes only from broker
responses; a local proxy rejection (451) cannot become a target HTTP observation.
Shared response capture and safety parsing remain necessary even when real tools
run. No native capability is reported as external execution.

Stage results include process identity, version/hash, exit code, elapsed time,
input/output/completed-input counts, actual process-start confirmation, broker
counts, failures and fallback details. Successful evidence is committed during
execution. Resume reuses captured responses and completed tool-input checkpoints;
failed/partial work does not reset global budgets. Raw bounded tool output remains
in each invocation's existing artifact directory. Reports and the asset graph use
the same SQLite evidence pipeline.

## Validation

Portable policy/strict/partial-output tests:

```sh
python -m pytest -q tests/test_execution_boundary.py
```

Production Linux isolation and **real** pinned active tools against controlled
loopback HTTP/DNS fixtures:

```sh
python tools/install_tools.py --tool dnsx --tool httpx --tool katana --tool nuclei --directory .tools/bin
RECONMAP_REQUIRE_CONTAINMENT=1 RECONMAP_TEST_ACTIVE_TOOLS=.tools/bin python -m pytest -q tests/test_contained_linux.py
python -m pytest -q
```

`RECONMAP_REQUIRE_CONTAINMENT=1` makes unavailable isolation a failure, not a skip.
The dedicated Linux CI job requires this backend on Python 3.12 and 3.13. Ordinary
core CI can skip Linux-only tests on unsupported hosts, including Windows.
No test contacts a public scan target. The real-tool fixture verifies strict
execution, shared GET accounting, scripts/API references, reviewed exposure
matching, report/graph generation and zero-request resume. Adversarial fixtures
exercise direct child egress, decrypted HTTPS exclusions, VSOCK, output limits,
crash, timeout and cancellation.

Current execution results and unresolved checks are recorded in
[EXTERNAL_EXECUTION_PROGRESS.md](EXTERNAL_EXECUTION_PROGRESS.md). A passing mocked
adapter or help/version check is not proof of successful real target execution.

## Deliberate limits

Linux x86-64 is the only implemented active boundary. Windows native workflows
remain supported; strict active execution fails truthfully. Authenticated scans,
headless browsers, custom active flags/templates, arbitrary methods, bulk Nuclei
checks and non-HTTP protocols are not supported by this adapter profile. DNS
truncation becomes partial coverage. Unadmitted secondary references remain
inventory, without network validation. Passive providers are not covered by the
target-request broker and retain their separate approved-provider contract.
