# PatchPivot

PatchPivot is a defensive variant-analysis workspace for tracking security
patches, organizing reproducible research, and carrying findings through
responsible disclosure.

This repository is not an exploitation framework and is not a replacement for
human authorization, scoping, or disclosure review. It is a workbench for
defensive vulnerability research: patch diffing, source review, binary
analysis, fuzzing harnesses, crash triage, variant mapping, and coordinated
reporting.

PatchPivot can be driven manually, by an MCP-aware research CLI such as a
proprietary Vigilant Ink Security CLI, by `erosolar --profile variant-research`,
or by any orchestrator that can read and write the investigation directories
described below.

## Core Research Model

The workflow starts from a recently fixed vulnerability or security-relevant
commit:

1. Identify the patch, advisory, affected version range, and bug class.
2. Compare vulnerable and patched code to isolate the primitive that changed.
3. Search for related code paths where the same primitive may still exist.
4. Build minimal harnesses around the relevant parser, syscall, library, or
   binary interface.
5. Fuzz and triage crashes inside an isolated lab.
6. Reduce evidence to a defensible proof of impact.
7. Report through HackerOne, Bugcrowd, vendor PSIRT, CERT/CC, an internal
   advisory process, or another authorized coordinated disclosure channel.

PatchPivot intentionally separates the durable research record from bulky,
environment-specific artifacts. The repository stores source notes, harness
code, minimized proof material, and disclosure records. Large binaries,
decompiler projects, raw fuzzing corpora, VM images, crash dumps, and tool
caches should live outside the repo in an artifact store.

## Repository Layout

```text
targets.yaml
  Watchlist of products, source repositories, advisory feeds, bounty or PSIRT
  channels, and notes about why each product is useful for variant analysis.

scripts/patch-watch.mjs
  Dependency-light Node.js watcher. It mirrors watched Git repositories,
  searches new commit messages for security-relevant terms, and queues candidate
  investigations under findings/.

scripts/new-investigation.sh
  Manual investigation bootstrapper. It copies findings/_template to a new
  finding directory named by CVE, commit, or short slug.

scripts/mcp/patchpivot-security-mcp.mjs
  Dependency-free MCP stdio server for headless-only defensive lab automation.
  It exposes policy checks, finding helpers, scoped Kali WSL execution,
  headless Ghidra analysis, and artifact manifests.

scripts/vigil/patchpivot-vigil.mjs
  PatchPivot-to-Vigil bridge. It probes the local Vigil source checkout, exports
  a Vigil-shaped findings bundle, and writes project-local .vigil/mcp.json.

scripts/ghidra/ExportPatchPivotSummary.java
  Ghidra analyzeHeadless post-script that exports program metadata, functions,
  symbols, and strings into a finding's diff/ghidra directory.

sop/patch-watch.md
  Operational procedure for running the watcher, filtering candidates, and
  enforcing disclosure-terminal requirements.

config/security-mcp.example.json
  Example local policy and path configuration for the MCP server.

config/vigil-mcp.example.json
  Example Vigil project MCP config that mounts PatchPivot's guarded MCP server.

docs/
  Headless MCP setup notes, Vigil integration, native Windows coverage, and the
  security use-case matrix.

schemas/
  JSON Schemas for MCP run logs, artifact manifests, and Vigil findings bundles.

state/watch-state.json
  Per-target watcher state. The first run for a target seeds lastSha. Later runs
  compare lastSha..HEAD and queue matching commits.

findings/_template/
  Skeleton investigation structure.

findings/<slug>/
  One investigation. The slug is usually a CVE identifier, target-shortSha, or
  short vulnerability name.

disclosures/log.md
  Cross-investigation disclosure ledger.
```

An investigation directory normally contains:

```text
findings/<slug>/
  README.md
    Investigation summary, status, source patch, hypothesis, variants, and
    disclosure state.

  intel/sources.md
    Advisory URLs, CVE records, patch commits, mailing-list references, vendor
    statements, version ranges, and scoping notes.

  diff/
    Patch analysis, changed-function lists, source-level comparisons,
    decompiler notes, call graphs, and variant-search results.

  harness/
    Reproducers, fuzz harnesses, seed generators, build scripts, and minimal
    target drivers. Harnesses should prove reachability without adding
    weaponized post-exploitation behavior.

  crashes/
    Minimized inputs, sanitizer logs, fault summaries, and stable reproduction
    notes. Raw fuzzing output belongs outside the repo.

  triage/
    GDB, LLDB, WinDbg, sanitizer, rr, core-file, or headless Ghidra correlation
    notes.

  disclosure.md
    Coordinated disclosure write-up and timeline.
```

## Requirements

Minimum local requirements:

- Git
- Node.js 18 or newer for `scripts/patch-watch.mjs`
- Bash, WSL, Git Bash, or another POSIX-compatible shell for
  `scripts/new-investigation.sh`

Recommended research tooling:

- Kali Linux with the `kali-linux-everything` metapackage for a broad toolset
- AFL++, libFuzzer, honggfuzz, or target-native fuzzers
- GCC, Clang, sanitizer runtimes, CMake, Make, Ninja, and target build systems
- GDB, LLDB, rr, strace, ltrace, perf, bpftrace, valgrind, and core dump tools
- Ghidra with `analyzeHeadless` for repeatable decompilation pipelines
- BinDiff, Diaphora, Semgrep, CodeQL, Joern, cscope, ctags, or tree-sitter tools
- QEMU, Docker, Podman, systemd-nspawn, Firecracker, or cloud VMs for isolation
- Vendor-specific SDKs, symbols, debug packages, firmware images, or source
  mirrors when authorized

This repository ships a headless-only MCP server for Windows-hosted lab control.
It does not ship a Kali image or proprietary Vigilant Ink Security CLI source.
The MCP server is an integration layer over local WSL Kali and local headless
Ghidra.

## Quick Start

Create a manual investigation:

```sh
./scripts/new-investigation.sh CVE-YYYY-NNNNN
cd findings/CVE-YYYY-NNNNN
```

Populate `intel/sources.md` and `README.md`, then drive the investigation with
your preferred operator:

```sh
erosolar --profile variant-research "investigate the patch referenced in intel/sources.md"
```

or, for an MCP-aware proprietary CLI:

```sh
vigilant-ink research run \
  --workspace "$PWD" \
  --profile variant-analysis \
  --finding "$PWD"
```

The exact CLI name and flags depend on the private implementation. The important
contract is that the orchestrator treats the finding directory as the source of
truth and writes durable evidence back into the expected subdirectories.

Run the patch watcher:

```sh
node scripts/patch-watch.mjs --dry-run
node scripts/patch-watch.mjs
```

Run one target only:

```sh
node scripts/patch-watch.mjs --target=openssl
```

Limit fallback date range when no previous state exists:

```sh
node scripts/patch-watch.mjs --since=4w
```

The first run for each target seeds `state/watch-state.json` and queues nothing.
The second and later runs queue candidate investigations.

## Built-In Headless MCP Server

PatchPivot includes a dependency-free MCP stdio server:

```sh
npm run mcp:security
```

Validate the server without running Kali or Ghidra:

```sh
npm run mcp:self-test
```

The server exposes:

- `security.probe`: inspect Windows, WSL, Kali, Ghidra, workspace, and policy
- `vigil.probe`: inspect Vigil source/config/build integration state
- `vigil.findings_bundle`: export findings in Vigil's normalized bundle shape
- `vigil.project_mcp_config`: render the recommended project `.vigil/mcp.json`
- `policy.explain`: return the active headless-only guardrails
- `policy.check_command`: evaluate a proposed Kali or Windows command without execution
- `windows.probe`: inspect native Windows security/tooling surface
- `windows.run`: run scoped, policy-filtered, non-interactive PowerShell
- `windows.defender_status`: read Microsoft Defender posture
- `windows.defender_scan`: run bounded Defender custom scans
- `windows.eventlog_query`: query local Windows event logs
- `windows.firewall_profiles`: read Windows Firewall profile posture
- `windows.optional_features`: probe Hyper-V, Sandbox, WSL, and related features
- `finding.list`: list finding slugs and statuses
- `finding.update_status`: update a finding status token
- `kali.run`: run a scoped command in the configured Kali WSL distro
- `ghidra.probe`: verify `analyzeHeadless` configuration
- `ghidra.analyze`: run Ghidra headlessly and export summary files
- `artifact.manifest`: hash files or directories into JSON manifests

Hard defaults:

- GUI tooling is blocked
- Ghidra is invoked only through `analyzeHeadless`
- `kali.run` and `windows.run` default to `network=off`
- lab execution requires `intel/scope.md` with `MCP-LAB-AUTHORIZED: yes`
- generated run logs stay under ignored `findings/<slug>/triage/runs/`

Local setup details are in `docs/headless-security-mcp.md`. Vigil by Trenchwork
integration is detailed in `docs/vigil-integration.md`. Native Windows coverage
is detailed in `docs/windows-native-security.md`. Broader defensive expansion
patterns are in `docs/security-use-cases.md`.

## Vigil by Trenchwork Integration

PatchPivot works with [Vigil by Trenchwork](https://trenchwork.org/vigil) in two
ways:

1. Vigil mounts PatchPivot as a project-local MCP server and calls the guarded
   PatchPivot tools during an operator session.
2. Vigil's existing security-analysis pipeline ingests PatchPivot findings from
   the sibling source checkout.

Current local source layout:

```text
C:\GitHub\patchpivot
C:\GitHub\vigil-by-trenchwork
```

Install the project-local Vigil MCP config:

```powershell
cd C:\GitHub\patchpivot
npm run vigil:install
```

Then build Vigil if `dist/` is missing and launch it from the PatchPivot working
directory:

```powershell
cd C:\GitHub\vigil-by-trenchwork
npm install
npm run build

cd C:\GitHub\patchpivot
node C:\GitHub\vigil-by-trenchwork\dist\bin\vigil.js --profile vigil-code
```

Inside Vigil, PatchPivot tools appear with the `mcp__patchpivot_security__`
prefix, for example `mcp__patchpivot_security__vigil_probe`,
`mcp__patchpivot_security__kali_run`, and
`mcp__patchpivot_security__ghidra_analyze`.

Verify the integration:

```powershell
npm run vigil:probe
npm run vigil:smoke
```

The generated `.vigil/mcp.json` is ignored by Git and must not contain sudo
passwords, API keys, portal credentials, or other secrets.

## Proprietary CLI Integration Contract

If a proprietary Vigilant Ink Security CLI is used to drive PatchPivot, treat the
CLI as an orchestration layer rather than a hidden database. The CLI may be
closed-source, but the research record it produces should remain inspectable in
this repository.

Recommended responsibilities:

- read target and finding metadata from the workspace
- start scoped MCP tool calls for Kali, source analysis, fuzzing, triage, and
  headless Ghidra
- write durable output files under the active finding directory
- register large artifacts by hash
- maintain run logs with timestamps, commands, tool versions, and exit codes
- enforce scope files and disclosure guardrails
- refuse unsafe or out-of-scope execution by default

Recommended commands:

```sh
vigilant-ink research init --workspace /work/patchpivot
vigilant-ink research list --workspace /work/patchpivot --status recon
vigilant-ink research run --finding /work/patchpivot/findings/CVE-YYYY-NNNNN
vigilant-ink research status --finding /work/patchpivot/findings/CVE-YYYY-NNNNN
vigilant-ink artifact register --finding /work/patchpivot/findings/CVE-YYYY-NNNNN --path /artifacts/file
vigilant-ink mcp serve --config /secure/vigilant-ink/mcp.json
```

Recommended exit codes:

```text
0   completed
1   general failure
2   invalid arguments or missing finding
3   scope file missing or invalid
4   tool unavailable
5   command refused by policy
6   artifact registration failed
7   disclosure action requires human approval
```

Recommended JSON-lines event stream:

```json
{"event":"run.started","finding":"CVE-YYYY-NNNNN","run_id":"2026-06-14T120000Z-operator-host"}
{"event":"tool.started","tool":"ghidra_headless.analyze","artifact":"sha256:..."}
{"event":"artifact.created","path":"/artifacts/patchpivot/...","sha256":"..."}
{"event":"finding.updated","status":"triage","file":"triage/gdb.txt"}
{"event":"run.finished","exit_code":0}
```

Recommended proprietary-source boundary:

- keep private CLI source in a separate private repository or signed package
- commit only public integration contracts, schemas, and generated evidence here
- record CLI version, MCP server versions, and policy bundle hash in each run log
- never commit API tokens, portal credentials, private exploit material, or
  customer data

Suggested run-log location:

```text
findings/<slug>/triage/runs/<run_id>.json
```

Suggested run-log minimum fields:

```json
{
  "run_id": "2026-06-14T120000Z-operator-host",
  "cli": {
    "name": "vigilant-ink",
    "version": "private-build",
    "policy_sha256": "..."
  },
  "finding": "CVE-YYYY-NNNNN",
  "workspace": "/work/patchpivot",
  "artifact_root": "/artifacts/patchpivot",
  "mcp_servers": [
    {"name": "kali_lab", "version": "..."},
    {"name": "ghidra_headless", "version": "..."}
  ],
  "outputs": [
    "diff/patch-analysis.txt",
    "triage/gdb.txt"
  ]
}
```

## Watcher Internals

`scripts/patch-watch.mjs` is intentionally small and auditable.

Input:

- `targets.yaml`
- `state/watch-state.json`
- command-line flags: `--target`, `--since`, `--dry-run`

Local cache:

- `.cache/mirrors/<target>` stores bare Git mirrors
- mirrors are created with `git clone --bare --filter=blob:none`
- existing mirrors are updated with `git fetch --filter=blob:none origin`

State behavior:

- if a target has no `lastSha`, the watcher records current `HEAD` and queues
  zero investigations
- if a target has `lastSha`, the watcher inspects `lastSha..HEAD`
- after a non-dry run, `lastSha` advances to current `HEAD`

Candidate heuristic:

- commit subject and body are scanned with a security-focused regular expression
- terms include CVE identifiers, security fixes, hardening, memory-corruption
  classes, sanitizer references, syzbot, race conditions, side channels, and
  common overflow terminology
- the heuristic intentionally prefers false positives over missed candidates

Queue output:

```text
findings/<target>-<shortSha>/README.md
findings/<target>-<shortSha>/intel/sources.md
```

The queued `intel/sources.md` includes:

- commit SHA
- upstream repository URL
- guessed commit view URL
- commit subject
- first 60 lines of commit body
- advisory feed
- configured disclosure or bounty channel

The watcher is not a vulnerability oracle. It is a triage feeder.

## Target Configuration

Targets are declared in `targets.yaml`:

```yaml
targets:
  - name: openssl
    product: OpenSSL
    repo: https://github.com/openssl/openssl
    advisory: https://www.openssl.org/news/secadv/
    bounty: ""
    notes: ASN.1, X.509 parsers; cluster bugs.
```

Fields:

- `name`: short stable slug used for cache and finding names
- `product`: human-readable product label
- `repo`: upstream source repository URL
- `advisory`: vendor advisory feed, RSS feed, mailing list, or portal URL
- `bounty`: disclosure program URL when one exists
- `notes`: portfolio rationale and bug-class hints

Good targets usually have:

- regular security patch volume
- a bug class with variant potential
- reachable source or binary distributions
- testable historical vulnerable versions
- clear disclosure paths
- authorization for the work being performed

Current checked-in targets include Linux kernel, Chromium/V8, OpenSSL, WebKit,
and glibc.

## Investigation Statuses

Use these statuses consistently in `findings/<slug>/README.md`:

```text
recon
  Patch/advisory identified. Scope, affected versions, and authorization still
  being established.

acquire
  Source, binary, symbols, debug packages, containers, firmware, or vulnerable
  builds are being obtained.

bindiff
  Vulnerable and patched versions are being compared at source, IR, decompiler,
  or binary level.

variant
  Sibling functions, call sites, parser branches, compiler passes, backends, or
  related products are being searched.

fuzz
  Harnesses and corpora are exercising suspected variant surfaces.

triage
  Crashes or suspicious behavior are being reduced and correlated with code.

poc
  Minimal proof material exists for the authorized environment.

disclose
  Report is prepared or submitted through an approved channel.

closed
  Coordinated disclosure terminal has been recorded and the investigation has no
  remaining tracked action.
```

## Research Phases

### 1. Recon

Record:

- CVE or advisory identifier
- vendor advisory URL
- patch commit or release tag
- affected versions
- fixed versions
- target component
- bug class and CWE when known
- reachable attack surface
- disclosure program or PSIRT route
- authorization notes

Output:

- `intel/sources.md`
- initial `README.md` hypothesis

### 2. Acquire

Collect only what is needed and legally permitted:

- vulnerable source checkout
- patched source checkout
- release tarballs
- debug symbols
- container image or VM snapshot
- target binaries
- test corpus
- build scripts
- exact compiler and dependency versions

Record SHA-256 hashes for binaries and large inputs. Keep heavy artifacts out of
Git.

Suggested external artifact layout:

```text
~/.patchpivot/artifacts/<sha256>/
  original-name
  metadata.json
  source-url.txt
  build-log.txt
```

### 3. Diff

For source-available targets:

- inspect patch hunks
- identify changed functions and call sites
- locate added bounds checks, lifetime changes, type checks, parser state
  transitions, integer-size changes, or error-handling changes
- compare vulnerable and fixed control flow
- write the exact primitive in plain language

For binary-only targets:

- import vulnerable and patched binaries into Ghidra or another RE tool
- run headless analysis with identical settings
- export function hashes, symbol tables, call graphs, strings, and decompiled
  changed functions
- compare function similarity with BinDiff, Diaphora, or a custom script
- confirm changes against runtime traces when possible

Output:

- `diff/patch-analysis.txt`
- changed-function lists
- call graph notes
- decompiler snippets where useful

### 4. Variant Search

Search for code that repeats the same unsafe assumption:

- same helper API used without the new guard
- same parser state machine in another file format
- same backend implementation in a different platform layer
- same compiler optimization in another IR node or tier
- same syscall, ioctl, socket family, or protocol operation
- same arithmetic pattern with different field names
- same allocation/copy/free sequence in neighboring code
- downstream forks missing the upstream patch

Record candidates in the `Variants` table with status and rationale.

### 5. Harness

Harnesses should be minimal, reproducible, and scoped:

- isolate the suspected parser or function
- avoid network scanning or third-party systems
- prefer local files, stdin, synthetic sockets, or test fixtures
- build with sanitizers when available
- pin compiler flags and target versions
- produce deterministic output

Useful build modes:

```sh
CC=clang CFLAGS="-g -O1 -fsanitize=address,undefined" make
afl-clang-fast -g -O1 -fsanitize=address -o harness/fuzz-harness harness/fuzz-harness.c
```

Do not turn a proof into a weapon. The goal is to prove reachability and impact
inside the authorized lab, not to add persistence, stealth, lateral movement,
credential access, or payload delivery.

### 6. Fuzz

For fuzzing:

- start with patch-derived seeds
- keep raw fuzzer output outside the repo
- minimize crashing inputs before committing
- store sanitizer logs and reproduction commands
- record corpus provenance
- separate suspected duplicates from unique root causes

Recommended external layout:

```text
~/.patchpivot/fuzz/<finding>/<harness>/
  in/
  out/
  minimized/
  logs/
```

Commit only stable, minimal, disclosure-safe inputs under `crashes/`.

### 7. Triage

Correlate crash behavior with code:

- sanitizer report
- debugger backtrace
- register and memory summary
- crashing input hash
- vulnerable and patched reproduction result
- exact commit or package version
- decompiler/source line mapping
- exploitability assessment limited to impact classification

Output:

- `triage/*.txt`
- `crashes/*.txt`
- updated `README.md` status and variant table

### 8. Disclosure

Every investigation must end in a coordinated channel:

- HackerOne
- Bugcrowd
- vendor PSIRT
- CERT/CC
- internal write-up
- published advisory after the applicable coordination period

`disclosure.md` should include:

- summary
- affected products and versions
- fixed versions when known
- vulnerability class
- impact
- reproduction environment
- minimal proof material
- variant analysis
- remediation guidance
- timeline
- reporter and contact information

Update `disclosures/log.md` after submission.

## MCP-Driven Expansion

MCP is useful as the control plane for repeatable research. PatchPivot expects
MCP tools to operate on explicit finding directories and produce auditable files,
not hidden chat-only state.

Recommended MCP tool groups:

```text
workspace
  Read and write investigation files, list findings, update statuses, register
  artifacts, and append disclosure log rows.

git_source
  Clone, fetch, checkout vulnerable and patched revisions, compute patch hunks,
  list changed functions, and run text or AST searches.

kali_lab
  Run authorized commands inside an isolated Kali VM/container with
  kali-linux-everything installed. Capture stdout, stderr, exit code, tool
  versions, and produced artifacts.

ghidra_headless
  Import binaries, run analyzeHeadless, execute scripts, export decompilation,
  recover call graphs, and compare vulnerable vs patched functions.

fuzzing
  Build harnesses, launch fuzzers, stop fuzzers, minimize crashes, and summarize
  coverage and unique faults.

triage
  Run GDB/LLDB/rr/sanitizers, collect traces, symbolize crashes, and correlate
  runtime faults with source or decompiler locations.

disclosure
  Render report drafts, validate timelines, and prepare submission packages for
  human review.
```

MCP safety controls:

- require an explicit `finding` path for every tool call
- require an explicit authorization scope file before lab execution
- default network access to off unless the task requires fetching public source
- block commands that target third-party IP ranges unless scope allows them
- mount the repo read-write and large artifacts read-write in separate paths
- record command, working directory, timestamp, exit code, and artifact hashes
- redact secrets before writing logs
- require human approval before public disclosure or external submission

Example `kali_lab.run` request:

```json
{
  "finding": "/work/patchpivot/findings/CVE-YYYY-NNNNN",
  "cwd": "/work/patchpivot/findings/CVE-YYYY-NNNNN",
  "command": ["bash", "-lc", "make -C harness test"],
  "network": "off",
  "timeout_seconds": 1800,
  "artifact_root": "/artifacts/patchpivot",
  "scope_file": "intel/scope.md"
}
```

Example `kali_lab.run` response:

```json
{
  "exit_code": 0,
  "stdout_path": "triage/runs/run-id/stdout.txt",
  "stderr_path": "triage/runs/run-id/stderr.txt",
  "artifacts": [
    {
      "path": "/artifacts/patchpivot/build/harness-test.log",
      "sha256": "..."
    }
  ],
  "tool_versions": {
    "gcc": "recorded by runner",
    "afl-fuzz": "recorded by runner"
  }
}
```

Example `ghidra_headless.analyze` request:

```json
{
  "finding": "/work/patchpivot/findings/CVE-YYYY-NNNNN",
  "binary": "/artifacts/vendor/vulnerable.bin",
  "project_dir": "/artifacts/ghidra/projects",
  "project_name": "CVE-YYYY-NNNNN-vulnerable",
  "scripts": ["ExportFunctions.java", "ExportCallGraph.java"],
  "output_dir": "diff/ghidra/vulnerable",
  "timeout_seconds": 3600
}
```

Example `ghidra_headless.analyze` response:

```json
{
  "status": "completed",
  "program_sha256": "...",
  "exports": [
    "diff/ghidra/vulnerable/functions.json",
    "diff/ghidra/vulnerable/callgraph.dot",
    "diff/ghidra/vulnerable/strings.txt"
  ],
  "warnings": []
}
```

Example MCP environment variables:

```sh
PATCHPIVOT_ROOT=/work/patchpivot
PATCHPIVOT_FINDING=/work/patchpivot/findings/CVE-YYYY-NNNNN
PATCHPIVOT_ARTIFACT_ROOT=/artifacts/patchpivot
PATCHPIVOT_LAB_SCOPE=/work/patchpivot/findings/CVE-YYYY-NNNNN/intel/scope.md
PATCHPIVOT_RUN_ID=2026-06-14T120000Z-operator-host
```

Expected MCP run record:

```json
{
  "run_id": "2026-06-14T120000Z-operator-host",
  "finding": "CVE-YYYY-NNNNN",
  "tool": "kali_lab.run",
  "command": "afl-fuzz -i in -o out -- ./harness/fuzz-harness",
  "cwd": "/work/patchpivot/findings/CVE-YYYY-NNNNN",
  "started_at": "2026-06-14T12:00:00Z",
  "finished_at": "2026-06-14T12:30:00Z",
  "exit_code": 0,
  "artifacts": [
    {
      "path": "/artifacts/patchpivot/fuzz/CVE-YYYY-NNNNN/out",
      "sha256": "directory-manifest-sha256"
    }
  ]
}
```

## Kali Linux Everything as a Lab Backend

`kali-linux-everything` is useful because it provides a broad security research
tool inventory in one environment. In PatchPivot it should be used as an isolated
analysis backend, not as an unrestricted attack box.

Recommended setup:

```text
host OS
  Codex, editor, Git, documentation, disclosure drafting

Kali VM/container
  kali-linux-everything tools, compilers, fuzzers, debuggers, RE utilities

artifact volume
  binaries, raw fuzzing corpora, Ghidra projects, crash dumps, package mirrors

target VM/container
  vulnerable package, patched package, kernel, browser, firmware, or service
```

Isolation recommendations:

- use snapshots before each experiment
- keep target networks host-only or private by default
- disable shared clipboard and drag-drop for malware or exploit-chain research
- mount source read-only when feasible
- mount artifacts separately from the Git worktree
- never place API tokens or disclosure portal credentials inside target VMs
- log tool versions and package state with every run

Useful Kali package families:

- reverse engineering: Ghidra, radare2, binutils, strings, objdump, readelf
- debugging: gdb, lldb, strace, ltrace, rr where supported
- fuzzing: afl++, honggfuzz, radamsa, zzuf, corpus tools
- binary exploitation research: pwntools, checksec, ROPgadget for impact
  classification in authorized labs
- web/browser research: Chromium builds, WebKit dependencies, protocol tools
- source analysis: semgrep, ctags, cscope, ripgrep, tree-sitter tools
- systems research: qemu, debootstrap, chroots, kernel build dependencies

PatchPivot does not require Kali specifically. Ubuntu, Debian, Fedora, Nix,
Windows with WSL2, macOS, or cloud runners can drive the same finding structure
as long as the required tools are available.

## Headless Ghidra on Any OS

Headless Ghidra is the preferred repeatable binary-analysis backend when source
is unavailable or when the source patch must be correlated with shipped binaries.

Typical headless flow:

```sh
analyzeHeadless /artifacts/ghidra/projects CVE-YYYY-NNNNN \
  -import /artifacts/binaries/vendor/vulnerable.bin \
  -processor x86:LE:64:default \
  -analysisTimeoutPerFile 3600 \
  -scriptPath /work/ghidra-scripts \
  -postScript ExportFunctions.java \
  -postScript ExportCallGraph.java
```

Recommended exports:

- program metadata
- import table
- export table
- strings
- function list
- function hashes
- decompiled functions around the patch
- call graph
- xrefs to changed functions
- data references to changed constants
- p-code or decompiler AST for custom comparison

Suggested output location:

```text
findings/<slug>/diff/ghidra/
  vulnerable-functions.json
  patched-functions.json
  changed-functions.txt
  callgraph.dot
  decompile/
```

Headless Ghidra can run on:

- Kali or Debian lab machines
- Windows analyst workstations
- macOS workstations
- Linux cloud workers
- CI runners
- offline malware-analysis or AV-validation labs

For large targets, keep Ghidra projects outside Git and commit only exported
summaries.

## Source-Code Analysis Expansion

PatchPivot works well with source-centric security tooling:

- `rg` for fast literal and regex searches
- tree-sitter queries for syntax-aware patterns
- Semgrep for reusable bug-class rules
- CodeQL for dataflow and control-flow queries
- Joern for code property graphs
- compiler warnings and sanitizers for build-time evidence
- custom scripts that emit SARIF or JSON for repeatable findings

Variant search examples:

```sh
rg "memcpy\\(|strncpy\\(|realloc\\(" vulnerable-source/
rg "EVP_MAX_IV_LENGTH|ASN1_TYPE|octet" openssl/
rg "copy_from_iter|splice|scatterlist" linux/crypto linux/net
```

When an MCP source-analysis tool produces results, store:

```text
findings/<slug>/diff/source-query-<name>.json
findings/<slug>/diff/source-query-<name>.md
```

Each result should include:

- repository URL
- commit SHA
- query or rule identifier
- matched file and line
- why it may be a variant
- triage status

## Cloud Deployment

Cloud is useful for bursty builds, large fuzzing jobs, and headless binary
analysis. Use ephemeral infrastructure and keep sensitive material controlled.

Recommended pattern:

```text
developer workstation
  owns Git working tree and disclosure material

object storage or encrypted volume
  stores large artifacts and fuzzing corpora

ephemeral worker
  checks out repo, mounts artifact volume, runs one scoped job, uploads outputs,
  destroys itself

private network
  only allows worker-to-artifact-store and approved source-fetching routes
```

Worker requirements:

- pinned image digest
- no long-lived credentials
- least-privilege object storage access
- egress restrictions
- job-level logs
- artifact manifest with SHA-256 hashes
- automatic teardown

Good cloud jobs:

- compile vulnerable and patched targets
- run headless Ghidra export
- run sanitizer test suites
- fuzz an already authorized harness
- minimize crash corpora
- generate source-query reports

Poor cloud jobs:

- handling embargoed samples without encryption and access controls
- running unreviewed exploit chains
- scanning public address space
- storing disclosure portal credentials
- uploading sensitive crash samples to public multi-scanners

## Anti-Virus and Malware-Analysis Lab Use

Some research targets, crash samples, or generated binaries may trigger endpoint
security controls. Treat AV or EDR environments as controlled validation labs.

Appropriate uses:

- observe whether a proof binary, crash input, or parser sample is detected
- validate that internal detections cover a vulnerable parser path
- compare telemetry between vulnerable and patched versions
- document defensive indicators for a disclosure or internal advisory

Controls:

- use isolated VMs with snapshots
- keep samples off shared drives unless explicitly approved
- do not upload private vendor samples or embargoed crash files to public
  multi-scanner services
- do not attempt AV bypass, evasion, persistence, or stealth
- document engine version, signatures, policy, and timestamp
- destroy or archive samples according to lab policy

PatchPivot's AV-lab role is evidence collection for defense, not evasion.

## Disclosure Guardrails

This project assumes authorized research only.

In scope:

- source and binary diffing
- local reproduction in owned or authorized environments
- fuzzing authorized targets
- minimal proofs of reachability and impact
- coordinated disclosure
- defensive detections and remediation notes

Out of scope:

- unauthorized scanning or exploitation
- credential theft
- persistence
- stealth
- lateral movement
- destructive payloads
- public release before coordination is complete
- brokering or silent retention of vulnerabilities

Every finding must land in a disclosure terminal:

```text
hackerone
bugcrowd
vendor_psirt
cert_cc
published_advisory
internal_writeup
```

A finding is not closed until `disclosure.md` and `disclosures/log.md` reflect
the coordinated outcome.

## Adding a New Target

1. Edit `targets.yaml`.
2. Add a unique `name`.
3. Add the upstream source `repo` when available.
4. Add the advisory feed or portal.
5. Add bounty or PSIRT information.
6. Explain the target's value in `notes`.
7. Run the watcher in dry-run mode.
8. Run the watcher normally once to seed state.
9. Review queued candidates on later runs.

Example:

```yaml
  - name: example-parser
    product: Example Parser
    repo: https://github.com/example/parser
    advisory: https://example.com/security
    bounty: https://example.com/security/bounty
    notes: |
      Binary parser with repeated length-field fixes and reachable file input.
```

## Adding a New Finding

Manual path:

```sh
./scripts/new-investigation.sh CVE-YYYY-NNNNN
```

Watcher path:

```sh
node scripts/patch-watch.mjs --target=openssl
```

Then:

1. Update `findings/<slug>/README.md`.
2. Fill `intel/sources.md`.
3. Add `intel/scope.md` if an MCP or lab runner will execute tools.
4. Add diff evidence under `diff/`.
5. Add harness code under `harness/`.
6. Add minimized proof inputs and logs under `crashes/`.
7. Add debugger and decompiler notes under `triage/`.
8. Draft and submit `disclosure.md`.
9. Update `disclosures/log.md`.

## Automation Boundaries

Safe to automate:

- public patch discovery
- source checkout
- changed-function extraction
- headless decompilation
- local builds
- sanitizer test runs
- fuzzing in scoped labs
- crash minimization
- report skeleton generation
- disclosure checklist validation

Keep human-supervised:

- target authorization decisions
- claims of exploitability
- public disclosure timing
- vendor communication
- any test with network reachability outside the lab
- any proof that could be adapted for real-world compromise

## Suggested Roadmap

High-value improvements:

- replace the minimal YAML parser with a real YAML parser if the config grows
- add a `schemas/` directory for finding metadata and disclosure terminal
  validation
- add a cross-platform `new-investigation` script for Windows-native shells
- add SARIF import/export for source-analysis tools
- add SSH, Docker, and cloud-worker backends for the MCP server
- extend artifact manifests with signing and external artifact-store sync
- add CI that validates README, target config, finding structure, and disclosure
  tables
- add a dashboard over finding status and disclosure state
- add Semgrep or CodeQL rules for recurring variant classes

## Current Examples

The checked-in findings demonstrate the intended evidence shape:

- `CVE-2026-5450-GLIBC-SCANF`: glibc scanf allocation off-by-one analysis,
  sanitizer-backed harnesses, and variant notes.
- `CVE-2025-15467-OPENSSL-CMS`: OpenSSL CMS AEAD parameter parsing analysis,
  DER-generation harness, and related caller review.
- `CVE-2026-31431-COPYFAIL`: Linux kernel AF_ALG/splice variant mapping and
  reachability checker.
- `CVE-2025-12727-V8-TYPECONF`: V8 JIT type-confusion variant methodology.
- `CVE-2025-14174-WEBKIT`: ANGLE/WebKit rendering-backend variant mapping.

These examples are research records. Reproduce or extend them only in authorized
lab environments.
