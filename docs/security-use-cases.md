# Security Use-Case Matrix

PatchPivot is designed for defensive, authorized research. The repo can expand
across several security workflows while preserving the same evidence model:
source, diff, harness, crash, triage, artifact, and disclosure records.

## Patch and Variant Research

Use PatchPivot to:

- watch upstream security patches
- queue candidate investigations
- diff vulnerable and fixed versions
- identify the patched primitive
- search sibling code paths
- document variant candidates
- produce coordinated disclosure packages

Primary artifacts:

- `intel/sources.md`
- `diff/patch-analysis.txt`
- `README.md` variant table
- `disclosure.md`

## Native Windows Host Security

Use Windows native MCP tools to:

- collect host build, PowerShell, WSL, and hypervisor posture
- read Microsoft Defender state and signature freshness
- run bounded Defender custom scans on workspace or artifact files
- query local System, Application, Defender, PowerShell, and Security logs
- capture firewall profile posture
- check optional features such as Hyper-V, Windows Sandbox, WSL, and Virtual
  Machine Platform

Primary artifacts:

- `triage/windows-*.json`
- `triage/runs/<run_id>/run.json`
- `diff/artifact-manifest-*.json`

Controls:

- keep Windows execution non-interactive and headless
- require finding scope for `windows.run`
- do not store Defender exclusions, credentials, or private host data in Git
- do not use MCP to disable security controls or add exclusions
- do not scan arbitrary system paths through MCP

## Binary-Only Product Analysis

Use headless Ghidra to:

- import vulnerable and fixed binaries
- export function lists and symbols
- compare call graphs
- map binary changes back to advisory claims
- identify reachable sibling functions

Primary artifacts:

- `diff/ghidra/<build>/program-metadata.json`
- `diff/ghidra/<build>/functions.jsonl`
- `diff/ghidra/<build>/symbols.jsonl`
- external Ghidra project in artifact storage

## Fuzzing and Harness Development

Use the lab to:

- build minimal parser or syscall harnesses
- run sanitizer-instrumented tests
- fuzz authorized local targets
- minimize crashes
- compare vulnerable and patched behavior

Primary artifacts:

- `harness/`
- `crashes/seeds/`
- `crashes/*.txt`
- `triage/*.txt`

Raw fuzzer output belongs outside Git.

## Kernel, Driver, and System Library Research

Use PatchPivot for:

- syscall and ioctl patch review
- kernel subsystem variant mapping
- sanitizer-backed reproducers
- QEMU or VM-based target validation
- downstream distro backport checks

Controls:

- use disposable VMs
- snapshot before test runs
- keep target networking private
- keep kernel crash dumps outside Git unless minimized

## Browser, JIT, and Rendering Research

Use PatchPivot for:

- compiler pass variant tracking
- rendering backend comparison
- sanitizer test-case reduction
- source search across V8, JSC, ANGLE, WebKit, and Chromium
- headless build and test orchestration

Controls:

- avoid live browsing targets
- use local test pages and corpora
- do not include exploit-chain payloads

## Crypto, Parser, and File-Format Research

Use PatchPivot for:

- ASN.1, X.509, DER, CMS, image, archive, and document parser diffing
- proof input generation
- parser harness fuzzing
- fixed-version comparison
- downstream fork audits

Primary artifacts:

- seed generators under `harness/`
- minimized inputs under `crashes/`
- parser call graph notes under `diff/`

## Supply Chain and Downstream Patch Audits

Use PatchPivot to:

- compare upstream fixes to distro packages
- track backport completeness
- hash vendor binaries
- generate artifact manifests
- document residual exposure in downstream forks

Primary artifacts:

- `schemas/artifact-manifest.schema.json`
- manifests under `diff/`
- package metadata in `intel/sources.md`

## Firmware and Appliance Research

Use PatchPivot for:

- firmware unpacking in an isolated lab
- binary import into headless Ghidra
- function and string export
- version and patch comparison
- emulator or local-device validation when authorized

Controls:

- do not connect unmanaged devices to production networks
- keep vendor firmware artifacts in external storage
- document hashes and source URLs

## Malware-Analysis and AV Validation Labs

Use PatchPivot only for defensive evidence:

- observe whether a crash sample or parser input is detected
- validate internal detections
- compare telemetry between vulnerable and patched versions
- document indicators for remediation

Hard boundaries:

- no evasion work
- no persistence
- no credential access
- no public multi-scanner uploads for private or embargoed samples

## Cloud Worker Expansion

Use ephemeral cloud workers for:

- large builds
- headless Ghidra export
- sanitizer test suites
- long-running fuzzing
- artifact hashing

Controls:

- no long-lived credentials
- egress restrictions
- encrypted artifact storage
- job-level logs
- teardown after each run

## CI and Quality Gates

Future CI can validate:

- README and docs links
- target config shape
- finding directory structure
- scope file presence
- disclosure table completeness
- schema validity for run logs and manifests
- MCP self-test

CI should not run exploit proofs, live network tests, or disclosure actions.

## Disclosure and Audit

Use PatchPivot to:

- keep a timeline per finding
- cross-reference `disclosures/log.md`
- preserve reproduction environments
- store artifact hashes
- separate raw lab output from polished evidence
- ensure every finding lands in a coordinated terminal

Terminals:

- HackerOne
- Bugcrowd
- vendor PSIRT
- CERT/CC
- internal write-up
- published advisory after coordination
