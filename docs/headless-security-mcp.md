# Headless Security MCP

PatchPivot ships a dependency-free MCP server for defensive security research
automation:

```sh
npm run mcp:security
```

The server uses MCP stdio JSON-RPC and exposes tools for:

- probing the local Windows/WSL/Ghidra environment
- checking execution policy
- running scoped native Windows PowerShell commands
- reading Microsoft Defender, Firewall, and Event Log posture
- listing and updating finding status
- running scoped headless Kali commands through WSL
- running Ghidra `analyzeHeadless`
- hashing files or directories into artifact manifests

It never starts a GUI. GUI launchers are blocked by policy, host GUI environment
variables are stripped from child processes, and Ghidra is invoked only through
`support/analyzeHeadless.bat`.

## Local Setup

This workspace is currently Windows-first.

Detected local assumptions:

- repository: `C:\GitHub\patchpivot`
- Ghidra: `C:\ghidra_12.1_PUBLIC`
- headless Ghidra: `C:\ghidra_12.1_PUBLIC\support\analyzeHeadless.bat`
- expected Kali WSL distro name: `kali-linux`

Your current WSL inventory may not include Kali yet. The MCP server will still
start and report that through `security.probe`; `kali.run` will fail until the
configured Kali distro exists.

## Configuration

Copy the example config for local edits:

```powershell
Copy-Item config\security-mcp.example.json config\security-mcp.local.json
```

`config/security-mcp.local.json` is ignored by Git. Use it for machine-specific
paths and local policy choices.

Important fields:

```json
{
  "workspaceRoot": "C:\\GitHub\\patchpivot",
  "artifactRoot": "C:\\PatchPivotArtifacts",
  "headlessOnly": true,
  "requireScopeFile": true,
  "scopeAuthorizedMarker": "MCP-LAB-AUTHORIZED: yes",
  "kali": {
    "backend": "wsl",
    "distribution": "kali-linux",
    "user": "",
    "allowNetworkModes": ["off"]
  },
  "windows": {
    "powershell": "powershell.exe",
    "defaultTimeoutSeconds": 300,
    "maxTimeoutSeconds": 3600,
    "allowNetworkModes": ["off"],
    "defaultNetworkMode": "off",
    "allowDefenderScan": true,
    "allowEventLogQuery": true
  },
  "ghidra": {
    "analyzeHeadless": "C:\\ghidra_12.1_PUBLIC\\support\\analyzeHeadless.bat",
    "projectRoot": "C:\\PatchPivotArtifacts\\ghidra\\projects"
  }
}
```

You may also set:

```powershell
$env:PATCHPIVOT_MCP_CONFIG="C:\GitHub\patchpivot\config\security-mcp.local.json"
$env:PATCHPIVOT_KALI_DISTRO="kali-linux"
$env:PATCHPIVOT_KALI_USER="bo"
$env:PATCHPIVOT_GHIDRA_HEADLESS="C:\ghidra_12.1_PUBLIC\support\analyzeHeadless.bat"
$env:PATCHPIVOT_ARTIFACT_ROOT="C:\PatchPivotArtifacts"
```

## MCP Client Entry

Use this command in an MCP client that supports stdio servers:

```json
{
  "patchpivot-security": {
    "command": "node",
    "args": [
      "C:\\GitHub\\patchpivot\\scripts\\mcp\\patchpivot-security-mcp.mjs"
    ],
    "env": {
      "PATCHPIVOT_MCP_CONFIG": "C:\\GitHub\\patchpivot\\config\\security-mcp.local.json"
    }
  }
}
```

## Kali WSL Backend

The server expects a WSL distribution named `kali-linux` by default.
If your Kali account should run as a specific non-root user, set:

```json
{
  "kali": {
    "distribution": "kali-linux",
    "user": "bo"
  }
}
```

After Kali is installed, install the broad research toolset inside Kali:

```sh
sudo apt update
sudo apt install -y kali-linux-everything
```

That package is intentionally large. For smaller labs, install only the tool
families required by the active finding.

The MCP server runs commands through:

```text
wsl.exe -d kali-linux -u <configured-user> --cd <finding-or-artifact-path> -- env -i ... bash -lc <command>
```

The environment is intentionally sparse:

- `DISPLAY`, `WAYLAND_DISPLAY`, WSLg, and related GUI variables are removed
- `TERM=dumb`
- `DEBIAN_FRONTEND=noninteractive`
- `PATCHPIVOT_ROOT`, `PATCHPIVOT_FINDING`, and `PATCHPIVOT_ARTIFACT_ROOT` are set

Do not store sudo passwords in PatchPivot config, MCP client config, environment
variables, findings, logs, or docs. Run privileged Kali setup interactively
outside MCP, use a disposable root setup shell, or configure narrow
least-privilege `sudo -n` rules for specific lab maintenance commands.

## Scope Files

By default, `kali.run` and `ghidra.analyze` require:

```text
findings/<slug>/intel/scope.md
```

The file must contain:

```text
MCP-LAB-AUTHORIZED: yes
```

New investigations inherit a template with `no`. Change it only after the
operator has confirmed authorization, target versions, artifacts, and lab
boundaries.

## Tools

### `security.probe`

Returns:

- Node and OS details
- workspace and artifact paths
- WSL distributions
- configured Kali distro availability
- configured Ghidra path
- active policy summary

### `policy.explain`

Returns blocked GUI, offensive, network, and destructive command patterns. This
is documentation at runtime: MCP clients can inspect the policy before planning
tool calls.

### `policy.check_command`

Checks a command without execution or scope authorization.

Examples:

```json
{"command":"xterm","network":"off"}
```

returns `allowed: false`.

```json
{"command":"echo patchpivot-headless","network":"off"}
```

returns `allowed: true`.

### `windows.probe`

Reports native Windows build, PowerShell, Defender, Firewall, Event Log, WSL,
hypervisor, and optional-feature state. Optional-feature checks may return
per-feature elevation errors.

### `windows.run`

Runs a scoped, non-interactive PowerShell command on the Windows host. It uses
the same finding scope gate as `kali.run` and writes logs under `triage/runs/`.

### `windows.defender_status`

Reads selected Microsoft Defender status and preference posture without
including exclusion paths.

### `windows.defender_scan`

Runs a Defender custom scan against a path under `workspaceRoot` or
`artifactRoot`. It does not scan arbitrary system paths through MCP.

### `windows.eventlog_query`

Runs bounded local event-log queries and can write JSON evidence into a finding.

### `windows.firewall_profiles`

Reads Domain, Private, and Public Windows Firewall profile posture.

### `windows.optional_features`

Probes optional features such as Hyper-V, Windows Sandbox, WSL, Virtual Machine
Platform, and Defender Application Guard. It reports elevation errors rather
than prompting.

### `finding.list`

Lists findings and README statuses.

### `finding.update_status`

Updates the status token in `findings/<slug>/README.md`.

Allowed statuses:

```text
recon acquire bindiff variant fuzz triage poc disclose closed
```

### `kali.run`

Runs a scoped command in Kali WSL after policy checks.

Required:

- finding
- command

Optional:

- cwd
- timeoutSeconds
- network
- dryRun

`network` defaults to `off`. The example policy only allows `off`.

Generated logs are written under:

```text
findings/<slug>/triage/runs/<run_id>/
```

That path is ignored by Git because command output can be noisy or sensitive.
Promote only useful summaries into `triage/`, `diff/`, or `crashes/`.

### `ghidra.probe`

Checks whether `analyzeHeadless.bat`, the script path, and the configured
project root are available.

### `ghidra.analyze`

Runs:

```text
C:\ghidra_12.1_PUBLIC\support\analyzeHeadless.bat
```

with the bundled post-script:

```text
scripts/ghidra/ExportPatchPivotSummary.java
```

Outputs are written under:

```text
findings/<slug>/diff/ghidra/<outputName>/
  functions.jsonl
  program-metadata.json
  strings.txt
  symbols.jsonl
```

Large Ghidra projects stay in the artifact root.

### `artifact.manifest`

Hashes a file or directory and can write a manifest under a finding.

Schema:

```text
schemas/artifact-manifest.schema.json
```

## Policy Boundaries

The MCP server is a guardrailed automation layer, not a perfect sandbox.

Always pair it with:

- WSL or VM isolation
- host firewall controls
- snapshots
- non-production target images
- least-privilege artifact storage
- human approval before disclosure or external communication

Hard boundaries:

- no GUI
- no third-party targets by default
- no credential access
- no persistence
- no stealth
- no destructive payloads
- no autonomous public disclosure

## Verification

Run:

```sh
npm run mcp:self-test
```

The self-test verifies:

- MCP initialization
- tool listing
- environment probe
- GUI command blocking
- harmless headless command allowance
- native Windows firewall profile query
- Microsoft Defender status query
- bounded Windows event-log query

It does not execute Kali commands or run Ghidra analysis.
