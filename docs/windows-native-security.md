# Windows Native Security Backend

PatchPivot's MCP server can use Windows directly, without a GUI and without
requiring Kali for host-side tasks.

Start the server:

```powershell
npm run mcp:security
```

Run the self-test:

```powershell
npm run mcp:self-test
```

The self-test covers MCP initialization, native Windows firewall posture,
Microsoft Defender status, a bounded System event-log query, and Windows GUI
command blocking.

## Native Capabilities

```text
windows.probe
  Detect Windows product/build data, PowerShell version, Defender cmdlets,
  firewall cmdlets, event-log cmdlets, WSL, hypervisor state, and optional
  feature availability.

windows.run
  Run a scoped, policy-filtered, non-interactive PowerShell command under an
  authorized finding.

windows.defender_status
  Read Microsoft Defender service, signature, engine, realtime, IOAV, behavior,
  cloud, and PUA posture.

windows.defender_scan
  Run a Microsoft Defender custom scan against a workspace/artifact path.

windows.eventlog_query
  Query local Windows event logs with bounded filters and optional output into a
  finding.

windows.firewall_profiles
  Read Domain, Private, and Public firewall profile posture.

windows.optional_features
  Probe selected optional Windows features. Elevation errors are reported rather
  than prompting.
```

## Configuration

```json
{
  "windows": {
    "powershell": "powershell.exe",
    "defaultTimeoutSeconds": 300,
    "maxTimeoutSeconds": 3600,
    "allowNetworkModes": ["off"],
    "defaultNetworkMode": "off",
    "allowDefenderScan": true,
    "allowEventLogQuery": true
  }
}
```

`config/security-mcp.local.json` can override those values and is ignored by Git.

## Guardrails

Native Windows execution uses:

```text
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command <command>
```

Policy blocks common GUI, offensive, credential-access, persistence,
network-fetch, and destructive command patterns.

Examples of blocked actions:

- `Start-Process`, `explorer.exe`, browser launches, and terminal GUI tools
- `Invoke-WebRequest`, `Invoke-RestMethod`, `iwr`, `irm`, and BITS downloads
  while `network=off`
- Defender preference changes such as `Set-MpPreference`
- local user and service creation
- PowerShell remoting enablement
- destructive disk and boot tooling
- broad recursive deletion patterns against system paths

Policy checks are guardrails, not a sandbox. Pair them with standard user
execution, separate lab folders, Hyper-V/WSL isolation, firewall restrictions,
snapshots, and careful artifact handling.

## Scope Requirement

`windows.run` requires an authorized finding scope by default:

```text
findings/<slug>/intel/scope.md
```

The file must contain:

```text
MCP-LAB-AUTHORIZED: yes
```

This keeps host command execution attached to a specific investigation and audit
trail.

## Logs

`windows.run` writes logs under:

```text
findings/<slug>/triage/runs/<run_id>/
  run.json
  stdout.txt
  stderr.txt
```

Those run directories are ignored by Git. Promote only stable summaries or
minimal evidence into tracked `triage/`, `diff/`, or `crashes/` files.

`windows.defender_scan` writes logs under the finding when a finding is supplied,
or under:

```text
<artifactRoot>/windows-runs/<run_id>/
```

when it is used as a standalone host scan.

## Defender Workflow

Recommended uses:

- verify Defender service and signature posture
- custom-scan generated harnesses, crash samples, or parser inputs
- record detection state for internal defensive validation

Avoid:

- storing malware or exploit-chain samples in the Git worktree
- scanning arbitrary system paths through MCP
- changing Defender preferences through MCP
- adding exclusions through MCP

The backend intentionally scans only paths under `workspaceRoot` or
`artifactRoot`.

## Event Log Workflow

Good log names:

```text
System
Application
Security
Microsoft-Windows-Windows Defender/Operational
Microsoft-Windows-PowerShell/Operational
Windows PowerShell
```

Example filter:

```json
{
  "logName": "Microsoft-Windows-Windows Defender/Operational",
  "maxEvents": 25
}
```

Example finding output:

```json
{
  "logName": "System",
  "id": 7036,
  "maxEvents": 50,
  "finding": "CVE-YYYY-NNNNN",
  "outputFile": "triage/windows-system-events.json"
}
```

Some logs, especially `Security`, may require elevation. The MCP server reports
the error instead of attempting elevation.

## Optional Features

Useful Windows Pro/Enterprise features for PatchPivot labs:

- Hyper-V for isolated target VMs and snapshots
- Windows Sandbox for disposable manual validation
- WSL and Virtual Machine Platform for Linux/Kali/Debian backends
- Defender Application Guard where available

Optional-feature state queries may require elevation depending on local policy.
The MCP tool returns per-feature errors instead of prompting.

## Native vs Kali vs Ghidra

Use Windows native tools for Defender posture, firewall posture, Windows event
logs, host inventory, and PowerShell-only triage around local artifacts.

Use Kali WSL for Linux-native fuzzing, compiler/sanitizer workflows, CLI reverse
engineering utilities, and Linux package reproduction.

Use headless Ghidra for repeatable binary import, function/symbol/string export,
and source/binary patch correlation.

All three backends share the same finding directory model.
