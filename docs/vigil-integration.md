# Vigil Integration

PatchPivot integrates with [Vigil by Trenchwork](https://trenchwork.org/vigil)
as a guarded, headless MCP server and as a normalized findings source for
Vigil's security-analysis pipeline.

## Best Integration Model

Use PatchPivot as the evidence workspace and policy boundary. Use Vigil as the
interactive CND agent that plans work and calls PatchPivot's MCP tools.

This keeps responsibilities clean:

- PatchPivot owns findings, scope files, run logs, manifests, Ghidra exports,
  and disclosure evidence.
- PatchPivot MCP owns guardrails for Windows, WSL Kali, headless Ghidra, and
  artifact paths.
- Vigil owns the operator session, profile rules, agent planning, and remote MCP
  tool invocation.
- Vigil's existing bulk pipeline can still ingest PatchPivot findings directly
  when the repos are siblings.

## Local Source Layout

Current tested layout:

```text
C:\GitHub\patchpivot
C:\GitHub\vigil-by-trenchwork
```

Vigil already includes a PatchPivot findings importer at:

```text
C:\GitHub\vigil-by-trenchwork\scripts\_patchpivot-findings.mjs
```

That importer searches for a sibling PatchPivot checkout and is used by Vigil's
`scripts/security-analysis.mjs` pass named `patchpivot findings`.

## Install Project MCP Config

Generate the project-local Vigil MCP config from the PatchPivot repo:

```powershell
cd C:\GitHub\patchpivot
npm run vigil:install
```

This writes:

```text
C:\GitHub\patchpivot\.vigil\mcp.json
```

The file is ignored by Git. It should stay local because it contains
machine-specific absolute paths. It does not contain passwords or API keys.

The generated server entry mounts PatchPivot as:

```json
{
  "mcpServers": {
    "patchpivot-security": {
      "command": "node",
      "args": [
        "C:\\GitHub\\patchpivot\\scripts\\mcp\\patchpivot-security-mcp.mjs"
      ],
      "cwd": "C:\\GitHub\\patchpivot",
      "env": {
        "PATCHPIVOT_MCP_CONFIG": "C:\\GitHub\\patchpivot\\config\\security-mcp.local.json",
        "PATCHPIVOT_VIGIL_ROOT": "C:\\GitHub\\vigil-by-trenchwork"
      },
      "profiles": [
        "vigil-code",
        "vigil-cnd"
      ]
    }
  }
}
```

Vigil sanitizes MCP server and tool names into native tool names. For example:

```text
mcp__patchpivot_security__security_probe
mcp__patchpivot_security__vigil_probe
mcp__patchpivot_security__vigil_findings_bundle
mcp__patchpivot_security__kali_run
mcp__patchpivot_security__ghidra_analyze
mcp__patchpivot_security__windows_defender_scan
```

## Build Vigil If Needed

The local Vigil source checkout currently does not include `dist/`. Build it
before launching the packaged CLI path:

```powershell
cd C:\GitHub\vigil-by-trenchwork
npm install
npm run build
```

Then launch Vigil from the PatchPivot workspace so it loads
`C:\GitHub\patchpivot\.vigil\mcp.json`:

```powershell
cd C:\GitHub\patchpivot
node C:\GitHub\vigil-by-trenchwork\dist\bin\vigil.js --profile vigil-code
```

For development mode from the Vigil repo, keep the working directory as
PatchPivot:

```powershell
cd C:\GitHub\patchpivot
node --loader ts-node/esm C:\GitHub\vigil-by-trenchwork\src\bin\vigil.ts --profile vigil-code
```

## PatchPivot Integration Commands

PatchPivot provides helper scripts for verification and export:

```powershell
npm run vigil:probe
npm run vigil:config
npm run vigil:export
npm run vigil:smoke
```

Command behavior:

- `vigil:probe` reports PatchPivot, Vigil source, local config, and findings
  summary state.
- `vigil:config` renders the recommended `.vigil/mcp.json` content.
- `vigil:install` merges the PatchPivot server into `.vigil/mcp.json`.
- `vigil:export` emits a normalized findings bundle with statuses, severity
  counts, disclosure fields, variant rows, and evidence file lists.
- `vigil:smoke` starts the PatchPivot MCP server and verifies the Vigil-facing
  tools are listed and callable.

The export shape is documented by:

```text
schemas/vigil-findings-bundle.schema.json
```

## MCP Tools Added For Vigil

PatchPivot MCP exposes these read-only integration tools:

- `vigil.probe`: integration posture, source paths, build status, and findings
  summary.
- `vigil.findings_bundle`: normalized PatchPivot findings bundle for Vigil or
  other CND orchestrators.
- `vigil.project_mcp_config`: recommended project-local Vigil MCP config.

The rest of PatchPivot MCP remains available through Vigil, including:

- `security.probe`
- `policy.explain`
- `policy.check_command`
- `finding.list`
- `finding.update_status`
- `windows.probe`
- `windows.run`
- `windows.defender_status`
- `windows.defender_scan`
- `windows.eventlog_query`
- `windows.firewall_profiles`
- `windows.optional_features`
- `kali.run`
- `ghidra.probe`
- `ghidra.analyze`
- `artifact.manifest`

## Headless Controls

PatchPivot's Vigil integration keeps the no-GUI rule:

- no Ghidra GUI launcher
- no WSLg, X11, browser, terminal emulator, or desktop session
- no interactive sudo handling through MCP
- no storage of sudo passwords in config, environment, logs, or docs
- no Defender disabling or exclusion management through MCP

Kali access remains scoped through `kali.run`. The active finding must contain:

```text
findings/<slug>/intel/scope.md
```

with:

```text
MCP-LAB-AUTHORIZED: yes
```

## Kali And Ghidra Division

Vigil ships its own Kali and Ghidra MCP servers, but the safest default for this
workspace is to mount PatchPivot's single guarded MCP server into Vigil.

Reasons:

- one scope gate for Windows, Kali, and Ghidra
- one artifact root
- one run-log format
- one command policy
- one disclosure evidence trail

Use Vigil's native MCP servers only when a separate Vigil workflow requires
them. For PatchPivot research, prefer `mcp__patchpivot_security__kali_run` and
`mcp__patchpivot_security__ghidra_analyze`.

## Bulk Vigil Analysis

Vigil's existing pipeline can ingest PatchPivot without MCP when the repos are
siblings:

```powershell
cd C:\GitHub\vigil-by-trenchwork
npm run analyze:local
```

The PatchPivot pass writes a `13-patchpivot-findings.json` output inside the
Vigil security-analysis run directory.

## Cloud Or Lab Deployment

For a cloud worker or lab VM, keep the same contract:

1. Clone PatchPivot and Vigil.
2. Put heavy binaries, fuzz corpora, and Ghidra projects outside Git.
3. Generate a machine-local `.vigil/mcp.json`.
4. Run Vigil from the PatchPivot working directory.
5. Keep Kali headless and scope-gated.
6. Export PatchPivot findings with `npm run vigil:export` for batch ingestion.

Only the paths change. The MCP server entry, finding structure, run logs, and
artifact manifests stay the same.
