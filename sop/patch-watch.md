# SOP — continuous patch-watch + coordinated disclosure

This is the operational standard for running the patch-watch
pipeline against the targets in `targets.yaml`. Every variant the
agent identifies must end at one of EVRP's coordinated channels —
`hackerone | bugcrowd | vendor_psirt | cert_cc | published_advisory
| internal_writeup`. Broker drops, silent retention, and "sit on
it" outcomes are out of scope.

## Frequency

Weekly, or on-demand after a high-profile vendor advisory. The
heuristic in `scripts/patch-watch.mjs` biases toward false
positives — running too often just queues more candidates the
operator filters down.

## Cadence

```sh
# 1. Discover candidates (writes findings/<target>-<shortSha>/)
cd ~/GitHub/patchpivot
node scripts/patch-watch.mjs

# 2. Drive each new finding through the rulebook
for d in findings/*-*/; do
  test -e "$d/README.md" || continue
  status=$(grep -m1 'Status' "$d/README.md")
  case "$status" in
    *recon*)
      ( cd "$d" && erosolar --profile variant-research \
        "investigate the patch referenced in intel/sources.md" ) ;;
  esac
done

# 3. Review terminal phase output (each finding's disclosure.md
#    must end on a valid EVRP DisclosureTerminal channel).
ls findings/*/disclosure.md
```

For unattended weekly runs, schedule the discover step via cron /
GitHub Actions / a remote agent routine. Drive-through (step 2)
SHOULD remain operator-supervised for now — autonomous publication
of advisories without human review crosses a line we're not ready
for.

## Headless MCP lab gate

PatchPivot includes a headless-only MCP server for Windows-hosted lab
control:

```sh
npm run mcp:security
```

Before using any lab execution tool:

1. Run the self-test:

   ```sh
   npm run mcp:self-test
   ```

2. Confirm Kali exists as the configured WSL distro (default:
   `kali-linux`) through `security.probe`.
3. Confirm Ghidra headless resolves to
   `C:\ghidra_12.1_PUBLIC\support\analyzeHeadless.bat` or the local
   configured equivalent.
4. Use `windows.probe`, `windows.defender_status`, and
   `windows.firewall_profiles` for native host posture before running lab
   commands.
5. Add `findings/<slug>/intel/scope.md`.
6. Change `MCP-LAB-AUTHORIZED: no` to `MCP-LAB-AUTHORIZED: yes` only
   after target, artifact, and lab boundaries are approved.

GUI tools are never part of this workflow. The MCP server blocks common
GUI launchers, strips GUI environment variables, and uses Ghidra only
through `analyzeHeadless`. Native Windows PowerShell runs are
non-interactive and scope-gated. Network mode defaults to `off`; broader
network modes require local policy changes and explicit scope notes.

## Filtering candidates

Every queued finding starts at `Status: recon`. Before driving
through the rulebook, the operator triages:

- Skip pure CI / docs / typo fixes the heuristic snagged.
- Skip targets out of authorization scope.
- Defer findings under active embargo (vendor already disclosed,
  no public detail).

Remove a finding by deleting its directory:

```sh
rm -rf findings/linux-kernel-abc123def456
```

Tracked state in `state/watch-state.json` is not affected; the
target's `lastSha` already advanced past this commit.

## Disclosure terminal — required outcomes

Each `findings/<slug>/disclosure.md` MUST end with a populated
"Coordinated disclosure timeline" table that includes a row
matching the EVRP `DisclosureTerminal` schema (`schemas/disclosure-
terminal.schema.json` in the [evrp-spec](https://github.com/Aroxora/evrp-spec)
repo). Mapping reminder:

| Channel             | When to use                                   |
|---------------------|-----------------------------------------------|
| `hackerone`         | Target runs an active H1 program              |
| `bugcrowd`          | Target runs an active Bugcrowd program        |
| `vendor_psirt`      | Target has a PSIRT email or web form          |
| `cert_cc`           | Multi-vendor coordination required            |
| `published_advisory`| Vendor unresponsive past 90-day deadline      |
| `internal_writeup`  | Held internally — not yet ready to disclose   |

A finding without a populated terminal row is **not closed** —
the workflow loops back until one is filed.

## Auditability

Every CLI launch driving a finding writes a `usage_logs/{uid}/sessions/{id}`
record (EVRP-Audited level — `@trenchwork/erosolar` ≥ 1.1.26).
Cross-correlate by uid + finding slug when reporting "N coordinated
disclosures auto-driven from this CLI to date".

## Honest limits

- The heuristic at `scripts/patch-watch.mjs` is regex-based. It
  misses obfuscated security fixes (a vendor "performance fix"
  that's actually a length check). Compensate by adding manual
  watchlist entries.
- The agent's ability to find a real variant is bounded by the
  model. Capability evals (#1 in the suggestions list) anchor
  this empirically — until then, expect mixed results.
- "Coordinated" doesn't mean "fast". A `vendor_psirt` channel may
  sit at "submitted" for months. The SOP closes a finding when
  the row is filed, not when the patch ships.
