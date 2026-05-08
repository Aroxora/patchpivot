# patchpivot

Variant-analysis research. Take a recently-patched bug in a high-value target, diff vuln↔patched, hunt the same primitive in unpatched related code, fuzz around it, triage, develop PoC, disclose.

This repo is a **research workspace**, not a tool. The actual work is driven by `erosolar --profile variant-research` against the per-investigation directories under `findings/`.

## Layout

```
targets.yaml         watched products (vendor, repo, advisory feed)
findings/<slug>/     one workspace per investigation
  intel/             CVE / advisory links, patch commit URLs, bug-class hypothesis
  diff/              changed-function set + decompiled C
  harness/           fuzzing harness sources (afl-clang-fast)
  crashes/           minimized crash inputs (by hash)
  triage/            gdb dumps + Ghidra decomp correlations
  disclosure.md      coordinated-disclosure write-up
disclosures/log.md   submission tracking (HackerOne / vendor PSIRT / CERT-CC / advisories)
scripts/             helpers
```

## Workflow

```sh
# Pick a target patch (CVE id or commit URL)
./scripts/new-investigation.sh CVE-2026-XXXXX

# Drive the analysis with the erosolar variant-research profile
cd findings/CVE-2026-XXXXX
erosolar --profile variant-research "investigate the patch at <url>"
```

The profile walks Recon → Acquire → BinDiff → Variant → Fuzz → Triage → PoC → Disclose against the offsec capability surface (afl++/gdb/ghidra-mcp/pwntools/binary-analysis). Big artifacts (binaries, decompilations, crash corpora) live in `~/.erosolar/artifacts/` keyed by sha256; this repo just tracks intel, harnesses, write-ups.

## Disclosure terminal — pinned

Every investigation ends in a coordinated channel: HackerOne / Bugcrowd / vendor PSIRT email / CERT-CC coordination / internal write-up / 90-day-disclosure published advisory. Never broker, never silent.
