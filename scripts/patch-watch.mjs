#!/usr/bin/env node
// Continuous patch-watch driver. For each target in targets.yaml,
// pull commits whose message looks security-relevant and queue them
// as new investigations under findings/.
//
// State lives in state/watch-state.json: { <targetName>: <lastSha> }.
// First run on a target seeds with the current HEAD and queues
// nothing — actual investigations start on the SECOND run, which
// limits initial noise.
//
// Usage:
//   node scripts/patch-watch.mjs                # walk all targets
//   node scripts/patch-watch.mjs --target=linux-kernel
//   node scripts/patch-watch.mjs --since=4w     # ignore older than 4 weeks
//   node scripts/patch-watch.mjs --dry-run      # don't write findings
//
// Each queued finding lands at:
//   findings/<target>-<shortSha>/intel/sources.md
//   findings/<target>-<shortSha>/README.md  (status=recon, links pre-filled)
// Then drive each through the rulebook by hand or via batch:
//   for d in findings/<target>-*/; do
//     ( cd "$d" && erosolar --profile variant-research \
//       "investigate the patch referenced in intel/sources.md" )
//   done

import { execSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync, cpSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const STATE = join(ROOT, 'state', 'watch-state.json');
const TARGETS_YAML = join(ROOT, 'targets.yaml');
const FINDINGS = join(ROOT, 'findings');
const TEMPLATE = join(FINDINGS, '_template');
const CACHE_ROOT = join(ROOT, '.cache', 'mirrors');

const args = process.argv.slice(2);
const dryRun = args.includes('--dry-run');
const onlyTarget = pickFlag('--target');
const sinceArg = pickFlag('--since') ?? '6w';

function pickFlag(name) {
  const idx = args.findIndex((a) => a === name || a.startsWith(`${name}=`));
  if (idx < 0) return null;
  if (args[idx].includes('=')) return args[idx].split('=').slice(1).join('=');
  return args[idx + 1] ?? null;
}

// Minimal YAML parser for the subset of targets.yaml we use. Avoids
// pulling in a dep just for this. Recognises only:
//   key: value
//   key:
//     - { item: value, ... }
//   key: |
//     <multiline>
function parseTargets(raw) {
  const lines = raw.split('\n');
  const out = [];
  let cur = null;
  let inNotes = false;
  let notesIndent = 0;
  const top = (s) => s.trim();
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/^\s*#/.test(line) || /^\s*$/.test(line)) continue;
    if (inNotes) {
      const ind = line.match(/^( *)/)[1].length;
      if (line.trim() === '' || ind > notesIndent) {
        cur.notes = (cur.notes || '') + line.replace(/^ {0,}/, '') + '\n';
        continue;
      }
      inNotes = false;
    }
    const m = line.match(/^\s*-\s+name:\s*(.+)$/);
    if (m) { cur = { name: top(m[1]) }; out.push(cur); continue; }
    if (!cur) continue;
    const kv = line.match(/^\s+(\w+):\s*(.*)$/);
    if (kv) {
      const k = kv[1]; const v = kv[2];
      if (v === '|') {
        inNotes = true;
        notesIndent = line.match(/^( *)/)[1].length;
        cur[k] = '';
      } else {
        cur[k] = top(v);
      }
    }
  }
  return out;
}

function loadState() {
  if (!existsSync(STATE)) return {};
  try { return JSON.parse(readFileSync(STATE, 'utf8')); } catch { return {}; }
}

function saveState(s) {
  mkdirSync(dirname(STATE), { recursive: true });
  writeFileSync(STATE, JSON.stringify(s, null, 2) + '\n', 'utf8');
}

function ensureMirror(target) {
  const dir = join(CACHE_ROOT, target.name);
  mkdirSync(dirname(dir), { recursive: true });
  if (!existsSync(dir)) {
    console.log(`[${target.name}] cloning bare mirror (this is a one-time cost)`);
    execSync(`git clone --bare --filter=blob:none ${shellQuote(target.repo)} ${shellQuote(dir)}`,
      { stdio: 'inherit' });
  } else {
    console.log(`[${target.name}] fetching updates`);
    execSync(`git --git-dir=${shellQuote(dir)} fetch --quiet --filter=blob:none origin`,
      { stdio: 'inherit' });
  }
  return dir;
}

function shellQuote(s) {
  return `'${String(s).replace(/'/g, "'\\''")}'`;
}

// Heuristic for "this commit looks security-relevant" — biased
// toward false positives because the human (or LLM in the
// rulebook) decides on the actual investigation.
const SECURITY_PATTERN = new RegExp(
  '\\b(' +
  'CVE-\\d{4}-\\d+|' +
  'security|sec[ -]fix|secfix|hardening|' +
  'use[- ]after[- ]free|UAF|' +
  'out[- ]of[- ]bounds|OOB|oob[- ]read|oob[- ]write|' +
  'heap[- ]overflow|stack[- ]overflow|buffer[- ]overflow|' +
  'integer[- ]overflow|int[- ]overflow|' +
  'double[- ]free|null[- ]deref|' +
  'race condition|TOCTOU|' +
  'memory leak|info leak|info[- ]leak|' +
  'side[- ]channel|spectre|meltdown|' +
  'ASLR|RELRO|stack canary|' +
  'fuzz|sanitizer|KASAN|ASAN|UBSAN|MSAN|' +
  'syzbot' +
  ')\\b',
  'i'
);

function listSecurityCommitsSince(mirror, sinceSha, sinceDate) {
  // Custom separators: 0x1f (US) between fields, 0x1e (RS) between
  // records. Don't use `-z` — git would prepend a NUL to each
  // record-after-the-first, which leaks into the sha.
  const range = sinceSha ? `${sinceSha}..HEAD` : `--since=${sinceDate} HEAD`;
  const cmd = `git --git-dir=${shellQuote(mirror)} log ${range} --no-merges --format='format:%H%x1f%s%x1f%b%x1e'`;
  const out = execSync(cmd, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  const records = out.split('\x1e').map((r) => r.trim()).filter(Boolean);
  const hits = [];
  for (const rec of records) {
    const [sha, subject, body] = rec.split('\x1f');
    if (!sha) continue;
    const text = `${subject ?? ''}\n${body ?? ''}`;
    if (SECURITY_PATTERN.test(text)) {
      hits.push({ sha, subject: subject ?? '', body: body ?? '' });
    }
  }
  return hits;
}

function shaShort(sha) { return sha.slice(0, 12); }

function queueFinding(target, hit) {
  const slug = `${target.name}-${shaShort(hit.sha)}`;
  const dir = join(FINDINGS, slug);
  if (existsSync(dir)) return false;
  if (dryRun) return true;
  cpSync(TEMPLATE, dir, { recursive: true });
  const intelDir = join(dir, 'intel');
  mkdirSync(intelDir, { recursive: true });
  writeFileSync(join(intelDir, 'sources.md'),
`# Intel — ${target.name} ${shaShort(hit.sha)}

Auto-queued by patch-watch on ${new Date().toISOString()}.

## Source patch

- Commit: \`${hit.sha}\`
- Repo:   ${target.repo}
- View:   ${target.repo}/commit/${hit.sha}
- Subject:

\`\`\`
${hit.subject}
\`\`\`

- Body (first 60 lines):

\`\`\`
${(hit.body || '').split('\n').slice(0, 60).join('\n')}
\`\`\`

## Vendor advisory feed

${target.advisory ? `- ${target.advisory}` : '- (none on file)'}

## Disclosure target

${target.bounty ? `- Bounty: ${target.bounty}` : '- No bounty program — vendor PSIRT or 90-day published advisory.'}
`, 'utf8');
  writeFileSync(join(dir, 'README.md'),
`# ${slug}

**Status:** \`recon\`  (auto-queued from patch-watch)

Subject: ${hit.subject}

See \`intel/sources.md\` for the full patch reference. Drive through
the rulebook with:

\`\`\`sh
cd findings/${slug}
erosolar --profile variant-research "investigate the patch referenced in intel/sources.md"
\`\`\`
`, 'utf8');
  return true;
}

const targets = parseTargets(readFileSync(TARGETS_YAML, 'utf8'));
const state = loadState();
const summary = [];

for (const target of targets) {
  if (onlyTarget && target.name !== onlyTarget) continue;
  if (!target.repo) {
    summary.push({ target: target.name, skipped: 'no repo url' });
    continue;
  }
  let mirror;
  try { mirror = ensureMirror(target); }
  catch (e) {
    summary.push({ target: target.name, error: String(e.message || e).slice(0, 200) });
    continue;
  }
  const lastSha = state[target.name]?.lastSha ?? null;
  if (!lastSha) {
    // First run — seed and queue nothing.
    const head = execSync(`git --git-dir=${shellQuote(mirror)} rev-parse HEAD`,
      { encoding: 'utf8' }).trim();
    if (!dryRun) {
      state[target.name] = { lastSha: head, lastRunAt: new Date().toISOString() };
    }
    summary.push({ target: target.name, seeded: head, queued: 0 });
    continue;
  }
  const hits = listSecurityCommitsSince(mirror, lastSha, sinceArg);
  let queued = 0;
  for (const hit of hits) {
    if (queueFinding(target, hit)) queued += 1;
  }
  if (!dryRun) {
    const head = execSync(`git --git-dir=${shellQuote(mirror)} rev-parse HEAD`,
      { encoding: 'utf8' }).trim();
    state[target.name] = { lastSha: head, lastRunAt: new Date().toISOString() };
  }
  summary.push({ target: target.name, candidates: hits.length, queued });
}

if (!dryRun) saveState(state);

console.log('\n=== patch-watch summary ===');
for (const s of summary) {
  console.log(JSON.stringify(s));
}
const totalQueued = summary.reduce((acc, s) => acc + (s.queued ?? 0), 0);
console.log(`total queued: ${totalQueued}${dryRun ? ' (dry-run)' : ''}`);
