#!/usr/bin/env node
import { spawn } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync
} from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const DEFAULT_SERVER_NAME = 'patchpivot-security';
const VIGIL_PROFILES = ['vigil-code', 'vigil-cnd'];
const MAX_README_CHARS = 6000;
const MAX_DISCLOSURE_CHARS = 4000;

const args = process.argv.slice(2);

main().catch((err) => {
  process.stderr.write(`${err.stack || err.message || err}\n`);
  process.exit(1);
});

async function main() {
  if (args.includes('--help') || args.includes('-h')) {
    printHelp();
    return;
  }

  if (args.includes('--export')) {
    printJson(exportFindingsBundle());
    return;
  }

  if (args.includes('--config')) {
    printJson(buildProjectMcpConfig());
    return;
  }

  if (args.includes('--install-project-mcp')) {
    printJson(installProjectMcpConfig());
    return;
  }

  if (args.includes('--smoke')) {
    const result = await runSmokeTest();
    printJson(result);
    if (!result.ok) process.exitCode = 1;
    return;
  }

  printJson(probeIntegration());
}

function printHelp() {
  process.stdout.write([
    'PatchPivot Vigil integration helper',
    '',
    'Usage:',
    '  node scripts/vigil/patchpivot-vigil.mjs --probe',
    '  node scripts/vigil/patchpivot-vigil.mjs --export',
    '  node scripts/vigil/patchpivot-vigil.mjs --config',
    '  node scripts/vigil/patchpivot-vigil.mjs --install-project-mcp',
    '  node scripts/vigil/patchpivot-vigil.mjs --smoke',
    '',
    'Environment:',
    '  PATCHPIVOT_VIGIL_ROOT  Override the local Vigil source checkout path.'
  ].join('\n') + '\n');
}

function printJson(value) {
  process.stdout.write(JSON.stringify(value, null, 2) + '\n');
}

function probeIntegration() {
  const vigilRoot = detectVigilRoot();
  const patchpivotPackage = readJson(join(ROOT, 'package.json'));
  const vigilPackage = vigilRoot ? readJson(join(vigilRoot, 'package.json')) : null;
  const projectMcpPath = join(ROOT, '.vigil', 'mcp.json');
  const projectMcp = readJson(projectMcpPath);
  const bundle = exportFindingsBundle({ includeFullText: false });
  const distCliExists = Boolean(vigilRoot && existsSync(join(vigilRoot, 'dist', 'bin', 'vigil.js')));

  return {
    generatedAt: new Date().toISOString(),
    integration: {
      mode: 'Vigil mounts PatchPivot as a guarded stdio MCP server; Vigil bulk analysis can also ingest PatchPivot findings from the sibling checkout.',
      publicProductUrl: 'https://trenchwork.org/vigil',
      vigilToolPrefix: `mcp__${sanitizeForVigilToolName(DEFAULT_SERVER_NAME)}__`,
      headlessOnly: true
    },
    patchpivot: {
      root: ROOT,
      packageName: patchpivotPackage?.name || 'patchpivot',
      version: patchpivotPackage?.version || 'unknown',
      mcpServer: join(ROOT, 'scripts', 'mcp', 'patchpivot-security-mcp.mjs'),
      mcpServerExists: existsSync(join(ROOT, 'scripts', 'mcp', 'patchpivot-security-mcp.mjs')),
      localMcpConfig: join(ROOT, 'config', 'security-mcp.local.json'),
      localMcpConfigExists: existsSync(join(ROOT, 'config', 'security-mcp.local.json')),
      projectVigilConfig: {
        path: projectMcpPath,
        exists: existsSync(projectMcpPath),
        hasPatchpivotServer: Boolean(projectMcp?.mcpServers?.[DEFAULT_SERVER_NAME])
      },
      findings: {
        total: bundle.totalFindings,
        byStatus: bundle.byStatus,
        bySeverity: bundle.bySeverity
      }
    },
    vigil: {
      root: vigilRoot,
      exists: Boolean(vigilRoot && existsSync(vigilRoot)),
      packageName: vigilPackage?.name || null,
      version: vigilPackage?.version || null,
      requiredNode: vigilPackage?.engines?.node || null,
      currentNode: process.version,
      nodeMeetsRequirement: nodeMeetsRequirement(vigilPackage?.engines?.node),
      distCli: vigilRoot ? join(vigilRoot, 'dist', 'bin', 'vigil.js') : null,
      distCliExists,
      devCli: vigilRoot ? join(vigilRoot, 'src', 'bin', 'vigil.ts') : null,
      devCliExists: Boolean(vigilRoot && existsSync(join(vigilRoot, 'src', 'bin', 'vigil.ts'))),
      mcpExampleExists: Boolean(vigilRoot && existsSync(join(vigilRoot, 'mcp.json.example'))),
      patchpivotImporterExists: Boolean(vigilRoot && existsSync(join(vigilRoot, 'scripts', '_patchpivot-findings.mjs'))),
      securityAnalysisPassExists: Boolean(vigilRoot && fileContains(join(vigilRoot, 'scripts', 'security-analysis.mjs'), 'probePatchpivotFindings'))
    },
    commands: {
      installProjectMcp: 'npm run vigil:install',
      exportFindings: 'npm run vigil:export',
      probe: 'npm run vigil:probe',
      smoke: 'npm run vigil:smoke',
      buildVigilIfNeeded: vigilRoot ? `cd ${vigilRoot} ; npm install ; npm run build` : null,
      runVigilFromPatchpivot: vigilRoot ? `cd ${ROOT} ; node ${join(vigilRoot, 'dist', 'bin', 'vigil.js')} --profile vigil-code` : null
    },
    notes: [
      'Generated .vigil/mcp.json is local-only and ignored by Git.',
      'The generated Vigil MCP config does not include passwords or API keys.',
      distCliExists
        ? 'Vigil dist CLI is available for launch from the PatchPivot working directory.'
        : 'Vigil source needs a dist build before the packaged CLI path exists.'
    ]
  };
}

function exportFindingsBundle(options = {}) {
  const includeFullText = options.includeFullText !== false;
  const findingsDir = join(ROOT, 'findings');
  const findings = [];
  if (existsSync(findingsDir)) {
    for (const entry of readdirSync(findingsDir, { withFileTypes: true })) {
      if (!entry.isDirectory() || entry.name.startsWith('_') || entry.name.startsWith('.')) continue;
      const dir = join(findingsDir, entry.name);
      const readme = safeRead(join(dir, 'README.md'));
      if (!readme) continue;
      findings.push(parseFinding(dir, entry.name, readme, includeFullText));
    }
  }

  const byStatus = {};
  const bySeverity = { critical: 0, high: 0, moderate: 0, medium: 0, low: 0, unknown: 0 };
  for (const finding of findings) {
    byStatus[finding.status] = (byStatus[finding.status] || 0) + 1;
    const severity = normalizeSeverity(finding.severity);
    bySeverity[severity] = (bySeverity[severity] || 0) + 1;
  }

  const disclosuresDir = join(ROOT, 'disclosures');
  const disclosures = existsSync(disclosuresDir)
    ? readdirSync(disclosuresDir).filter((name) => name.endsWith('.md')).sort()
    : [];
  const localDisclosureFiles = findings.filter((finding) => finding.files.disclosure).length;

  return {
    generatedAt: new Date().toISOString(),
    sourceRepo: 'patchpivot',
    sourcePath: ROOT,
    publicVigilUrl: 'https://trenchwork.org/vigil',
    totalFindings: findings.length,
    byStatus,
    bySeverity,
    disclosures: disclosures.length + localDisclosureFiles,
    disclosureFiles: disclosures,
    targets: safeRead(join(ROOT, 'targets.yaml')).slice(0, 12000),
    findings
  };
}

function parseFinding(dir, slug, readme, includeFullText) {
  const disclosure = safeRead(join(dir, 'disclosure.md'));
  const title = firstMatch(readme, /^#\s+(.+)$/m) || slug;
  const cveId = firstMatch(readme, /(CVE-\d{4}-\d{4,})/i) || firstMatch(slug, /(CVE-\d{4}-\d{4,})/i) || '';
  const cvss = firstMatch(readme, /CVSS(?:\s+score)?[:\s]+([\d.]+)/i) || firstMatch(readme, /-\s*CVE:\s*CVE-\d{4}-\d{4,}\s*\(CVSS\s+([\d.]+)/i);
  const severityText = (
    firstMatch(readme, /-\s*CVE:\s*CVE-\d{4}-\d{4,}\s*\((critical|high|moderate|medium|low)/i) ||
    firstMatch(readme, /\bSeverity:\s*`?(critical|high|moderate|medium|low)\b/i) ||
    firstMatch(title, /\b(critical|high|moderate|medium|low)\b/i)
  );
  const severity = normalizeSeverity(severityText) !== 'unknown'
    ? normalizeSeverity(severityText)
    : severityFromCvss(cvss);

  return {
    slug,
    title,
    cveId,
    severity,
    cvss: cvss || '',
    status: readStatusFromText(readme),
    description: readDescription(readme),
    bugClass: readBulletValue(readme, 'Bug class'),
    affected: readBulletValue(readme, 'Affected versions'),
    vendorAdvisory: readBulletValue(readme, 'Vendor advisory'),
    patchCommit: readBulletValue(readme, 'Patch commit'),
    hypothesis: readSection(readme, 'Hypothesis').slice(0, 1200),
    variants: readVariantRows(readme),
    variantCount: readVariantRows(readme).length,
    disclosure: {
      channel: readDisclosureValue(readme, 'Channel'),
      submitted: readDisclosureValue(readme, 'Submitted'),
      acknowledged: readDisclosureValue(readme, 'Acknowledged'),
      fixed: readDisclosureValue(readme, 'Fixed'),
      public: readDisclosureValue(readme, 'Public')
    },
    files: {
      root: relative(ROOT, dir).split(sep).join('/'),
      readme: 'README.md',
      disclosure: existsSync(join(dir, 'disclosure.md')) ? 'disclosure.md' : '',
      intelFiles: safeListDir(join(dir, 'intel')),
      harnessFiles: safeListDir(join(dir, 'harness')),
      diffFiles: safeListDir(join(dir, 'diff')),
      crashFiles: safeListDir(join(dir, 'crashes')),
      triageFiles: safeListDir(join(dir, 'triage'))
    },
    readmeFull: includeFullText ? readme.slice(0, MAX_README_CHARS) : '',
    disclosureFull: includeFullText ? disclosure.slice(0, MAX_DISCLOSURE_CHARS) : ''
  };
}

function buildProjectMcpConfig() {
  const env = {
    PATCHPIVOT_VIGIL_ROOT: detectVigilRoot() || ''
  };
  const localConfig = join(ROOT, 'config', 'security-mcp.local.json');
  if (existsSync(localConfig)) {
    env.PATCHPIVOT_MCP_CONFIG = localConfig;
  }

  return {
    mcpServers: {
      [DEFAULT_SERVER_NAME]: {
        command: 'node',
        args: [join(ROOT, 'scripts', 'mcp', 'patchpivot-security-mcp.mjs')],
        cwd: ROOT,
        env,
        profiles: VIGIL_PROFILES
      }
    }
  };
}

function installProjectMcpConfig() {
  const projectDir = join(ROOT, '.vigil');
  const projectPath = join(projectDir, 'mcp.json');
  const existing = readJson(projectPath) || {};
  const generated = buildProjectMcpConfig();
  const merged = {
    ...existing,
    mcpServers: {
      ...(existing.mcpServers || {}),
      ...generated.mcpServers
    }
  };
  mkdirSync(projectDir, { recursive: true });
  writeFileSync(projectPath, JSON.stringify(merged, null, 2) + '\n', 'utf8');
  return {
    ok: true,
    path: projectPath,
    server: DEFAULT_SERVER_NAME,
    profiles: VIGIL_PROFILES,
    toolPrefixInVigil: `mcp__${sanitizeForVigilToolName(DEFAULT_SERVER_NAME)}__`,
    wroteSecrets: false
  };
}

function runSmokeTest() {
  return new Promise((resolvePromise) => {
    const serverPath = join(ROOT, 'scripts', 'mcp', 'patchpivot-security-mcp.mjs');
    const child = spawn(process.execPath, [serverPath], {
      cwd: ROOT,
      windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe']
    });

    const responses = [];
    let stdout = '';
    let stderr = '';
    let done = false;

    const finish = (result) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      child.kill('SIGTERM');
      resolvePromise(result);
    };

    const timer = setTimeout(() => {
      finish({
        ok: false,
        error: 'Vigil MCP smoke test timed out.',
        responses,
        stderr: stderr.trim()
      });
    }, 12000);

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString('utf8');
      for (;;) {
        const idx = stdout.indexOf('\n');
        if (idx < 0) break;
        const line = stdout.slice(0, idx).trim();
        stdout = stdout.slice(idx + 1);
        if (line) {
          try {
            responses.push(JSON.parse(line));
          } catch (err) {
            finish({ ok: false, error: `Invalid JSON-RPC response: ${err.message}`, line, stderr });
            return;
          }
        }
      }
      maybeSmokeDone(responses, stderr, finish);
    });

    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString('utf8');
    });

    child.on('error', (err) => {
      finish({ ok: false, error: err.message, stderr });
    });

    child.on('close', () => {
      maybeSmokeDone(responses, stderr, finish);
    });

    send(child, {
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2025-06-18',
        capabilities: {},
        clientInfo: { name: 'patchpivot-vigil-smoke', version: '0.1.0' }
      }
    });
    send(child, { jsonrpc: '2.0', method: 'notifications/initialized' });
    send(child, { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
    send(child, {
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: {
        name: 'vigil.probe',
        arguments: {}
      }
    });
  });
}

function maybeSmokeDone(responses, stderr, finish) {
  const ids = new Set(responses.map((response) => response.id));
  if (![1, 2, 3].every((id) => ids.has(id))) return;
  const list = responses.find((response) => response.id === 2);
  const probe = responses.find((response) => response.id === 3);
  const tools = list?.result?.tools?.map((tool) => tool.name) || [];
  const required = ['vigil.probe', 'vigil.findings_bundle', 'vigil.project_mcp_config'];
  const missing = required.filter((name) => !tools.includes(name));
  finish({
    ok: missing.length === 0 && !probe?.result?.isError,
    missingTools: missing,
    vigilProbeError: probe?.result?.isError ? probe.result?.structuredContent : null,
    tools,
    stderr: stderr.trim().split(/\r?\n/).filter(Boolean)
  });
}

function send(child, message) {
  child.stdin.write(JSON.stringify(message) + '\n');
}

function detectVigilRoot() {
  const explicit = valueAfter('--vigil-root') || process.env.PATCHPIVOT_VIGIL_ROOT;
  const candidates = [
    explicit,
    'C:\\GitHub\\vigil-by-trenchwork',
    join(ROOT, '..', 'vigil-by-trenchwork'),
    join(ROOT, '..', 'vigil'),
    join(ROOT, '..', '..', 'vigil-by-trenchwork')
  ].filter(Boolean);
  for (const candidate of candidates) {
    const full = isAbsolute(candidate) ? resolve(candidate) : resolve(ROOT, candidate);
    if (existsSync(join(full, 'package.json'))) return full;
  }
  return explicit ? resolve(explicit) : null;
}

function valueAfter(flag) {
  const eq = args.find((arg) => arg.startsWith(`${flag}=`));
  if (eq) return eq.slice(flag.length + 1);
  const idx = args.indexOf(flag);
  if (idx >= 0 && args[idx + 1] && !args[idx + 1].startsWith('-')) return args[idx + 1];
  return '';
}

function nodeMeetsRequirement(requirement) {
  if (!requirement) return null;
  const current = Number(process.versions.node.split('.')[0]);
  const min = Number(String(requirement).match(/>=\s*(\d+)/)?.[1] || 0);
  return min ? current >= min : null;
}

function readJson(path) {
  try {
    if (!existsSync(path)) return null;
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return null;
  }
}

function safeRead(path) {
  try {
    return readFileSync(path, 'utf8');
  } catch {
    return '';
  }
}

function safeListDir(path) {
  try {
    if (!existsSync(path) || !statSync(path).isDirectory()) return [];
    return readdirSync(path)
      .filter((name) => !name.startsWith('.'))
      .sort()
      .slice(0, 50);
  } catch {
    return [];
  }
}

function fileContains(path, needle) {
  try {
    return readFileSync(path, 'utf8').includes(needle);
  } catch {
    return false;
  }
}

function firstMatch(text, regex) {
  const match = String(text || '').match(regex);
  return match ? match[1].trim() : '';
}

function readBulletValue(text, label) {
  const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return firstMatch(text, new RegExp(`^-\\s*${escaped}(?:[^\\S\\r\\n]*\\([^)]+\\))?:[^\\S\\r\\n]*(.+)$`, 'im'));
}

function readDisclosureValue(text, label) {
  const disclosure = readSection(text, 'Disclosure');
  return readBulletValue(disclosure || text, label);
}

function readStatusFromText(text) {
  return (
    firstMatch(text, /##\s+Status\s+`?([A-Za-z0-9_.-]+)`?/i) ||
    firstMatch(text, /##\s+Status[\s\S]{0,240}?`([A-Za-z0-9_.-]+)`/i) ||
    firstMatch(text, /\*\*Status:\*\*\s*`?([A-Za-z0-9_.-]+)`?/i) ||
    'unknown'
  ).toLowerCase();
}

function readDescription(text) {
  const quoted = firstMatch(text, /^\s*"([^"]{40,})"/m);
  if (quoted) return quoted;
  const lines = String(text).split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('`')) continue;
    if (trimmed.length > 40) return trimmed.replace(/^"|"$/g, '');
  }
  return '';
}

function readSection(text, heading) {
  const lines = String(text || '').split(/\r?\n/);
  const start = lines.findIndex((line) => new RegExp(`^##\\s+${heading}\\b`, 'i').test(line.trim()));
  if (start < 0) return '';
  const out = [];
  for (let i = start + 1; i < lines.length; i += 1) {
    if (/^##\s+/.test(lines[i])) break;
    out.push(lines[i]);
  }
  return out.join('\n').trim();
}

function readVariantRows(text) {
  const section = readSection(text, 'Variants');
  if (!section) return [];
  return section
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.startsWith('|') && !/^\|\s*-+/.test(line) && !/\|\s*Location\s*\|/i.test(line))
    .slice(0, 50);
}

function normalizeSeverity(value) {
  const text = String(value || '').toLowerCase();
  if (text.includes('critical')) return 'critical';
  if (text.includes('high')) return 'high';
  if (text.includes('moderate')) return 'moderate';
  if (text.includes('medium')) return 'medium';
  if (text.includes('low')) return 'low';
  return 'unknown';
}

function severityFromCvss(value) {
  const score = Number.parseFloat(String(value || ''));
  if (!Number.isFinite(score)) return 'unknown';
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'unknown';
}

function sanitizeForVigilToolName(input) {
  return String(input).replace(/[^a-zA-Z0-9_]/g, '_');
}
