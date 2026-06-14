#!/usr/bin/env node
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream, existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { homedir, platform } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SERVER_VERSION = '0.1.0';
const PROTOCOL_VERSIONS = ['2025-11-25', '2025-06-18'];
const DEFAULT_PROTOCOL_VERSION = PROTOCOL_VERSIONS[0];
const VALID_STATUSES = new Set(['recon', 'acquire', 'bindiff', 'variant', 'fuzz', 'triage', 'poc', 'disclose', 'closed']);

const config = loadConfig();

const tools = [
  {
    name: 'security.probe',
    title: 'Probe headless security lab',
    description: 'Report configured workspace, WSL distributions, Kali target, Ghidra headless path, and policy state without running lab tools.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {}
    }
  },
  {
    name: 'vigil.probe',
    title: 'Probe Vigil integration',
    description: 'Report local Vigil by Trenchwork integration status, including source checkout, project MCP config, and PatchPivot findings summary.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {}
    }
  },
  {
    name: 'vigil.findings_bundle',
    title: 'Export Vigil findings bundle',
    description: 'Export PatchPivot findings in the normalized bundle shape consumed by Vigil security analysis.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {}
    }
  },
  {
    name: 'vigil.project_mcp_config',
    title: 'Render Vigil project MCP config',
    description: 'Return the recommended .vigil/mcp.json server block for mounting PatchPivot inside Vigil.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {}
    }
  },
  {
    name: 'policy.explain',
    title: 'Explain execution policy',
    description: 'Return the active headless-only execution policy and blocked command patterns.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {}
    }
  },
  {
    name: 'policy.check_command',
    title: 'Check command policy',
    description: 'Evaluate a proposed Kali command against the active policy without executing it or requiring a scope file.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['command'],
      properties: {
        command: {
          type: 'string'
        },
        network: {
          type: 'string',
          enum: ['off', 'public-source', 'lab-only']
        },
        backend: {
          type: 'string',
          enum: ['kali', 'windows'],
          description: 'Policy namespace to evaluate. Defaults to kali.'
        }
      }
    }
  },
  {
    name: 'windows.probe',
    title: 'Probe native Windows security surface',
    description: 'Inspect local Windows, PowerShell, Defender, Firewall, WSL, and optional-feature availability without changing system state.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {}
    }
  },
  {
    name: 'windows.run',
    title: 'Run guarded native PowerShell',
    description: 'Run a scoped, headless-only PowerShell command on the Windows host. Requires an authorized finding scope file by default.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['finding', 'command'],
      properties: {
        finding: {
          type: 'string',
          description: 'Finding slug or absolute path under findings/.'
        },
        command: {
          type: 'string',
          description: 'Single-line PowerShell command after policy checks.'
        },
        cwd: {
          type: 'string',
          description: 'Optional working directory. Defaults to the finding directory.'
        },
        timeoutSeconds: {
          type: 'integer',
          minimum: 1,
          maximum: 7200
        },
        network: {
          type: 'string',
          enum: ['off', 'public-source', 'lab-only']
        },
        dryRun: {
          type: 'boolean'
        }
      }
    }
  },
  {
    name: 'windows.defender_status',
    title: 'Get Microsoft Defender status',
    description: 'Return selected Microsoft Defender status and preference fields with sensitive paths redacted.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {}
    }
  },
  {
    name: 'windows.defender_scan',
    title: 'Run Microsoft Defender custom scan',
    description: 'Run a headless Defender custom scan for a workspace/artifact path and record the result.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['path'],
      properties: {
        path: {
          type: 'string',
          description: 'File or directory under workspaceRoot or artifactRoot.'
        },
        finding: {
          type: 'string',
          description: 'Optional finding slug/path. If supplied, scope authorization is required and logs are written under the finding.'
        },
        timeoutSeconds: {
          type: 'integer',
          minimum: 1,
          maximum: 14400
        }
      }
    }
  },
  {
    name: 'windows.eventlog_query',
    title: 'Query Windows event logs',
    description: 'Query local Windows event logs with a bounded filter and optional finding output file.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        logName: {
          type: 'string',
          description: 'Log name, for example System, Application, Security, or Microsoft-Windows-Windows Defender/Operational.'
        },
        providerName: {
          type: 'string'
        },
        id: {
          type: 'integer'
        },
        startTimeIso: {
          type: 'string'
        },
        maxEvents: {
          type: 'integer',
          minimum: 1,
          maximum: 1000
        },
        finding: {
          type: 'string'
        },
        outputFile: {
          type: 'string',
          description: 'Optional path relative to the finding.'
        }
      }
    }
  },
  {
    name: 'windows.firewall_profiles',
    title: 'Get Windows Firewall profiles',
    description: 'Return local Windows Firewall profile posture.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {}
    }
  },
  {
    name: 'windows.optional_features',
    title: 'Probe Windows optional features',
    description: 'Probe selected optional Windows features. Reports elevation errors rather than prompting.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        featureNames: {
          type: 'array',
          items: {
            type: 'string'
          }
        }
      }
    }
  },
  {
    name: 'finding.list',
    title: 'List findings',
    description: 'List finding directories and their current README status.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        status: {
          type: 'string',
          description: 'Optional status filter.'
        }
      }
    }
  },
  {
    name: 'finding.update_status',
    title: 'Update finding status',
    description: 'Update the status token in a finding README.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['finding', 'status'],
      properties: {
        finding: {
          type: 'string',
          description: 'Finding slug or absolute path under findings/.'
        },
        status: {
          type: 'string',
          enum: Array.from(VALID_STATUSES)
        }
      }
    }
  },
  {
    name: 'kali.run',
    title: 'Run headless Kali command',
    description: 'Run a scoped, headless-only command in the configured Kali WSL distribution. Requires an authorized scope file by default.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['finding', 'command'],
      properties: {
        finding: {
          type: 'string',
          description: 'Finding slug or absolute path under findings/.'
        },
        command: {
          type: 'string',
          description: 'Shell command to run through bash -lc after policy checks.'
        },
        cwd: {
          type: 'string',
          description: 'Optional working directory. Defaults to the finding directory.'
        },
        timeoutSeconds: {
          type: 'integer',
          minimum: 1,
          maximum: 14400
        },
        network: {
          type: 'string',
          enum: ['off', 'public-source', 'lab-only'],
          description: 'Requested network mode. The active policy must allow it.'
        },
        dryRun: {
          type: 'boolean',
          description: 'Validate policy and return the command that would run, without executing it.'
        }
      }
    }
  },
  {
    name: 'ghidra.probe',
    title: 'Probe headless Ghidra',
    description: 'Check the configured analyzeHeadless path and Ghidra project/script directories.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {}
    }
  },
  {
    name: 'ghidra.analyze',
    title: 'Run headless Ghidra analysis',
    description: 'Import one binary with analyzeHeadless and export PatchPivot summary files. This never launches the Ghidra GUI.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['finding', 'binaryPath'],
      properties: {
        finding: {
          type: 'string',
          description: 'Finding slug or absolute path under findings/.'
        },
        binaryPath: {
          type: 'string',
          description: 'Absolute or workspace-relative path to the binary.'
        },
        projectName: {
          type: 'string',
          description: 'Optional Ghidra project name.'
        },
        outputName: {
          type: 'string',
          description: 'Output directory name under diff/ghidra/.'
        },
        timeoutSeconds: {
          type: 'integer',
          minimum: 1,
          maximum: 28800
        },
        extraAnalyzeArgs: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional extra analyzeHeadless flags. GUI launchers are never accepted.'
        }
      }
    }
  },
  {
    name: 'artifact.manifest',
    title: 'Create artifact manifest',
    description: 'Hash a file or directory and optionally write a manifest into the finding.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['path'],
      properties: {
        path: {
          type: 'string',
          description: 'File or directory to hash.'
        },
        finding: {
          type: 'string',
          description: 'Optional finding slug/path for writing the manifest.'
        },
        outputFile: {
          type: 'string',
          description: 'Optional manifest path relative to the finding.'
        },
        maxFiles: {
          type: 'integer',
          minimum: 1,
          maximum: 100000
        }
      }
    }
  }
];

const rl = readline.createInterface({
  input: process.stdin,
  crlfDelay: Infinity
});

rl.on('line', (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;
  let msg;
  try {
    msg = JSON.parse(trimmed);
  } catch (err) {
    sendError(null, -32700, `Parse error: ${err.message}`);
    return;
  }
  handleMessage(msg).catch((err) => {
    const id = Object.prototype.hasOwnProperty.call(msg, 'id') ? msg.id : null;
    sendError(id, -32603, err.message || String(err));
  });
});

process.stderr.write(`patchpivot-security-mcp ${SERVER_VERSION} ready on stdio\n`);

async function handleMessage(msg) {
  if (!msg || msg.jsonrpc !== '2.0') {
    sendError(msg?.id ?? null, -32600, 'Invalid JSON-RPC message');
    return;
  }

  if (!Object.prototype.hasOwnProperty.call(msg, 'id')) {
    await handleNotification(msg);
    return;
  }

  switch (msg.method) {
    case 'initialize':
      sendResult(msg.id, {
        protocolVersion: negotiateProtocol(msg.params?.protocolVersion),
        capabilities: {
          tools: {
            listChanged: false
          }
        },
        serverInfo: {
          name: 'patchpivot-security-mcp',
          title: 'PatchPivot Headless Security MCP',
          version: SERVER_VERSION
        },
        instructions: 'Headless-only defensive security research tools. Kali commands require an authorized scope file and are policy-filtered before execution.'
      });
      break;
    case 'ping':
      sendResult(msg.id, {});
      break;
    case 'tools/list':
      sendResult(msg.id, { tools });
      break;
    case 'tools/call':
      await handleToolCall(msg.id, msg.params ?? {});
      break;
    default:
      sendError(msg.id, -32601, `Unknown method: ${msg.method}`);
  }
}

async function handleNotification(msg) {
  if (msg.method === 'notifications/initialized' || msg.method === 'notifications/cancelled') return;
  process.stderr.write(`Ignoring notification: ${msg.method}\n`);
}

async function handleToolCall(id, params) {
  const name = params.name;
  const args = params.arguments ?? {};
  const tool = tools.find((t) => t.name === name);
  if (!tool) {
    sendError(id, -32602, `Unknown tool: ${name}`);
    return;
  }

  try {
    let result;
    switch (name) {
      case 'security.probe':
        result = await probeSecurityLab();
        break;
      case 'vigil.probe':
        result = runVigilBridge(['--probe']);
        break;
      case 'vigil.findings_bundle':
        result = runVigilBridge(['--export']);
        break;
      case 'vigil.project_mcp_config':
        result = runVigilBridge(['--config']);
        break;
      case 'policy.explain':
        result = explainPolicy();
        break;
      case 'policy.check_command':
        result = checkCommandPolicy(String(args.command || ''), args.network || defaultNetworkMode(args.backend || 'kali'), args.backend || 'kali');
        break;
      case 'windows.probe':
        result = await probeWindowsNative();
        break;
      case 'windows.run':
        result = await runWindowsCommand(args);
        break;
      case 'windows.defender_status':
        result = await getDefenderStatus();
        break;
      case 'windows.defender_scan':
        result = await runDefenderScan(args);
        break;
      case 'windows.eventlog_query':
        result = await queryWindowsEventLog(args);
        break;
      case 'windows.firewall_profiles':
        result = await getFirewallProfiles();
        break;
      case 'windows.optional_features':
        result = await probeWindowsOptionalFeatures(args);
        break;
      case 'finding.list':
        result = listFindings(args);
        break;
      case 'finding.update_status':
        result = updateFindingStatus(args);
        break;
      case 'kali.run':
        result = await runKali(args);
        break;
      case 'ghidra.probe':
        result = probeGhidra();
        break;
      case 'ghidra.analyze':
        result = await runGhidraAnalyze(args);
        break;
      case 'artifact.manifest':
        result = await artifactManifest(args);
        break;
      default:
        throw new Error(`Unhandled tool: ${name}`);
    }
    sendResult(id, toolResult(result));
  } catch (err) {
    sendResult(id, toolResult({ error: err.message || String(err) }, true));
  }
}

function sendResult(id, result) {
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, result }) + '\n');
}

function sendError(id, code, message, data) {
  const error = { code, message };
  if (data !== undefined) error.data = data;
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, error }) + '\n');
}

function toolResult(data, isError = false) {
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(data, null, 2)
      }
    ],
    structuredContent: data,
    isError
  };
}

function negotiateProtocol(requested) {
  if (requested && PROTOCOL_VERSIONS.includes(requested)) return requested;
  return DEFAULT_PROTOCOL_VERSION;
}

function loadConfig() {
  const ghidraHeadless = discoverGhidraHeadless();
  const defaults = {
    workspaceRoot: ROOT,
    artifactRoot: process.env.PATCHPIVOT_ARTIFACT_ROOT || join(homedir(), '.patchpivot', 'artifacts'),
    headlessOnly: true,
    requireScopeFile: true,
    scopeAuthorizedMarker: 'MCP-LAB-AUTHORIZED: yes',
    kali: {
      backend: 'wsl',
      distribution: process.env.PATCHPIVOT_KALI_DISTRO || 'kali-linux',
      user: process.env.PATCHPIVOT_KALI_USER || '',
      defaultTimeoutSeconds: 900,
      maxTimeoutSeconds: 7200,
      allowNetworkModes: ['off'],
      defaultNetworkMode: 'off'
    },
    windows: {
      powershell: process.env.PATCHPIVOT_POWERSHELL || 'powershell.exe',
      defaultTimeoutSeconds: 300,
      maxTimeoutSeconds: 3600,
      allowNetworkModes: ['off'],
      defaultNetworkMode: 'off',
      allowDefenderScan: true,
      allowEventLogQuery: true
    },
    ghidra: {
      analyzeHeadless: process.env.PATCHPIVOT_GHIDRA_HEADLESS || ghidraHeadless,
      projectRoot: process.env.PATCHPIVOT_GHIDRA_PROJECT_ROOT || join(homedir(), '.patchpivot', 'ghidra', 'projects'),
      scriptPath: join(ROOT, 'scripts', 'ghidra'),
      defaultTimeoutSeconds: 3600,
      maxTimeoutSeconds: 14400
    },
    policy: {
      maxCommandLength: 4000,
      blockedCommandPatterns: [
        '\\b(startx|xinit|xfce4-session|gnome-session|kdeinit|plasmashell|mate-session|openbox|i3|xterm|alacritty|kitty|gnome-terminal|konsole|xfce4-terminal)\\b',
        '\\b(firefox|chromium|google-chrome|brave-browser|burpsuite|wireshark|ghidraRun|ghidra)\\b',
        '\\b(xdg-open|gio\\s+open|explorer\\.exe|Start-Process)\\b',
        '\\b(Invoke-WebRequest|Invoke-RestMethod|iwr|irm|Start-BitsTransfer|bitsadmin|certutil\\s+-urlcache)\\b',
        '\\b(msfconsole|msfvenom|metasploit|exploitdb|searchsploit)\\b',
        '\\b(nmap|masscan|zmap|hping3|nping|nikto|sqlmap|hydra|medusa|patator|crackmapexec|netcat|nc|ncat|socat)\\b',
        '\\b(mimikatz|secretsdump|samdump2|lsassy|evil-winrm|psexec|wmiexec|dcsync)\\b',
        '\\b(Set-MpPreference|Add-MpPreference|Remove-MpPreference)\\b',
        '\\b(Disable-WindowsOptionalFeature|Enable-PSRemoting|winrm|diskpart|format-volume|bcdedit)\\b',
        '\\b(New-LocalUser|net\\s+user|net\\s+localgroup|schtasks|New-Service|sc\\.exe\\s+create)\\b',
        'rm\\s+-rf\\s+/',
        'Remove-Item\\s+.*(-Recurse|/s).*(:\\\\|\\$env:SystemRoot|C:\\\\Windows|C:\\\\Users)',
        '\\bmkfs\\b',
        '\\bdd\\b.*\\bof=',
        ':\\s*\\(\\s*\\)\\s*\\{\\s*:'
      ],
      networkIndicators: [
        'https?://',
        'ftp://',
        'ssh://',
        '\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b',
        '\\b(curl|wget|aria2c|ssh|scp|sftp|rsync|git\\s+clone|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|Start-BitsTransfer)\\b'
      ]
    }
  };

  const candidates = [
    process.env.PATCHPIVOT_MCP_CONFIG,
    join(ROOT, 'config', 'security-mcp.local.json'),
    join(ROOT, 'config', 'security-mcp.json')
  ].filter(Boolean);

  let loaded = {};
  let configPath = null;
  for (const candidate of candidates) {
    const full = resolve(candidate);
    if (existsSync(full)) {
      loaded = JSON.parse(readFileSync(full, 'utf8'));
      configPath = full;
      break;
    }
  }

  const merged = deepMerge(defaults, loaded);
  merged.configPath = configPath;
  merged.workspaceRoot = resolve(expandConfigValue(merged.workspaceRoot, merged));
  merged.artifactRoot = resolve(expandConfigValue(merged.artifactRoot, merged));
  merged.ghidra.analyzeHeadless = resolve(expandConfigValue(merged.ghidra.analyzeHeadless, merged));
  merged.ghidra.projectRoot = resolve(expandConfigValue(merged.ghidra.projectRoot, merged));
  merged.ghidra.scriptPath = resolve(merged.workspaceRoot, expandConfigValue(merged.ghidra.scriptPath, merged));

  if (!merged.headlessOnly) {
    throw new Error('Refusing to start: headlessOnly must be true.');
  }

  merged.policy.blockedRegexes = merged.policy.blockedCommandPatterns.map((p) => new RegExp(p, 'i'));
  merged.policy.networkRegexes = merged.policy.networkIndicators.map((p) => new RegExp(p, 'i'));
  return merged;
}

function deepMerge(base, override) {
  if (!override || typeof override !== 'object') return base;
  const out = Array.isArray(base) ? [...base] : { ...base };
  for (const [key, value] of Object.entries(override)) {
    if (value && typeof value === 'object' && !Array.isArray(value) && base[key] && typeof base[key] === 'object' && !Array.isArray(base[key])) {
      out[key] = deepMerge(base[key], value);
    } else {
      out[key] = value;
    }
  }
  return out;
}

function expandConfigValue(value, cfg) {
  return String(value)
    .replaceAll('${workspaceRoot}', cfg.workspaceRoot)
    .replaceAll('${artifactRoot}', cfg.artifactRoot);
}

function discoverGhidraHeadless() {
  const candidates = [
    process.env.PATCHPIVOT_GHIDRA_HEADLESS,
    'C:\\ghidra_12.1_PUBLIC\\support\\analyzeHeadless.bat',
    'C:\\ghidra\\support\\analyzeHeadless.bat',
    '/opt/ghidra/support/analyzeHeadless',
    '/usr/local/ghidra/support/analyzeHeadless'
  ].filter(Boolean);
  return candidates.find((candidate) => existsSync(candidate)) || candidates[0];
}

async function probeSecurityLab() {
  const wsl = probeWsl();
  return {
    server: {
      name: 'patchpivot-security-mcp',
      version: SERVER_VERSION,
      protocolVersions: PROTOCOL_VERSIONS
    },
    platform: {
      node: process.version,
      os: platform(),
      cwd: process.cwd()
    },
    workspace: {
      root: config.workspaceRoot,
      exists: existsSync(config.workspaceRoot),
      artifactRoot: config.artifactRoot,
      configPath: config.configPath
    },
    kali: {
      backend: config.kali.backend,
      distribution: config.kali.distribution,
      user: config.kali.user || '',
      available: wsl.distributions.some((d) => d.name === config.kali.distribution),
      wsl
    },
    ghidra: probeGhidra(),
    windows: await probeWindowsNative(),
    policy: {
      headlessOnly: config.headlessOnly,
      requireScopeFile: config.requireScopeFile,
      scopeAuthorizedMarker: config.scopeAuthorizedMarker,
      defaultNetworkMode: config.kali.defaultNetworkMode,
      allowNetworkModes: config.kali.allowNetworkModes
    }
  };
}

function runVigilBridge(bridgeArgs) {
  const script = join(config.workspaceRoot, 'scripts', 'vigil', 'patchpivot-vigil.mjs');
  if (!existsSync(script)) {
    throw new Error(`Vigil integration helper not found: ${script}`);
  }
  const res = spawnSync(process.execPath, [script, ...bridgeArgs], {
    cwd: config.workspaceRoot,
    encoding: 'utf8',
    timeout: 30000,
    windowsHide: true,
    env: scrubHostEnv(process.env),
    maxBuffer: 64 * 1024 * 1024
  });
  if (res.error) {
    throw new Error(`Vigil integration helper failed: ${res.error.message}`);
  }
  if (res.status !== 0) {
    throw new Error(`Vigil integration helper exited ${res.status}: ${(res.stderr || res.stdout || '').trim()}`);
  }
  try {
    return JSON.parse(String(res.stdout || '{}'));
  } catch (err) {
    throw new Error(`Vigil integration helper returned invalid JSON: ${err.message}`);
  }
}

function probeWsl() {
  if (platform() !== 'win32') {
    return { available: false, distributions: [], raw: '', note: 'WSL probing is only available on Windows hosts.' };
  }
  const res = spawnSync('wsl.exe', ['-l', '-v'], { encoding: 'buffer' });
  const raw = decodeWindowsBuffer(res.stdout || Buffer.alloc(0)) + decodeWindowsBuffer(res.stderr || Buffer.alloc(0));
  const distributions = [];
  for (const line of raw.split(/\r?\n/)) {
    const clean = line.replace(/\0/g, '').trim();
    if (!clean || /^NAME\s+STATE\s+VERSION/i.test(clean)) continue;
    const normalized = clean.replace(/^\*\s*/, '').trim();
    const parts = normalized.split(/\s{2,}/);
    if (parts[0]) {
      distributions.push({
        name: parts[0],
        state: parts[1] || '',
        version: parts[2] || ''
      });
    }
  }
  return {
    available: res.status === 0,
    exitCode: res.status,
    distributions,
    raw: raw.replace(/\0/g, '')
  };
}

function decodeWindowsBuffer(buf) {
  if (!buf || buf.length === 0) return '';
  const utf16 = buf.toString('utf16le').replace(/\0/g, '');
  const utf8 = buf.toString('utf8').replace(/\0/g, '');
  const score = (s) => (s.match(/[A-Za-z0-9_ -]/g) || []).length;
  return score(utf16) > score(utf8) ? utf16 : utf8;
}

function probeGhidra() {
  return {
    analyzeHeadless: config.ghidra.analyzeHeadless,
    analyzeHeadlessExists: existsSync(config.ghidra.analyzeHeadless),
    projectRoot: config.ghidra.projectRoot,
    projectRootExists: existsSync(config.ghidra.projectRoot),
    scriptPath: config.ghidra.scriptPath,
    scriptPathExists: existsSync(config.ghidra.scriptPath),
    headlessOnly: true
  };
}

async function probeWindowsNative() {
  if (platform() !== 'win32') {
    return {
      available: false,
      note: 'Native Windows tools are only available on Windows hosts.'
    };
  }
  const featureNames = [
    'Microsoft-Hyper-V-All',
    'Containers-DisposableClientVM',
    'Microsoft-Windows-Subsystem-Linux',
    'VirtualMachinePlatform',
    'Microsoft-Windows-Defender-ApplicationGuard'
  ];
  const script = `
$ErrorActionPreference = 'Stop'
function Has-Command($Name) { [bool](Get-Command $Name -ErrorAction SilentlyContinue) }
$computer = Get-ComputerInfo | Select-Object WindowsProductName,WindowsVersion,OsBuildNumber,OsArchitecture,CsManufacturer,CsModel,HyperVisorPresent
$ps = [pscustomobject]@{
  PSVersion = $PSVersionTable.PSVersion.ToString()
  PSEdition = $PSVersionTable.PSEdition
  BuildVersion = $PSVersionTable.BuildVersion.ToString()
}
$features = @()
foreach ($name in @(${featureNames.map(psString).join(',')})) {
  try {
    $feature = Get-WindowsOptionalFeature -Online -FeatureName $name -ErrorAction Stop
    $features += [pscustomobject]@{ FeatureName = $feature.FeatureName; State = [string]$feature.State; Error = $null }
  } catch {
    $features += [pscustomobject]@{ FeatureName = $name; State = $null; Error = $_.Exception.Message }
  }
}
[pscustomobject]@{
  Computer = $computer
  PowerShell = $ps
  Commands = [pscustomobject]@{
    GetMpComputerStatus = Has-Command 'Get-MpComputerStatus'
    StartMpScan = Has-Command 'Start-MpScan'
    GetNetFirewallProfile = Has-Command 'Get-NetFirewallProfile'
    GetWinEvent = Has-Command 'Get-WinEvent'
    GetWindowsOptionalFeature = Has-Command 'Get-WindowsOptionalFeature'
  }
  OptionalFeatures = $features
} | ConvertTo-Json -Depth 8
`;
  return runPowerShellJson(script, config.windows.defaultTimeoutSeconds);
}

async function runWindowsCommand(args) {
  const finding = resolveFinding(args.finding);
  ensureScopeAuthorized(finding);

  const command = String(args.command || '');
  const network = args.network || config.windows.defaultNetworkMode || 'off';
  const policy = checkCommandPolicy(command, network, 'windows');
  if (!policy.allowed) {
    throw new Error(`Command refused by policy: ${policy.reason}`);
  }

  const cwd = resolveAllowedCwd(args.cwd, finding.path);
  const timeoutSeconds = clampTimeout(args.timeoutSeconds, config.windows.defaultTimeoutSeconds, config.windows.maxTimeoutSeconds);
  const run = makeRunPaths(finding, 'windows');
  const psArgs = ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', command];

  const summary = {
    runId: run.runId,
    finding: finding.slug,
    backend: 'windows',
    command,
    network,
    cwd,
    timeoutSeconds,
    dryRun: Boolean(args.dryRun),
    startedAt: new Date().toISOString(),
    policy
  };

  if (args.dryRun) {
    return {
      ...summary,
      argv: [config.windows.powershell, ...psArgs],
      note: 'dryRun=true; command was not executed.'
    };
  }

  mkdirSync(run.runDir, { recursive: true });
  const result = await spawnWithLogs(config.windows.powershell, psArgs, {
    cwd,
    timeoutSeconds,
    stdoutPath: run.stdoutPath,
    stderrPath: run.stderrPath
  });
  const finished = {
    ...summary,
    finishedAt: new Date().toISOString(),
    exitCode: result.exitCode,
    signal: result.signal,
    timedOut: result.timedOut,
    stdoutPath: relative(finding.path, run.stdoutPath),
    stderrPath: relative(finding.path, run.stderrPath),
    stdoutPreview: result.stdoutPreview,
    stderrPreview: result.stderrPreview
  };
  writeFileSync(run.runPath, JSON.stringify(finished, null, 2) + '\n', 'utf8');
  return {
    ...finished,
    runPath: relative(finding.path, run.runPath)
  };
}

async function getDefenderStatus() {
  const script = `
$ErrorActionPreference = 'Stop'
if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
  throw 'Get-MpComputerStatus is not available on this host.'
}
$status = Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,AntispywareEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,NISEnabled,OnAccessProtectionEnabled,RealTimeProtectionEnabled,IsTamperProtected,FullScanAge,QuickScanAge,AntivirusSignatureLastUpdated,NISSignatureLastUpdated,AMEngineVersion,AMProductVersion,AntivirusSignatureVersion,NISSignatureVersion
$pref = $null
if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
  $pref = Get-MpPreference | Select-Object PUAProtection,CloudBlockLevel,MAPSReporting,SubmitSamplesConsent,DisableRealtimeMonitoring,DisableBehaviorMonitoring,DisableIOAVProtection,SignatureScheduleDay,ScanScheduleDay,ScanParameters
}
[pscustomobject]@{
  Status = $status
  Preference = $pref
} | ConvertTo-Json -Depth 6
`;
  return runPowerShellJson(script, config.windows.defaultTimeoutSeconds);
}

async function runDefenderScan(args) {
  if (!config.windows.allowDefenderScan) throw new Error('Defender scans are disabled by policy.');
  const target = resolveAllowedHostPath(args.path);
  let finding = null;
  if (args.finding) {
    finding = resolveFinding(args.finding);
    ensureScopeAuthorized(finding);
  }
  const timeoutSeconds = clampTimeout(args.timeoutSeconds, 7200, 14400);
  const run = makeRunPaths(finding, 'defender');
  mkdirSync(run.runDir, { recursive: true });

  const script = `
$ErrorActionPreference = 'Stop'
if (-not (Get-Command Start-MpScan -ErrorAction SilentlyContinue)) {
  throw 'Start-MpScan is not available on this host.'
}
Start-MpScan -ScanType CustomScan -ScanPath ${psString(target)}
$threats = @()
if (Get-Command Get-MpThreatDetection -ErrorAction SilentlyContinue) {
  $threats = Get-MpThreatDetection | Select-Object -First 25 ThreatID,ThreatName,Resources,InitialDetectionTime,LastThreatStatusChangeTime,ActionSuccess
}
[pscustomobject]@{
  ScanPath = ${psString(target)}
  ThreatDetections = $threats
} | ConvertTo-Json -Depth 8
`;
  const result = await spawnWithLogs(config.windows.powershell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script], {
    cwd: config.workspaceRoot,
    timeoutSeconds,
    stdoutPath: run.stdoutPath,
    stderrPath: run.stderrPath
  });

  const finished = {
    runId: run.runId,
    backend: 'windows-defender',
    finding: finding?.slug || null,
    scanPath: target,
    timeoutSeconds,
    startedAt: run.startedAt,
    finishedAt: new Date().toISOString(),
    exitCode: result.exitCode,
    signal: result.signal,
    timedOut: result.timedOut,
    stdoutPath: finding ? relative(finding.path, run.stdoutPath) : run.stdoutPath,
    stderrPath: finding ? relative(finding.path, run.stderrPath) : run.stderrPath,
    stdoutPreview: result.stdoutPreview,
    stderrPreview: result.stderrPreview
  };
  writeFileSync(run.runPath, JSON.stringify(finished, null, 2) + '\n', 'utf8');
  return {
    ...finished,
    runPath: finding ? relative(finding.path, run.runPath) : run.runPath
  };
}

async function queryWindowsEventLog(args) {
  if (!config.windows.allowEventLogQuery) throw new Error('Event log queries are disabled by policy.');
  const maxEvents = Math.max(1, Math.min(Number(args.maxEvents || 50), 1000));
  const logName = args.logName || 'System';
  assertSafeEventValue(logName, 'logName');
  if (args.providerName) assertSafeEventValue(args.providerName, 'providerName');
  const id = args.id === undefined ? null : Number(args.id);
  if (id !== null && (!Number.isInteger(id) || id < 0 || id > 65535)) {
    throw new Error('id must be an integer between 0 and 65535');
  }
  let startTimeExpr = '$null';
  if (args.startTimeIso) {
    const dt = new Date(args.startTimeIso);
    if (Number.isNaN(dt.getTime())) throw new Error('startTimeIso must parse as a date-time');
    startTimeExpr = `[datetime]::Parse(${psString(dt.toISOString())})`;
  }

  const script = `
$ErrorActionPreference = 'Stop'
$filter = @{ LogName = ${psString(logName)} }
if (${args.providerName ? '$true' : '$false'}) { $filter.ProviderName = ${psString(args.providerName || '')} }
if (${id === null ? '$false' : '$true'}) { $filter.Id = ${id === null ? 0 : id} }
$start = ${startTimeExpr}
if ($start -ne $null) { $filter.StartTime = $start }
$events = Get-WinEvent -FilterHashtable $filter -MaxEvents ${maxEvents} | Select-Object TimeCreated,Id,ProviderName,LogName,LevelDisplayName,RecordId,MachineName,@{Name='Message';Expression={ if ($_.Message -and $_.Message.Length -gt 2000) { $_.Message.Substring(0,2000) } else { $_.Message } }}
[pscustomobject]@{
  Filter = $filter
  Count = @($events).Count
  Events = $events
} | ConvertTo-Json -Depth 8
`;
  const data = await runPowerShellJson(script, config.windows.defaultTimeoutSeconds);
  if (args.finding && args.outputFile) {
    const finding = resolveFinding(args.finding);
    const outPath = resolve(finding.path, args.outputFile);
    assertInside(outPath, finding.path, 'Event log output must stay inside finding directory');
    mkdirSync(dirname(outPath), { recursive: true });
    writeFileSync(outPath, JSON.stringify(data, null, 2) + '\n', 'utf8');
    data.outputFile = relative(finding.path, outPath);
  }
  return data;
}

async function getFirewallProfiles() {
  const script = `
$ErrorActionPreference = 'Stop'
if (-not (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
  throw 'Get-NetFirewallProfile is not available on this host.'
}
Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,NotifyOnListen,LogAllowed,LogBlocked,LogFileName | ConvertTo-Json -Depth 5
`;
  return runPowerShellJson(script, config.windows.defaultTimeoutSeconds);
}

async function probeWindowsOptionalFeatures(args) {
  const names = Array.isArray(args.featureNames) && args.featureNames.length
    ? args.featureNames.slice(0, 50)
    : ['Microsoft-Hyper-V-All', 'Containers-DisposableClientVM', 'Microsoft-Windows-Subsystem-Linux', 'VirtualMachinePlatform', 'Microsoft-Windows-Defender-ApplicationGuard'];
  for (const name of names) assertSafeEventValue(name, 'featureName');
  const script = `
$features = @()
foreach ($name in @(${names.map(psString).join(',')})) {
  try {
    $feature = Get-WindowsOptionalFeature -Online -FeatureName $name -ErrorAction Stop
    $features += [pscustomobject]@{ FeatureName = $feature.FeatureName; State = [string]$feature.State; Error = $null }
  } catch {
    $features += [pscustomobject]@{ FeatureName = $name; State = $null; Error = $_.Exception.Message }
  }
}
$features | ConvertTo-Json -Depth 5
`;
  return runPowerShellJson(script, config.windows.defaultTimeoutSeconds);
}

function explainPolicy() {
  return {
    headlessOnly: config.headlessOnly,
    requireScopeFile: config.requireScopeFile,
    scopeAuthorizedMarker: config.scopeAuthorizedMarker,
    kali: {
      backend: config.kali.backend,
      distribution: config.kali.distribution,
      user: config.kali.user || '',
      defaultNetworkMode: config.kali.defaultNetworkMode,
      allowNetworkModes: config.kali.allowNetworkModes,
      defaultTimeoutSeconds: config.kali.defaultTimeoutSeconds,
      maxTimeoutSeconds: config.kali.maxTimeoutSeconds
    },
    windows: {
      powershell: config.windows.powershell,
      defaultNetworkMode: config.windows.defaultNetworkMode,
      allowNetworkModes: config.windows.allowNetworkModes,
      defaultTimeoutSeconds: config.windows.defaultTimeoutSeconds,
      maxTimeoutSeconds: config.windows.maxTimeoutSeconds,
      allowDefenderScan: config.windows.allowDefenderScan,
      allowEventLogQuery: config.windows.allowEventLogQuery
    },
    blockedCommandPatterns: config.policy.blockedCommandPatterns,
    networkIndicators: config.policy.networkIndicators,
    notes: [
      'GUI launchers are blocked and DISPLAY/WAYLAND/WSLg variables are stripped.',
      'kali.run defaults to network=off and only permits configured network modes.',
      'kali.run requires intel/scope.md to contain the authorized marker unless disabled in local config.',
      'Policy checks are guardrails, not a sandbox. Use VM, WSL, firewall, and cloud controls for isolation.'
    ]
  };
}

function listFindings(args) {
  const findingsDir = join(config.workspaceRoot, 'findings');
  const entries = readdirSync(findingsDir, { withFileTypes: true })
    .filter((d) => d.isDirectory() && d.name !== '_template')
    .map((d) => {
      const dir = join(findingsDir, d.name);
      const readme = join(dir, 'README.md');
      return {
        slug: d.name,
        path: dir,
        status: existsSync(readme) ? readStatus(readme) : 'unknown'
      };
    })
    .filter((entry) => !args.status || entry.status === args.status)
    .sort((a, b) => a.slug.localeCompare(b.slug));
  return { findings: entries };
}

function readStatus(readmePath) {
  const text = readFileSync(readmePath, 'utf8');
  const statusHeading = text.match(/## Status\s+`?([a-z-]+)`?/i);
  if (statusHeading) return statusHeading[1].toLowerCase();
  const ticked = text.match(/## Status[\s\S]{0,200}?`([a-z-]+)`/i);
  if (ticked) return ticked[1].toLowerCase();
  const inline = text.match(/\*\*Status:\*\*\s*`?([a-z-]+)`?/i);
  if (inline) return inline[1].toLowerCase();
  return 'unknown';
}

function updateFindingStatus(args) {
  if (!VALID_STATUSES.has(args.status)) {
    throw new Error(`Invalid status: ${args.status}`);
  }
  const finding = resolveFinding(args.finding);
  const readme = join(finding.path, 'README.md');
  if (!existsSync(readme)) throw new Error(`Missing README.md for ${finding.slug}`);
  const text = readFileSync(readme, 'utf8');
  const updated = replaceStatus(text, args.status);
  writeFileSync(readme, updated, 'utf8');
  return {
    slug: finding.slug,
    path: finding.path,
    status: args.status
  };
}

function replaceStatus(text, status) {
  if (/\*\*Status:\*\*/i.test(text)) {
    return text.replace(/(\*\*Status:\*\*\s*)`?([a-z-]+)`?/i, `$1\`${status}\``);
  }
  const lines = text.split(/\r?\n/);
  const heading = lines.findIndex((line) => /^## Status\s*$/i.test(line.trim()));
  if (heading >= 0) {
    for (let i = heading + 1; i < Math.min(lines.length, heading + 8); i += 1) {
      if (/`[a-z-]+`/i.test(lines[i])) {
        lines[i] = lines[i].replace(/`[a-z-]+`/i, `\`${status}\``);
        return lines.join('\n');
      }
      if (lines[i].trim() && !lines[i].startsWith('#')) {
        lines.splice(i, 0, `\`${status}\``);
        return lines.join('\n');
      }
    }
    lines.splice(heading + 1, 0, '', `\`${status}\``);
    return lines.join('\n');
  }
  return text.trimEnd() + `\n\n## Status\n\n\`${status}\`\n`;
}

async function runKali(args) {
  if (config.kali.backend !== 'wsl') {
    throw new Error(`Unsupported Kali backend: ${config.kali.backend}`);
  }
  const finding = resolveFinding(args.finding);
  ensureScopeAuthorized(finding);

  const command = String(args.command || '');
  const network = args.network || config.kali.defaultNetworkMode || 'off';
  const policy = checkCommandPolicy(command, network, 'kali');
  if (!policy.allowed) {
    throw new Error(`Command refused by policy: ${policy.reason}`);
  }

  const cwd = resolveAllowedCwd(args.cwd, finding.path);
  const timeoutSeconds = clampTimeout(args.timeoutSeconds, config.kali.defaultTimeoutSeconds, config.kali.maxTimeoutSeconds);
  const linuxCwd = windowsPathToWsl(cwd);
  const runId = makeRunId('kali');
  const runDir = join(finding.path, 'triage', 'runs', runId);
  const stdoutPath = join(runDir, 'stdout.txt');
  const stderrPath = join(runDir, 'stderr.txt');
  const runPath = join(runDir, 'run.json');

  const wslArgs = [
    '-d', config.kali.distribution
  ];
  if (config.kali.user) {
    const user = String(config.kali.user);
    if (!/^[A-Za-z_][A-Za-z0-9_-]{0,31}$/.test(user)) {
      throw new Error(`Invalid WSL user in config: ${user}`);
    }
    wslArgs.push('-u', user);
  }
  wslArgs.push(
    '--cd', linuxCwd,
    '--',
    'env',
    '-i',
    'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    'LANG=C.UTF-8',
    'LC_ALL=C.UTF-8',
    'TERM=dumb',
    'DEBIAN_FRONTEND=noninteractive',
    `PATCHPIVOT_ROOT=${windowsPathToWsl(config.workspaceRoot)}`,
    `PATCHPIVOT_FINDING=${windowsPathToWsl(finding.path)}`,
    `PATCHPIVOT_ARTIFACT_ROOT=${windowsPathToWsl(config.artifactRoot)}`,
    'bash',
    '-lc',
    command
  );

  const summary = {
    runId,
    finding: finding.slug,
    command,
    backend: 'wsl',
    distribution: config.kali.distribution,
    user: config.kali.user || '',
    network,
    cwd,
    linuxCwd,
    timeoutSeconds,
    dryRun: Boolean(args.dryRun),
    startedAt: new Date().toISOString(),
    policy
  };

  if (args.dryRun) {
    return {
      ...summary,
      argv: ['wsl.exe', ...wslArgs],
      note: 'dryRun=true; command was not executed.'
    };
  }

  mkdirSync(runDir, { recursive: true });
  const result = await spawnWithLogs('wsl.exe', wslArgs, { cwd: config.workspaceRoot, timeoutSeconds, stdoutPath, stderrPath });
  const finished = {
    ...summary,
    finishedAt: new Date().toISOString(),
    exitCode: result.exitCode,
    signal: result.signal,
    timedOut: result.timedOut,
    stdoutPath: relative(finding.path, stdoutPath),
    stderrPath: relative(finding.path, stderrPath),
    stdoutPreview: result.stdoutPreview,
    stderrPreview: result.stderrPreview
  };
  writeFileSync(runPath, JSON.stringify(finished, null, 2) + '\n', 'utf8');
  return {
    ...finished,
    runPath: relative(finding.path, runPath)
  };
}

async function runGhidraAnalyze(args) {
  const finding = resolveFinding(args.finding);
  ensureScopeAuthorized(finding);
  if (!existsSync(config.ghidra.analyzeHeadless)) {
    throw new Error(`Ghidra analyzeHeadless not found: ${config.ghidra.analyzeHeadless}`);
  }

  const binaryPath = resolveInputPath(args.binaryPath);
  if (!existsSync(binaryPath)) throw new Error(`Binary does not exist: ${binaryPath}`);
  const binaryStat = statSync(binaryPath);
  if (!binaryStat.isFile()) throw new Error(`Binary path is not a file: ${binaryPath}`);

  const outputName = safeName(args.outputName || stem(binaryPath));
  const outputDir = join(finding.path, 'diff', 'ghidra', outputName);
  const projectName = safeName(args.projectName || `${finding.slug}-${outputName}`);
  const projectRoot = config.ghidra.projectRoot;
  const timeoutSeconds = clampTimeout(args.timeoutSeconds, config.ghidra.defaultTimeoutSeconds, config.ghidra.maxTimeoutSeconds);
  const extraAnalyzeArgs = Array.isArray(args.extraAnalyzeArgs) ? args.extraAnalyzeArgs : [];
  for (const value of extraAnalyzeArgs) {
    if (/ghidraRun|gui|display|startx|xinit/i.test(value)) {
      throw new Error(`Refusing GUI-related Ghidra argument: ${value}`);
    }
  }

  mkdirSync(outputDir, { recursive: true });
  mkdirSync(projectRoot, { recursive: true });

  const runId = makeRunId('ghidra');
  const runDir = join(finding.path, 'triage', 'runs', runId);
  const stdoutPath = join(runDir, 'stdout.txt');
  const stderrPath = join(runDir, 'stderr.txt');
  const runPath = join(runDir, 'run.json');
  mkdirSync(runDir, { recursive: true });

  const ghidraArgs = [
    projectRoot,
    projectName,
    '-import',
    binaryPath,
    '-overwrite',
    '-scriptPath',
    config.ghidra.scriptPath,
    ...extraAnalyzeArgs,
    '-postScript',
    'ExportPatchPivotSummary.java',
    outputDir
  ];

  const started = {
    runId,
    finding: finding.slug,
    binaryPath,
    binarySha256: await sha256File(binaryPath),
    analyzeHeadless: config.ghidra.analyzeHeadless,
    projectRoot,
    projectName,
    outputDir,
    timeoutSeconds,
    startedAt: new Date().toISOString(),
    headlessOnly: true
  };

  const result = await spawnWithLogs(config.ghidra.analyzeHeadless, ghidraArgs, { cwd: config.workspaceRoot, timeoutSeconds, stdoutPath, stderrPath });
  const finished = {
    ...started,
    finishedAt: new Date().toISOString(),
    exitCode: result.exitCode,
    signal: result.signal,
    timedOut: result.timedOut,
    stdoutPath: relative(finding.path, stdoutPath),
    stderrPath: relative(finding.path, stderrPath),
    stdoutPreview: result.stdoutPreview,
    stderrPreview: result.stderrPreview,
    exports: existsSync(outputDir) ? readdirSync(outputDir).sort().map((name) => relative(finding.path, join(outputDir, name))) : []
  };
  writeFileSync(runPath, JSON.stringify(finished, null, 2) + '\n', 'utf8');
  return {
    ...finished,
    runPath: relative(finding.path, runPath)
  };
}

async function artifactManifest(args) {
  const target = resolveInputPath(args.path);
  if (!existsSync(target)) throw new Error(`Path does not exist: ${target}`);
  const maxFiles = args.maxFiles || 10000;
  const entries = [];
  if (statSync(target).isDirectory()) {
    const files = walkFiles(target, maxFiles);
    for (const file of files) {
      entries.push({
        path: relative(target, file).split(sep).join('/'),
        bytes: statSync(file).size,
        sha256: await sha256File(file)
      });
    }
  } else {
    entries.push({
      path: target,
      bytes: statSync(target).size,
      sha256: await sha256File(target)
    });
  }

  const manifest = {
    generatedAt: new Date().toISOString(),
    root: target,
    type: statSync(target).isDirectory() ? 'directory' : 'file',
    files: entries
  };
  manifest.manifestSha256 = sha256String(JSON.stringify(manifest.files));

  if (args.finding) {
    const finding = resolveFinding(args.finding);
    const outputFile = args.outputFile || join('diff', `artifact-manifest-${safeName(stem(target))}.json`);
    const outPath = resolve(finding.path, outputFile);
    assertInside(outPath, finding.path, 'Manifest output must stay inside finding directory');
    mkdirSync(dirname(outPath), { recursive: true });
    writeFileSync(outPath, JSON.stringify(manifest, null, 2) + '\n', 'utf8');
    manifest.outputFile = relative(finding.path, outPath);
  }

  return manifest;
}

function resolveFinding(value) {
  if (!value || typeof value !== 'string') throw new Error('finding is required');
  const candidate = isAbsolute(value) ? resolve(value) : resolve(config.workspaceRoot, 'findings', value);
  const findingsRoot = resolve(config.workspaceRoot, 'findings');
  assertInside(candidate, findingsRoot, 'Finding must be under findings/');
  if (!existsSync(candidate) || !statSync(candidate).isDirectory()) {
    throw new Error(`Finding not found: ${candidate}`);
  }
  return {
    slug: candidate.split(/[\\/]/).pop(),
    path: candidate
  };
}

function ensureScopeAuthorized(finding) {
  if (!config.requireScopeFile) return;
  const scope = join(finding.path, 'intel', 'scope.md');
  if (!existsSync(scope)) {
    throw new Error(`Missing scope file: ${relative(config.workspaceRoot, scope)}. Copy findings/_template/intel/scope.md and authorize it before lab execution.`);
  }
  const text = readFileSync(scope, 'utf8');
  if (!text.includes(config.scopeAuthorizedMarker)) {
    throw new Error(`Scope file is not authorized. Required marker: ${config.scopeAuthorizedMarker}`);
  }
}

function checkCommandPolicy(command, network, backend = 'kali') {
  if (!command.trim()) return { allowed: false, reason: 'empty command' };
  if (command.length > config.policy.maxCommandLength) {
    return { allowed: false, reason: `command exceeds max length ${config.policy.maxCommandLength}` };
  }
  if (/[\0\r\n]/.test(command)) {
    return { allowed: false, reason: 'command must be a single line without NUL or newline characters' };
  }
  for (const regex of config.policy.blockedRegexes) {
    if (regex.test(command)) {
      return { allowed: false, reason: `blocked pattern: ${regex.source}` };
    }
  }
  const allowedNetworkModes = backend === 'windows' ? config.windows.allowNetworkModes : config.kali.allowNetworkModes;
  if (!allowedNetworkModes.includes(network)) {
    return { allowed: false, reason: `network mode '${network}' is not enabled by policy` };
  }
  if (network === 'off') {
    for (const regex of config.policy.networkRegexes) {
      if (regex.test(command)) {
        return { allowed: false, reason: `network indicator blocked while network=off: ${regex.source}` };
      }
    }
  }
  return { allowed: true, network, backend };
}

function defaultNetworkMode(backend) {
  return backend === 'windows'
    ? config.windows.defaultNetworkMode || 'off'
    : config.kali.defaultNetworkMode || 'off';
}

function resolveAllowedCwd(value, defaultDir) {
  const candidate = value ? (isAbsolute(value) ? resolve(value) : resolve(defaultDir, value)) : defaultDir;
  const allowedRoots = [config.workspaceRoot, config.artifactRoot].map((p) => resolve(p));
  if (!allowedRoots.some((root) => isInside(candidate, root))) {
    throw new Error(`cwd must be inside workspaceRoot or artifactRoot: ${candidate}`);
  }
  return candidate;
}

function resolveInputPath(value) {
  if (!value || typeof value !== 'string') throw new Error('path is required');
  return isAbsolute(value) ? resolve(value) : resolve(config.workspaceRoot, value);
}

function resolveAllowedHostPath(value) {
  const candidate = resolveInputPath(value);
  const allowedRoots = [config.workspaceRoot, config.artifactRoot].map((p) => resolve(p));
  if (!allowedRoots.some((root) => isInside(candidate, root))) {
    throw new Error(`path must be inside workspaceRoot or artifactRoot: ${candidate}`);
  }
  if (!existsSync(candidate)) throw new Error(`Path does not exist: ${candidate}`);
  return candidate;
}

function clampTimeout(value, fallback, max) {
  const n = Number.isFinite(Number(value)) ? Number(value) : fallback;
  return Math.max(1, Math.min(Math.floor(n), max));
}

function windowsPathToWsl(value) {
  const full = resolve(value);
  if (platform() !== 'win32') return full;
  const drive = full.match(/^([A-Za-z]):\\(.*)$/);
  if (!drive) return full.replaceAll('\\', '/');
  return `/mnt/${drive[1].toLowerCase()}/${drive[2].replaceAll('\\', '/')}`;
}

function spawnWithLogs(command, args, options) {
  return new Promise((resolvePromise) => {
    const stdoutStream = createWriteStream(options.stdoutPath);
    const stderrStream = createWriteStream(options.stderrPath);
    let stdoutPreview = '';
    let stderrPreview = '';
    const previewLimit = 16000;
    let timedOut = false;

    const child = spawn(command, args, {
      cwd: options.cwd,
      windowsHide: true,
      env: scrubHostEnv(process.env)
    });

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
      setTimeout(() => child.kill('SIGKILL'), 5000).unref();
    }, options.timeoutSeconds * 1000);

    child.stdout.on('data', (chunk) => {
      stdoutStream.write(chunk);
      if (stdoutPreview.length < previewLimit) stdoutPreview += chunk.toString('utf8').slice(0, previewLimit - stdoutPreview.length);
    });
    child.stderr.on('data', (chunk) => {
      stderrStream.write(chunk);
      if (stderrPreview.length < previewLimit) stderrPreview += chunk.toString('utf8').slice(0, previewLimit - stderrPreview.length);
    });
    child.on('error', (err) => {
      stderrStream.write(String(err.stack || err.message || err));
    });
    child.on('close', (exitCode, signal) => {
      clearTimeout(timer);
      stdoutStream.end();
      stderrStream.end();
      resolvePromise({ exitCode, signal, timedOut, stdoutPreview, stderrPreview });
    });
  });
}

function runPowerShellJson(script, timeoutSeconds) {
  if (platform() !== 'win32') {
    throw new Error('Native PowerShell tools require a Windows host.');
  }
  const res = spawnSync(config.windows.powershell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script], {
    cwd: config.workspaceRoot,
    encoding: 'utf8',
    timeout: timeoutSeconds * 1000,
    windowsHide: true,
    env: scrubHostEnv(process.env),
    maxBuffer: 16 * 1024 * 1024
  });
  if (res.error) {
    throw new Error(`PowerShell failed: ${res.error.message}`);
  }
  if (res.status !== 0) {
    throw new Error(`PowerShell exited ${res.status}: ${(res.stderr || res.stdout || '').trim()}`);
  }
  const stdout = String(res.stdout || '').trim();
  if (!stdout) return null;
  try {
    return JSON.parse(stdout);
  } catch (err) {
    throw new Error(`PowerShell did not return JSON: ${err.message}; stdout=${stdout.slice(0, 2000)}`);
  }
}

function psString(value) {
  return `'${String(value).replaceAll("'", "''")}'`;
}

function assertSafeEventValue(value, name) {
  const text = String(value || '');
  if (!text || text.length > 240 || !/^[A-Za-z0-9 ._:/\\-]+$/.test(text)) {
    throw new Error(`${name} contains unsupported characters`);
  }
}

function makeRunPaths(finding, prefix) {
  const runId = makeRunId(prefix);
  const startedAt = new Date().toISOString();
  const runDir = finding
    ? join(finding.path, 'triage', 'runs', runId)
    : join(config.artifactRoot, 'windows-runs', runId);
  return {
    runId,
    runDir,
    startedAt,
    stdoutPath: join(runDir, 'stdout.txt'),
    stderrPath: join(runDir, 'stderr.txt'),
    runPath: join(runDir, 'run.json')
  };
}

function scrubHostEnv(env) {
  const out = { ...env };
  for (const key of [
    'DISPLAY',
    'WAYLAND_DISPLAY',
    'PULSE_SERVER',
    'WSL2_GUI_APPS_ENABLED',
    'WSLG_RUNTIME_DIR',
    'XDG_RUNTIME_DIR',
    'SSH_AUTH_SOCK'
  ]) {
    delete out[key];
  }
  return out;
}

function walkFiles(root, maxFiles) {
  const out = [];
  const stack = [root];
  while (stack.length) {
    const cur = stack.pop();
    for (const entry of readdirSync(cur, { withFileTypes: true })) {
      const full = join(cur, entry.name);
      if (entry.isDirectory()) {
        stack.push(full);
      } else if (entry.isFile()) {
        out.push(full);
        if (out.length > maxFiles) throw new Error(`Too many files for manifest; maxFiles=${maxFiles}`);
      }
    }
  }
  return out.sort();
}

function sha256File(file) {
  return new Promise((resolvePromise, reject) => {
    const hash = createHash('sha256');
    const stream = createReadStream(file);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('error', reject);
    stream.on('end', () => resolvePromise(hash.digest('hex')));
  });
}

function sha256String(value) {
  return createHash('sha256').update(value).digest('hex');
}

function assertInside(candidate, root, message) {
  if (!isInside(candidate, root)) throw new Error(`${message}: ${candidate}`);
}

function isInside(candidate, root) {
  const rel = relative(resolve(root), resolve(candidate));
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

function makeRunId(prefix) {
  return `${prefix}-${new Date().toISOString().replace(/[:.]/g, '-')}-${process.pid}`;
}

function safeName(value) {
  return String(value || 'unnamed').replace(/[^A-Za-z0-9_.-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 120) || 'unnamed';
}

function stem(value) {
  const base = String(value).split(/[\\/]/).pop() || 'artifact';
  return base.replace(/\.[^.]+$/, '') || base;
}
