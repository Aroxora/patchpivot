#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SERVER = join(ROOT, 'scripts', 'mcp', 'patchpivot-security-mcp.mjs');

const child = spawn(process.execPath, [SERVER], {
  cwd: ROOT,
  windowsHide: true,
  stdio: ['pipe', 'pipe', 'pipe']
});

const responses = [];
let stdout = '';
let stderr = '';

child.stdout.on('data', (chunk) => {
  stdout += chunk.toString('utf8');
  for (;;) {
    const idx = stdout.indexOf('\n');
    if (idx < 0) break;
    const line = stdout.slice(0, idx).trim();
    stdout = stdout.slice(idx + 1);
    if (line) responses.push(JSON.parse(line));
  }
  maybeFinish();
});

child.stderr.on('data', (chunk) => {
  stderr += chunk.toString('utf8');
});

const timeout = setTimeout(() => {
  child.kill('SIGKILL');
  fail('self-test timed out');
}, 30000);

send({
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: {
      name: 'patchpivot-self-test',
      version: '0.1.0'
    }
  }
});
send({ jsonrpc: '2.0', method: 'notifications/initialized' });
send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
send({
  jsonrpc: '2.0',
  id: 3,
  method: 'tools/call',
  params: {
    name: 'security.probe',
    arguments: {}
  }
});
send({
  jsonrpc: '2.0',
  id: 4,
  method: 'tools/call',
  params: {
    name: 'policy.check_command',
    arguments: {
      command: 'xterm',
      network: 'off'
    }
  }
});
send({
  jsonrpc: '2.0',
  id: 5,
  method: 'tools/call',
  params: {
    name: 'policy.check_command',
    arguments: {
      command: 'echo patchpivot-headless',
      network: 'off'
    }
  }
});
send({
  jsonrpc: '2.0',
  id: 6,
  method: 'tools/call',
  params: {
    name: 'policy.check_command',
    arguments: {
      command: 'Start-Process notepad.exe',
      network: 'off',
      backend: 'windows'
    }
  }
});
send({
  jsonrpc: '2.0',
  id: 7,
  method: 'tools/call',
  params: {
    name: 'windows.firewall_profiles',
    arguments: {}
  }
});
send({
  jsonrpc: '2.0',
  id: 8,
  method: 'tools/call',
  params: {
    name: 'windows.defender_status',
    arguments: {}
  }
});
send({
  jsonrpc: '2.0',
  id: 9,
  method: 'tools/call',
  params: {
    name: 'windows.eventlog_query',
    arguments: {
      logName: 'System',
      maxEvents: 1
    }
  }
});
send({
  jsonrpc: '2.0',
  id: 10,
  method: 'tools/call',
  params: {
    name: 'vigil.probe',
    arguments: {}
  }
});

child.on('close', () => {
  clearTimeout(timeout);
  if (!finished) finish();
});

let finished = false;

function maybeFinish() {
  if (finished) return;
  const ids = new Set(responses.map((r) => r.id));
  if ([1, 2, 3, 4, 5, 6, 7, 8, 9, 10].every((id) => ids.has(id))) {
    finished = true;
    child.kill('SIGTERM');
    finish();
  }
}

function finish() {
  const init = responses.find((r) => r.id === 1);
  const list = responses.find((r) => r.id === 2);
  const probe = responses.find((r) => r.id === 3);
  const blocked = responses.find((r) => r.id === 4);
  const allowed = responses.find((r) => r.id === 5);
  const windowsBlocked = responses.find((r) => r.id === 6);
  const firewall = responses.find((r) => r.id === 7);
  const defender = responses.find((r) => r.id === 8);
  const eventlog = responses.find((r) => r.id === 9);
  const vigilProbe = responses.find((r) => r.id === 10);

  if (!init?.result?.capabilities?.tools) fail('initialize did not return tools capability');
  if (!Array.isArray(list?.result?.tools)) fail('tools/list did not return a tools array');
  if (!list.result.tools.some((tool) => tool.name === 'kali.run')) fail('kali.run tool missing');
  if (!list.result.tools.some((tool) => tool.name === 'ghidra.analyze')) fail('ghidra.analyze tool missing');
  if (!list.result.tools.some((tool) => tool.name === 'windows.run')) fail('windows.run tool missing');
  if (!list.result.tools.some((tool) => tool.name === 'windows.defender_status')) fail('windows.defender_status tool missing');
  if (!list.result.tools.some((tool) => tool.name === 'vigil.probe')) fail('vigil.probe tool missing');
  if (!list.result.tools.some((tool) => tool.name === 'vigil.findings_bundle')) fail('vigil.findings_bundle tool missing');
  if (probe?.result?.isError) fail('security.probe returned an error');
  if (blocked?.result?.structuredContent?.allowed !== false) fail('GUI command was not blocked');
  if (allowed?.result?.structuredContent?.allowed !== true) fail('benign headless command was not allowed');
  if (windowsBlocked?.result?.structuredContent?.allowed !== false) fail('Windows GUI command was not blocked');
  if (firewall?.result?.isError) fail('windows.firewall_profiles returned an error');
  if (defender?.result?.isError) fail('windows.defender_status returned an error');
  if (eventlog?.result?.isError) fail('windows.eventlog_query returned an error');
  if (vigilProbe?.result?.isError) fail('vigil.probe returned an error');

  console.log(JSON.stringify({
    ok: true,
    tools: list.result.tools.map((tool) => tool.name),
    stderr: stderr.trim().split(/\r?\n/).filter(Boolean)
  }, null, 2));
}

function send(msg) {
  child.stdin.write(JSON.stringify(msg) + '\n');
}

function fail(message) {
  console.error(JSON.stringify({
    ok: false,
    message,
    responses,
    stdout,
    stderr
  }, null, 2));
  process.exit(1);
}
