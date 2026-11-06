import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { scanFile } from '../src/analyzer/index.mjs';
import { Sandbox } from '../src/analyzer/sandbox.mjs';
import { parsePEBuffer } from '../src/analyzer/pe.mjs';
import { toHtml, toMarkdown } from '../src/analyzer/report.mjs';
import { writeFixtures, SUSPICIOUS_PY } from './fixtures.mjs';

let dir;
let fx;
let sandboxRoot;
const opts = () => ({ useRea: false, verifySignature: false, sandboxRoot });
const ids = (r) => new Set(r.findings.map((f) => f.ruleId));

before(async () => {
  dir = await fs.mkdtemp(path.join(os.tmpdir(), 'reap-test-'));
  sandboxRoot = path.join(dir, 'sandbox');
  fx = await writeFixtures(path.join(dir, 'fixtures'));
});
after(async () => {
  await fs.rm(dir, { recursive: true, force: true });
});

test('safeJoin blocks traversal, absolute and device paths', async () => {
  const sb = await new Sandbox({ root: sandboxRoot }).init();
  try {
    assert.equal(sb.safeJoin(sb.dir, '../../etc/passwd'), null);
    assert.equal(sb.safeJoin(sb.dir, 'a/../../b'), null);
    assert.equal(sb.safeJoin(sb.dir, ''), null);
    assert.equal(sb.safeJoin(sb.dir, 'x\0y'), null);
    assert.ok(sb.safeJoin(sb.dir, 'C:\\Windows\\evil.dll').startsWith(sb.dir));
    assert.ok(sb.safeJoin(sb.dir, '/abs/file').startsWith(sb.dir));
    assert.match(path.basename(sb.safeJoin(sb.dir, 'dir/CON.txt')), /^_CON/);
  } finally {
    await sb.cleanup();
  }
});

test('Electron ASAR: insecure webPreferences and IPC are flagged', async () => {
  const r = await scanFile(fx.asarPath, opts());
  const s = ids(r);
  assert.ok(r.verdict.electronApp);
  for (const id of [
    'electron.node-integration',
    'electron.context-isolation-off',
    'electron.web-security-off',
    'electron.expose-ipc-raw',
    'electron.ipc-passthrough',
    'electron.ipc-dangerous-handler',
    'electron.rce-config',
    'ioc.discord-webhook',
  ]) {
    assert.ok(s.has(id), `missing ${id}`);
  }
  assert.equal(r.verdict.level, 'Critical');
  // Secrets are redacted in the report.
  const hook = r.findings.find((f) => f.ruleId === 'ioc.discord-webhook');
  assert.match(hook.evidence[0], /redacted/);
});

test('Python dropper patterns are flagged', async () => {
  const r = await scanFile(fx.pyPath, opts());
  const s = ids(r);
  for (const id of ['py.decode-exec', 'py.subprocess', 'py.winreg-run', 'ps.hidden-bypass', 'ioc.run-key', 'ioc.ip-port']) {
    assert.ok(s.has(id), `missing ${id}`);
  }
  assert.ok(['High', 'Critical'].includes(r.verdict.level));
});

test('benign script scores Low', async () => {
  const r = await scanFile(fx.benignPath, opts());
  assert.equal(r.verdict.level, 'Low');
  assert.equal(r.findings.filter((f) => f.severity !== 'info').length, 0);
});

test('ZIP: nested archives are unpacked, zip-slip blocked, double extension flagged', async () => {
  const r = await scanFile(fx.zipPath, opts());
  const s = ids(r);
  assert.ok(s.has('archive.path-traversal'));
  assert.ok(s.has('evasion.double-extension'));
  assert.ok(s.has('electron.context-isolation-off'), 'asar inside zip analysed');
  assert.ok(r.files.some((f) => f.rel.endsWith('inner.zip!/scripts/installer.py')), 'nested zip unpacked');
  assert.ok(!fsSync.existsSync(path.join(sandboxRoot, '..', 'escape.txt')));
  assert.ok(!fsSync.existsSync(path.resolve(sandboxRoot, '..', '..', 'escape.txt')));
});

test('TAR.GZ is unpacked and analysed', async () => {
  const r = await scanFile(fx.tgzPath, opts());
  assert.ok(r.files.some((f) => f.rel.endsWith('pkg/installer.py')));
  assert.ok(ids(r).has('py.decode-exec'));
});

test('malformed archive produces a finding instead of crashing', async () => {
  const r = await scanFile(fx.garbagePath, opts());
  assert.ok(ids(r).has('archive.malformed'));
  assert.ok(r.errors.length > 0);
});

test('sandbox is removed after each scan', async () => {
  await scanFile(fx.zipPath, opts());
  const left = (await fs.readdir(sandboxRoot)).filter((n) => n.startsWith('scan-'));
  assert.deepEqual(left, []);
});

test('RAR archive (requires WinRAR rar.exe)', async (t) => {
  const rarExe = ['C:\\Program Files\\WinRAR\\Rar.exe', 'C:\\Program Files (x86)\\WinRAR\\Rar.exe'].find((p) => fsSync.existsSync(p));
  if (!rarExe) return t.skip('rar.exe not installed');
  const rarPath = path.join(dir, 'fixtures', 'bundle.rar');
  execFileSync(rarExe, ['a', '-ep1', '-idq', rarPath, path.join(fx.tarSrc, 'pkg', 'installer.py')]);
  const r = await scanFile(rarPath, opts());
  assert.ok(r.files.some((f) => f.rel.endsWith('installer.py')), JSON.stringify(r.errors));
  assert.ok(ids(r).has('py.decode-exec'));
});

test('PE parser handles a real Windows binary', async (t) => {
  const exe = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'notepad.exe');
  if (!fsSync.existsSync(exe)) return t.skip('notepad.exe not available');
  const pe = parsePEBuffer(await fs.readFile(exe));
  assert.ok(pe.valid);
  assert.ok(pe.imports.length > 3);
  assert.ok(pe.sections.some((s) => s.name === '.text'));
});

test('PE parser survives truncated / garbage input', () => {
  const buf = Buffer.alloc(512);
  buf.write('MZ', 0, 'latin1');
  buf.writeUInt32LE(0x40, 0x3c);
  buf.write('PE\0\0', 0x40, 'latin1');
  buf.writeUInt16LE(0x14c, 0x44);
  buf.writeUInt16LE(200, 0x46); // absurd section count
  const pe = parsePEBuffer(buf);
  assert.equal(typeof pe.valid, 'boolean');
  assert.ok(Array.isArray(pe.errors));
});

test('reports escape untrusted content', async () => {
  const p = path.join(dir, 'fixtures', 'xss.js');
  await fs.writeFile(p, `${SUSPICIOUS_PY}\neval("<img src=x onerror=alert(1)>")`);
  const r = await scanFile(p, opts());
  const html = toHtml(r);
  assert.ok(!html.includes('<img src=x'));
  assert.ok(toMarkdown(r).length > 100);
});
