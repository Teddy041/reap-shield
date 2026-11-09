/**
 * YARA-X signature matching.
 *
 * Rules are compiled with the official YARA-X WebAssembly build
 * (@virustotal/yara-x), so matching works the same on Windows, macOS and Linux
 * and needs no native binaries. Matching only reads bytes; nothing is executed.
 *
 * No rules are shipped in this repository (third-party rule licenses vary).
 * Rules come from two places in the per-user data folder:
 *   <data>/yara/forge/   the YARA Forge package, downloaded on request
 *                        ("Download rules" in the app, `reap-shield rules update`)
 *   <data>/yara/custom/  the user's own *.yar / *.yara files
 * plus any extra files or folders passed with --yara-rules.
 */
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import yauzl from 'yauzl';
import { initSync, Compiler } from '@virustotal/yara-x';
import { LIMITS, SEVERITIES } from './config.mjs';

const require = createRequire(import.meta.url);
const YARA_PKG_DIR = path.dirname(require.resolve('@virustotal/yara-x/package.json'));

export const YARA_ENGINE = Object.freeze({
  name: 'YARA-X',
  version: require('@virustotal/yara-x/package.json').version,
});

export const FORGE_PACKAGES = Object.freeze(['core', 'extended', 'full']);
export const FORGE_DEFAULT_PACKAGE = 'core';
export const FORGE_HOME = 'https://github.com/YARAHQ/yara-forge';
export const FORGE_NOTE =
  'YARA Forge collects rules from many public repositories. Each rule keeps its own license ' +
  '(see the meta fields author, reference and license_url in the rule file); review them before ' +
  'redistributing the rules. "core" has the fewest false positives, "extended" and "full" add ' +
  'more rules at the cost of more noise.';

const RULE_FILE_RE = /\.(?:yar|yara)$/i;
const MAX_RULE_FILE_BYTES = 64 * 1024 * 1024;
const MAX_RULE_FILES = 500;
const MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024;

/** Per-user data folder shared by the desktop app and the CLI. Override with REAP_DATA_DIR. */
export function dataDir() {
  if (process.env.REAP_DATA_DIR) return path.resolve(process.env.REAP_DATA_DIR);
  if (process.platform === 'win32') {
    return path.join(process.env.APPDATA ?? path.join(os.homedir(), 'AppData', 'Roaming'), 'REAP-Shield');
  }
  if (process.platform === 'darwin') return path.join(os.homedir(), 'Library', 'Application Support', 'REAP-Shield');
  return path.join(process.env.XDG_CONFIG_HOME ?? path.join(os.homedir(), '.config'), 'REAP-Shield');
}

/** Rule folders. Override the root with REAP_YARA_DIR. */
export function yaraDirs() {
  const root = process.env.REAP_YARA_DIR ? path.resolve(process.env.REAP_YARA_DIR) : path.join(dataDir(), 'yara');
  return { root, forge: path.join(root, 'forge'), custom: path.join(root, 'custom') };
}

const CUSTOM_README = `REAP-Shield custom YARA rules
=============================

Put your own YARA rule files (*.yar or *.yara) in this folder or in sub-folders.
They are compiled with YARA-X and used by every scan, next to the YARA Forge
rules (if downloaded). Each file is compiled in its own namespace; a file that
fails to compile is reported in the scan and skipped, the others still load.

Optional meta fields understood by REAP-Shield:
  severity    = "info" | "low" | "medium" | "high" | "critical"
  score       = 0..100   (used when "severity" is missing; 75+ is high, 90+ critical)
  description = "Shown as the finding text"
  author / reference = shown as evidence

YARA-X documentation: https://virustotal.github.io/yara-x/
`;

/** Create the custom rules folder (with a short README) and return its path. */
export async function ensureCustomDir() {
  const { custom } = yaraDirs();
  await fsp.mkdir(custom, { recursive: true });
  const readme = path.join(custom, 'README.txt');
  if (!fs.existsSync(readme)) await fsp.writeFile(readme, CUSTOM_README, 'utf8');
  return custom;
}

let engineReady = false;
function ensureEngine() {
  if (engineReady) return;
  initSync({ module: fs.readFileSync(path.join(YARA_PKG_DIR, 'pkg', 'yara_x_js_bg.wasm')) });
  engineReady = true;
}

/** Count public (non-private) rules in YARA source text. */
export function countRules(text) {
  let n = 0;
  for (const m of text.matchAll(/^[ \t]*((?:(?:private|global)[ \t]+)*)rule[ \t]+[A-Za-z_]\w*/gm)) {
    if (!/private/.test(m[1])) n += 1;
  }
  return n;
}

async function walkRuleDir(dir, out, kind, depth = 0) {
  if (depth > 6 || out.length >= MAX_RULE_FILES) return;
  let entries;
  try {
    entries = await fsp.readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  entries.sort((a, b) => a.name.localeCompare(b.name));
  for (const e of entries) {
    if (out.length >= MAX_RULE_FILES) return;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) await walkRuleDir(p, out, kind, depth + 1);
    else if (e.isFile() && RULE_FILE_RE.test(e.name)) out.push({ path: p, kind });
  }
}

/**
 * Every rule file that a scan would load, in load order.
 * @param {{extraPaths?: string[]}} [opts]
 */
export async function listRuleSources({ extraPaths = [] } = {}) {
  const dirs = yaraDirs();
  const out = [];
  await walkRuleDir(dirs.forge, out, 'forge');
  await walkRuleDir(dirs.custom, out, 'custom');
  for (const extra of extraPaths) {
    const abs = path.resolve(extra);
    const st = await fsp.stat(abs).catch(() => null);
    if (!st) throw new Error(`YARA rules path not found: ${abs}`);
    if (st.isDirectory()) await walkRuleDir(abs, out, 'extra');
    else out.push({ path: abs, kind: 'extra' });
  }
  return out;
}

function firstLine(err) {
  const text = String(err?.message ?? err).trim();
  return text.split(/\r?\n/).slice(0, 6).join(' ').replace(/\s+/g, ' ').slice(0, 400);
}

/** Compiled rules are kept for the life of the process and reused while no rule file changes. */
let rulesCache = null;

async function cacheKey(files) {
  const parts = [];
  for (const f of files) {
    const st = await fsp.stat(f.path).catch(() => null);
    parts.push(`${f.kind}|${f.path}|${st?.size}|${st?.mtimeMs}`);
  }
  const forgeJson = await fsp.stat(path.join(yaraDirs().forge, 'forge.json')).catch(() => null);
  parts.push(`forge.json|${forgeJson?.mtimeMs}`);
  return parts.join('\n');
}

/**
 * Compile all rule files. A file that fails to compile is skipped and reported;
 * the others still load. The result is cached: the returned rules object is
 * owned by this module and must not be freed by the caller.
 * @param {{extraPaths?: string[]}} [opts]
 * @returns {Promise<{rules: any, sources: Array<object>, ruleCount: number, warnings: number, compileMs: number, cached: boolean}>}
 */
export async function loadRules(opts = {}) {
  const started = Date.now();
  const files = await listRuleSources(opts);
  if (files.length === 0) return { rules: null, sources: [], ruleCount: 0, warnings: 0, compileMs: 0, cached: false };
  const key = await cacheKey(files);
  if (rulesCache?.key === key) return { ...rulesCache.result, compileMs: 0, cached: true };
  const result = await compileRuleFiles(files, started);
  rulesCache?.result.rules?.free();
  rulesCache = result.rules ? { key, result } : null;
  return result;
}

async function compileRuleFiles(files, started) {
  const sources = [];
  ensureEngine();
  // The YARA Forge package was compiled once when it was installed; other files are
  // test-compiled on their own first, because a failed addSource() leaves the shared
  // compiler unusable and one broken file would otherwise disable every rule.
  const forge = await forgeInfo();
  const compiler = new Compiler();
  try {
    for (const [i, file] of files.entries()) {
      const entry = { name: path.basename(file.path), path: file.path, kind: file.kind, rules: 0, ok: false };
      sources.push(entry);
      try {
        const st = await fsp.stat(file.path);
        if (st.size > MAX_RULE_FILE_BYTES) throw new Error(`rule file is larger than ${MAX_RULE_FILE_BYTES / 1024 / 1024} MB`);
        const text = await fsp.readFile(file.path, 'utf8');
        if (!(file.kind === 'forge' && forge)) {
          const probe = new Compiler();
          try {
            probe.addSource(text);
            probe.build().free();
          } finally {
            probe.free();
          }
        }
        compiler.newNamespace(file.kind === 'forge' ? 'forge' : `${file.kind}_${i}`);
        compiler.addSource(text);
        entry.rules = countRules(text);
        entry.ok = true;
      } catch (err) {
        entry.error = firstLine(err);
      }
    }
    const ruleCount = sources.reduce((n, s) => n + (s.ok ? s.rules : 0), 0);
    if (!sources.some((s) => s.ok)) return { rules: null, sources, ruleCount: 0, warnings: 0, compileMs: Date.now() - started, cached: false };
    const warnings = compiler.warnings.length;
    const rules = compiler.build();
    return { rules, sources, ruleCount, warnings, compileMs: Date.now() - started, cached: false };
  } finally {
    compiler.free();
  }
}

/**
 * A reusable scanner with the per-file timeout and match caps applied.
 * Call free() when the scan is finished.
 */
export function createYaraScanner(rules) {
  const scanner = rules.scanner();
  scanner.setTimeoutMs(LIMITS.yaraTimeoutMs);
  scanner.setMaxMatchesPerPattern(LIMITS.yaraMaxMatchesPerPattern);
  return {
    /** @param {Buffer} buf */
    scan(buf) {
      const res = scanner.scan(new Uint8Array(buf.buffer, buf.byteOffset, buf.length));
      return (res?.matches ?? []).filter((m) => !m.isPrivate);
    },
    free() {
      scanner.free();
    },
  };
}

function metaMap(match) {
  const meta = {};
  for (const { identifier, value } of match.metadata ?? []) {
    if (!(identifier in meta)) meta[identifier] = value;
  }
  return meta;
}

/** Map rule metadata to a REAP-Shield severity. */
export function yaraSeverity(meta) {
  const word = String(meta.severity ?? '').toLowerCase();
  if (SEVERITIES.includes(word)) return word;
  const score = Number(meta.score);
  if (Number.isFinite(score)) {
    if (score >= 90) return 'critical';
    if (score >= 75) return 'high';
    if (score >= 60) return 'medium';
    if (score >= 40) return 'low';
    return 'info';
  }
  return 'medium';
}

function snippet(buf, offset, length) {
  if (!buf || offset >= buf.length) return '';
  const bytes = buf.subarray(offset, Math.min(buf.length, offset + Math.min(length, 48)));
  const printable = bytes.every((b) => (b >= 0x20 && b < 0x7f) || b === 0x09);
  if (printable) return JSON.stringify(bytes.toString('latin1'));
  const wide = bytes.length >= 4 && bytes.every((b, i) => (i % 2 === 1 ? b === 0 : b >= 0x20 && b < 0x7f));
  if (wide) return `${JSON.stringify(bytes.toString('utf16le'))} (UTF-16)`;
  return bytes.toString('hex').replace(/(..)/g, '$1 ').trim();
}

/**
 * Turn one YARA match into a REAP-Shield finding.
 * @param {any} match  YARA-X match object
 * @param {Buffer} buf  the scanned bytes (for evidence snippets)
 * @param {string} file report-relative file name
 */
export function yaraMatchToFinding(match, buf, file) {
  const meta = metaMap(match);
  const severity = yaraSeverity(meta);
  let description = typeof meta.description === 'string' && !/^No description has been set/i.test(meta.description) ? meta.description.trim() : '';
  if (!description) description = `The file matches the YARA rule ${match.identifier}.`;
  if (!/[.!?]$/.test(description)) description += '.';
  const origin = match.namespace === 'forge' ? 'YARA Forge' : 'custom rules';
  description += ` (YARA-X, ${origin}${meta.author ? `, author: ${meta.author}` : ''}.)`;

  const evidence = [];
  for (const pattern of match.patterns ?? []) {
    for (const m of pattern.matches ?? []) {
      if (evidence.length >= 6) break;
      evidence.push(`${pattern.identifier} @ 0x${m.offset.toString(16)}: ${snippet(buf, m.offset, m.length)}`);
    }
  }
  if (evidence.length === 0) evidence.push('Condition-only rule (file structure, hashes or module data); no string pattern to show.');
  if (typeof meta.reference === 'string' && /^https?:\/\//.test(meta.reference)) evidence.push(`Reference: ${meta.reference}`);

  return {
    ruleId: `yara.${match.identifier}`,
    category: 'yara',
    severity,
    title: `YARA: ${match.identifier}`,
    description,
    file,
    source: 'yara',
    evidence,
    yara: {
      rule: match.identifier,
      namespace: match.namespace,
      tags: match.tags ?? [],
      score: Number.isFinite(Number(meta.score)) ? Number(meta.score) : null,
      author: meta.author ?? null,
      reference: meta.reference ?? null,
      license: meta.license ?? meta.license_url ?? null,
    },
  };
}

// ------------------------------------------------------------- YARA Forge

/** Read "Creation Date", "YARA-Forge Version" and "Number of Rules" from the package header. */
export function parseForgeHeader(text) {
  const head = text.slice(0, 4096);
  return {
    created: /Creation Date:\s*(\S+)/.exec(head)?.[1] ?? null,
    forgeVersion: /YARA-Forge Version:\s*(\S+)/.exec(head)?.[1] ?? null,
    declaredRules: Number(/Number of Rules:\s*(\d+)/.exec(head)?.[1]) || null,
  };
}

function readYarFromZip(zipBuf) {
  return new Promise((resolve, reject) => {
    yauzl.fromBuffer(zipBuf, { lazyEntries: true }, (err, zip) => {
      if (err) return reject(new Error(`The downloaded file is not a valid ZIP archive: ${err.message}`));
      let found = false;
      zip.on('error', reject);
      zip.on('end', () => {
        if (!found) reject(new Error('The downloaded archive contains no .yar rule file.'));
      });
      zip.on('entry', (entry) => {
        if (found || !/\.yar$/i.test(entry.fileName) || entry.uncompressedSize > MAX_RULE_FILE_BYTES) return zip.readEntry();
        found = true;
        zip.openReadStream(entry, (e, stream) => {
          if (e) return reject(e);
          const chunks = [];
          let size = 0;
          stream.on('data', (c) => {
            size += c.length;
            if (size > MAX_RULE_FILE_BYTES) stream.destroy(new Error('Rule file in the archive is too large.'));
            else chunks.push(c);
          });
          stream.on('error', reject);
          stream.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
        });
      });
      zip.readEntry();
    });
  });
}

/** Information about the installed YARA Forge package, or null. */
export async function forgeInfo() {
  try {
    return JSON.parse(await fsp.readFile(path.join(yaraDirs().forge, 'forge.json'), 'utf8'));
  } catch {
    return null;
  }
}

/**
 * Download the latest YARA Forge release, check that it compiles with YARA-X and
 * install it (replacing any previously installed package).
 * Only rule text is downloaded; it is never executed.
 * @param {{pkg?: string, fetchImpl?: typeof fetch, onProgress?: (msg: string) => void}} [opts]
 */
export async function updateForgeRules({ pkg = FORGE_DEFAULT_PACKAGE, fetchImpl = globalThis.fetch, onProgress } = {}) {
  if (!FORGE_PACKAGES.includes(pkg)) throw new Error(`Unknown YARA Forge package "${pkg}". Use one of: ${FORGE_PACKAGES.join(', ')}.`);
  const url = `${FORGE_HOME}/releases/latest/download/yara-forge-rules-${pkg}.zip`;
  onProgress?.(`Downloading YARA Forge "${pkg}" rules`);
  const res = await fetchImpl(url, { redirect: 'follow', headers: { 'User-Agent': `REAP-Shield YARA updater` } });
  if (!res.ok) throw new Error(`Download failed: HTTP ${res.status} for ${url}`);
  const declared = Number(res.headers.get('content-length'));
  if (declared > MAX_DOWNLOAD_BYTES) throw new Error('The rule package is unexpectedly large; download aborted.');
  const zipBuf = Buffer.from(await res.arrayBuffer());
  if (zipBuf.length > MAX_DOWNLOAD_BYTES) throw new Error('The rule package is unexpectedly large; download aborted.');

  onProgress?.('Unpacking and compiling the rules with YARA-X');
  const text = await readYarFromZip(zipBuf);
  ensureEngine();
  const compiler = new Compiler();
  try {
    compiler.addSource(text);
    compiler.build().free();
  } catch (err) {
    throw new Error(`The downloaded rules do not compile with YARA-X ${YARA_ENGINE.version}: ${firstLine(err)}`);
  } finally {
    compiler.free();
  }

  const { forge } = yaraDirs();
  await fsp.mkdir(forge, { recursive: true });
  for (const name of await fsp.readdir(forge)) {
    if (RULE_FILE_RE.test(name)) await fsp.rm(path.join(forge, name), { force: true });
  }
  const target = path.join(forge, `yara-forge-rules-${pkg}.yar`);
  await fsp.writeFile(`${target}.tmp`, text, 'utf8');
  await fsp.rename(`${target}.tmp`, target);
  const header = parseForgeHeader(text);
  const info = {
    package: pkg,
    created: header.created,
    forgeVersion: header.forgeVersion,
    rules: countRules(text),
    sha256: crypto.createHash('sha256').update(text).digest('hex'),
    downloadedAt: new Date().toISOString(),
    source: url,
  };
  await fsp.writeFile(path.join(forge, 'forge.json'), JSON.stringify(info, null, 2), 'utf8');
  await ensureCustomDir();
  return info;
}

/** Summary for the app and `reap-shield rules status` (does not compile anything). */
export async function yaraStatus() {
  const dirs = yaraDirs();
  const files = await listRuleSources();
  const custom = files.filter((f) => f.kind === 'custom');
  return {
    engine: YARA_ENGINE,
    dirs,
    forge: await forgeInfo(),
    customFiles: custom.length,
    customRules: custom.reduce((n, f) => {
      try {
        return n + countRules(fs.readFileSync(f.path, 'utf8'));
      } catch {
        return n;
      }
    }, 0),
    packages: FORGE_PACKAGES,
    note: FORGE_NOTE,
  };
}
