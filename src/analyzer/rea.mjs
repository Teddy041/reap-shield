/**
 * Bridge to the REA (Reverse Engineer Anything) CLI / MCP toolset.
 *
 * REA exposes the same workflows through its MCP server and its CLI; the CLI
 * is the most robust integration for a desktop app because every invocation
 * is an isolated process with a JSON result. Resolution order:
 *
 *   1. REA_BIN            explicit path to `rea`, `rea.cmd` or `scripts/rea.mjs`
 *   2. REA_HOME           a REA checkout (must be built: dist/ present)
 *   3. ../../rea          sibling checkout next to "rea projects/"
 *   4. `rea` on PATH      global npm install (rea-agents)
 *
 * When REA is unavailable every call resolves to { available: false } and the
 * built-in REAP-Shield analyzers still produce a full report.
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { LIMITS, PROJECT_ROOT } from './config.mjs';

let cachedLocation;

function exists(p) {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
}

function whichSync(cmd) {
  const exts = process.platform === 'win32' ? (process.env.PATHEXT ?? '.EXE;.CMD;.BAT').split(';') : [''];
  for (const dir of (process.env.PATH ?? '').split(path.delimiter)) {
    if (!dir) continue;
    for (const ext of exts) {
      const full = path.join(dir, cmd + ext.toLowerCase());
      if (exists(full)) return full;
      const fullUpper = path.join(dir, cmd + ext);
      if (exists(fullUpper)) return fullUpper;
    }
  }
  return null;
}

/** Turn a checkout directory into a launchable script path, if built. */
function fromCheckout(dir) {
  const script = path.join(dir, 'scripts', 'rea.mjs');
  if (exists(script) && fs.existsSync(path.join(dir, 'dist'))) return { kind: 'node-script', script, source: `checkout ${dir}` };
  if (exists(script)) return { kind: 'unbuilt', script, source: `checkout ${dir} (not built: run "npm ci && npm run build" there)` };
  return null;
}

/** Find a Node.js binary for running REA's script (Electron's own binary is not Node). */
function nodeBinary() {
  if (process.env.REAP_NODE && exists(process.env.REAP_NODE)) return { bin: process.env.REAP_NODE, env: {} };
  if (!process.versions.electron) return { bin: process.execPath, env: {} };
  const sys = whichSync('node');
  if (sys) return { bin: sys, env: {} };
  return { bin: process.execPath, env: { ELECTRON_RUN_AS_NODE: '1' } };
}

/**
 * Locate REA. Result is cached per process.
 * @returns {{kind:'node-script'|'binary'|'unbuilt'|'missing', script?:string, bin?:string, source:string}}
 */
export function locateRea({ refresh = false } = {}) {
  if (cachedLocation && !refresh) return cachedLocation;
  const candidates = [];
  if (process.env.REA_BIN) {
    const p = path.resolve(process.env.REA_BIN);
    if (/\.(m?js|cjs)$/i.test(p) && exists(p)) candidates.push({ kind: 'node-script', script: p, source: 'REA_BIN' });
    else if (exists(p)) candidates.push({ kind: 'binary', bin: p, source: 'REA_BIN' });
  }
  if (process.env.REA_HOME) candidates.push(fromCheckout(path.resolve(process.env.REA_HOME)));
  candidates.push(fromCheckout(path.resolve(PROJECT_ROOT, '..', '..', 'rea')));
  const onPath = whichSync('rea');
  if (onPath) {
    // npm creates rea.cmd shims on Windows; run the real script through node instead of a shell.
    const globalScript = path.join(path.dirname(onPath), 'node_modules', 'rea-agents', 'scripts', 'rea.mjs');
    if (exists(globalScript)) candidates.push({ kind: 'node-script', script: globalScript, source: `PATH (${onPath})` });
    else if (!/\.(cmd|bat)$/i.test(onPath)) candidates.push({ kind: 'binary', bin: onPath, source: `PATH (${onPath})` });
  }
  const usable = candidates.find((c) => c && (c.kind === 'node-script' || c.kind === 'binary'));
  cachedLocation = usable ?? candidates.find((c) => c?.kind === 'unbuilt') ?? { kind: 'missing', source: 'REA not found (set REA_BIN or REA_HOME, or "npm i -g rea-agents")' };
  return cachedLocation;
}

/**
 * Run one REA CLI command. Never throws.
 * @param {string[]} args
 * @param {{timeoutMs?: number, stdoutFile?: string, cwd?: string}} [opts]
 * @returns {Promise<{available:boolean, ok:boolean, command:string, json?:any, error?:string, durationMs:number, stdoutFile?:string}>}
 */
export function runRea(args, opts = {}) {
  const loc = locateRea();
  const command = `rea ${args.join(' ')}`;
  const started = Date.now();
  if (loc.kind !== 'node-script' && loc.kind !== 'binary') {
    return Promise.resolve({ available: false, ok: false, command, error: loc.source, durationMs: 0 });
  }
  let bin;
  let argv;
  let extraEnv = {};
  if (loc.kind === 'node-script') {
    const node = nodeBinary();
    bin = node.bin;
    extraEnv = node.env;
    argv = [loc.script, ...args];
  } else {
    bin = loc.bin;
    argv = args;
  }
  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';
    let settled = false;
    const done = (res) => {
      if (settled) return;
      settled = true;
      resolve({ available: true, command, durationMs: Date.now() - started, ...res });
    };
    let child;
    try {
      child = spawn(bin, argv, {
        cwd: opts.cwd ?? process.cwd(),
        env: { ...process.env, ...extraEnv, NO_COLOR: '1', REA_TELEMETRY: '0' },
        shell: false,
        windowsHide: true,
        stdio: ['ignore', opts.stdoutFile ? 'pipe' : 'pipe', 'pipe'],
      });
    } catch (err) {
      done({ ok: false, error: `Failed to start REA: ${err.message}` });
      return;
    }
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      done({ ok: false, error: `REA command timed out after ${opts.timeoutMs ?? LIMITS.reaTimeoutMs} ms` });
    }, opts.timeoutMs ?? LIMITS.reaTimeoutMs);

    const maxCapture = 64 * 1024 * 1024;
    if (opts.stdoutFile) {
      child.stdout.pipe(fs.createWriteStream(opts.stdoutFile));
    } else {
      child.stdout.on('data', (d) => {
        if (stdout.length < maxCapture) stdout += d;
      });
    }
    child.stderr.on('data', (d) => {
      if (stderr.length < 64 * 1024) stderr += d;
    });
    child.on('error', (err) => {
      clearTimeout(timer);
      done({ ok: false, error: `REA process error: ${err.message}` });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (opts.stdoutFile) {
        if (code === 0) {
          done({ ok: true, stdoutFile: opts.stdoutFile });
          return;
        }
        // Failures are small JSON error documents written to stdout.
        fsp
          .readFile(opts.stdoutFile, 'utf8')
          .then((text) => extractError(JSON.parse(text)))
          .catch(() => undefined)
          .then((msg) => done({ ok: false, stdoutFile: opts.stdoutFile, error: msg || lastNonProgressLine(stderr) || `exit code ${code}` }));
        return;
      }
      let json;
      try {
        json = stdout.trim() ? JSON.parse(stdout) : undefined;
      } catch {
        /* non-JSON output */
      }
      const ok = code === 0 && json !== undefined;
      done({ ok, json, error: ok ? undefined : extractError(json) || lastNonProgressLine(stderr) || `exit code ${code}` });
    });
  });
}

/** Last stderr line that is not a {"rea_progress": ...} record. */
function lastNonProgressLine(s) {
  const lines = String(s).split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('{"rea_progress"'));
  return lines.at(-1)?.slice(0, 400);
}

function extractError(json) {
  if (!json || typeof json !== 'object') return undefined;
  // REA error contract: { code, category, message, retryable, remediation, details: { reason } }
  if (typeof json.code === 'string' && typeof json.message === 'string') {
    const reason = typeof json.details?.reason === 'string' ? ` Reason: ${json.details.reason.slice(0, 300)}` : '';
    return `${json.code}: ${json.message}${reason}`;
  }
  const e = json.error ?? json.result?.error ?? json.diagnostic;
  if (!e) return undefined;
  return typeof e === 'string' ? e : e.message ?? JSON.stringify(e).slice(0, 400);
}

/** Depth-first search for the first value stored under `key`. */
export function findKey(obj, key, maxDepth = 8) {
  const stack = [{ v: obj, d: 0 }];
  const seen = new Set();
  while (stack.length) {
    const { v, d } = stack.pop();
    if (!v || typeof v !== 'object' || seen.has(v) || d > maxDepth) continue;
    seen.add(v);
    if (Object.prototype.hasOwnProperty.call(v, key)) return v[key];
    for (const child of Object.values(v)) stack.push({ v: child, d: d + 1 });
  }
  return undefined;
}

/**
 * Normalise REA `inspect-pe-imports` Evidence into [{dll, functions: string[]}].
 * Shape: normalized_result.imports[] / delay_imports[] = { name, functions: [{ name, ordinal }] }.
 * Delay-load imports are included: malware uses them to keep APIs out of the main table.
 */
export function normaliseReaImports(json) {
  const result = json?.normalized_result ?? json;
  const tables = [findKey(result, 'imports'), findKey(result, 'delay_imports')].filter(Array.isArray);
  if (tables.length === 0) return null;
  return tables.flat().map((imp) => ({
    dll: String(imp.dll ?? imp.name ?? imp.library ?? imp.module ?? 'unknown'),
    functions: (Array.isArray(imp.functions) ? imp.functions : Array.isArray(imp.symbols) ? imp.symbols : [])
      .map((f) => (typeof f === 'string' ? f : f?.name ?? (f?.ordinal != null ? `ord${f.ordinal}` : null)))
      .filter(Boolean),
  }));
}

/** Certificate subjects (CN / O) embedded in the Authenticode PKCS#7 blob, from `inspect-pe-certificates`. */
export function summariseReaCertificates(json) {
  const entries = json?.normalized_result?.entries;
  if (!Array.isArray(entries)) return null;
  const subjects = [];
  for (const entry of entries) {
    for (const cert of entry?.pkcs7?.certificates ?? []) {
      const attrs = cert?.subject?.attributes ?? [];
      const cn = attrs.find((a) => a.oid_name === 'commonName')?.value;
      const org = attrs.find((a) => a.oid_name === 'organizationName')?.value;
      const label = [cn, org && org !== cn ? `(${org})` : null].filter(Boolean).join(' ');
      if (label && !subjects.includes(label)) subjects.push(label);
    }
  }
  return { entries: entries.length, subjects };
}

/** Hardening rows from `inspect-binary-hardening` as { property: state }. */
export function summariseReaHardening(json) {
  const images = json?.normalized_result?.images;
  if (!Array.isArray(images)) return null;
  const out = {};
  for (const row of images[0]?.rows ?? []) if (row?.property) out[row.property] = row.state;
  return out;
}

/** High-entropy run count from `inspect-byte-entropy`. */
export function summariseReaEntropy(json) {
  const r = json?.normalized_result;
  if (!r || typeof r.file_entropy !== 'number') return null;
  return {
    fileEntropy: r.file_entropy,
    highRuns: Array.isArray(r.runs) ? r.runs.filter((x) => x.classification === 'high').length : 0,
  };
}

/** Compact a REA JSON document for the report (keeps it small and readable). */
export function compactEvidence(json, maxChars = 12000) {
  if (json === undefined) return null;
  const text = JSON.stringify(
    json,
    (_k, v) => {
      if (typeof v === 'string' && v.length > 300) return `${v.slice(0, 300)}…`;
      if (Array.isArray(v) && v.length > 40) return [...v.slice(0, 20), `… ${v.length - 20} more item(s)`];
      return v;
    },
    2,
  );
  return text.length > maxChars ? `${text.slice(0, maxChars)}\n… (truncated, ${text.length} chars total)` : text;
}

/**
 * Run the REA pipeline that fits a file kind.
 * @param {string} filePath Absolute path.
 * @param {string} kind     Detected kind.
 * @param {{deep?: boolean, provider?: string, workDir: string}} opts
 */
export async function reaInspect(filePath, kind, opts) {
  const abs = path.resolve(filePath);
  const runs = [];
  if (kind === 'pe') {
    runs.push(runRea(['inspect-pe-imports', abs, '--json']));
    runs.push(runRea(['inspect-pe-certificates', abs, '--json']));
    runs.push(runRea(['inspect-binary-hardening', abs, '--json']));
    runs.push(runRea(['inspect-byte-entropy', abs, '--json']));
    if (opts.provider) {
      runs.push(runRea(['analyze', abs, '--provider', opts.provider, '--json'], { timeoutMs: LIMITS.reaDeepTimeoutMs }));
    }
  } else if (kind === 'elf' || kind === 'macho') {
    runs.push(runRea(['inspect-binary-hardening', abs, '--json']));
    runs.push(runRea(['inspect-byte-entropy', abs, '--json']));
    if (opts.provider) runs.push(runRea(['analyze', abs, '--provider', opts.provider, '--json'], { timeoutMs: LIMITS.reaDeepTimeoutMs }));
  } else if (kind === 'asar' && opts.deep) {
    runs.push(reaJavaScriptApplication(abs, opts.workDir));
  }
  return Promise.all(runs);
}

/**
 * Full JavaScript application reconstruction. Evidence can be hundreds of MB,
 * so it is streamed to disk and only a summary view is loaded.
 */
async function reaJavaScriptApplication(abs, workDir) {
  const evidenceFile = path.join(workDir, `rea-js-evidence-${Date.now()}.json`);
  const run = await runRea(['analyze-javascript-application', abs, '--json'], {
    timeoutMs: LIMITS.reaDeepTimeoutMs,
    stdoutFile: evidenceFile,
  });
  if (!run.ok) return run;
  const requestFile = path.join(workDir, `rea-js-view-${Date.now()}.json`);
  await fsp.writeFile(requestFile, JSON.stringify({ source: { kind: 'evidence-file', path: evidenceFile }, view: { kind: 'summary' } }));
  const view = await runRea(['inspect-analysis-view', requestFile, '--json']);
  return { ...view, command: `${run.command} → inspect-analysis-view (summary)` };
}
