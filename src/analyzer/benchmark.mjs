/**
 * Detection benchmark: scans a labelled corpus (folders of known-malicious and
 * known-clean files) and measures how well the verdicts separate them.
 *
 * Every file is analysed with the normal static pipeline (scanFile), so nothing
 * is ever executed. Malware corpora should still be handled inside an isolated
 * virtual machine: antivirus software may quarantine samples while they are read,
 * which is reported as an "unreadable" sample instead of aborting the run.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { scanFile, TOOL } from './index.mjs';
import { LEVELS } from './scoring.mjs';
import { formatBytes } from './config.mjs';

export const BENCH_SCHEMA = 'reap-shield/benchmark@1';
export const LABELS = ['malicious', 'clean'];
export const DEFAULT_THRESHOLD = 'Medium';
const MAX_DEPTH = 12;

/** Normalises "medium" / "Medium" to a verdict level name, or throws. */
export function parseLevel(value) {
  const level = LEVELS.find((l) => l.toLowerCase() === String(value ?? '').toLowerCase());
  if (!level) throw new Error(`Unknown verdict level "${value}" (expected ${LEVELS.join(', ').toLowerCase()})`);
  return level;
}

/** A sample is flagged when its verdict level is at or above the threshold level. */
export const isFlagged = (level, threshold) => LEVELS.indexOf(level) >= LEVELS.indexOf(threshold);

/** Small deterministic PRNG (mulberry32) so sampled subsets are reproducible. */
function prng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

async function walk(dir, out, depth = 0) {
  let entries;
  try {
    entries = await fsp.readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isSymbolicLink()) continue;
    if (e.isDirectory()) {
      if (depth < MAX_DEPTH) await walk(full, out, depth + 1);
    } else if (e.isFile()) out.push(full);
  }
}

async function sha256File(file) {
  const hash = crypto.createHash('sha256');
  await new Promise((resolve, reject) => {
    fs.createReadStream(file).on('data', (d) => hash.update(d)).on('end', resolve).on('error', reject);
  });
  return hash.digest('hex');
}

/**
 * Collects the corpus. Each source entry is a file or a folder (walked recursively)
 * with a label. Empty files, files over maxBytes, files whose extension is not in
 * `extensions` (when given) and exact duplicates (same SHA-256, even across labels)
 * are skipped and counted. With `limit`, a seeded shuffle picks at most that many
 * samples per label before any file is hashed, so huge folders stay fast.
 *
 * @param {{malicious?: string[], clean?: string[], limit?: number, seed?: number, maxBytes?: number, extensions?: string[]}} opts
 */
export async function collectCorpus({ malicious = [], clean = [], limit, seed = 1, maxBytes = Infinity, extensions } = {}) {
  const skipped = { empty: 0, tooLarge: 0, extension: 0, duplicate: 0, conflict: 0, unreadable: 0 };
  const exts = extensions?.length ? new Set(extensions.map((e) => `.${String(e).replace(/^\./, '').toLowerCase()}`)) : null;
  const seen = new Map();
  const byLabel = { malicious: [], clean: [] };
  const rand = prng(seed);
  for (const [label, roots] of [['malicious', malicious], ['clean', clean]]) {
    const candidates = [];
    for (const root of roots) {
      const abs = path.resolve(root);
      const stat = await fsp.stat(abs).catch(() => null);
      if (!stat) throw new Error(`Corpus path not found: ${abs}`);
      const files = [];
      if (stat.isDirectory()) await walk(abs, files);
      else files.push(abs);
      for (const file of files.sort()) {
        if (exts && !exts.has(path.extname(file).toLowerCase())) {
          skipped.extension += 1;
          continue;
        }
        const st = await fsp.stat(file).catch(() => null);
        if (!st) { skipped.unreadable += 1; continue; }
        if (st.size === 0) { skipped.empty += 1; continue; }
        if (st.size > maxBytes) { skipped.tooLarge += 1; continue; }
        candidates.push({ path: file, root: abs, label, size: st.size });
      }
    }
    if (limit && limit > 0) {
      for (let i = candidates.length - 1; i > 0; i -= 1) {
        const j = Math.floor(rand() * (i + 1));
        [candidates[i], candidates[j]] = [candidates[j], candidates[i]];
      }
    }
    for (const sample of candidates) {
      if (limit && byLabel[label].length >= limit) break;
      try {
        sample.sha256 = await sha256File(sample.path);
      } catch {
        skipped.unreadable += 1;
        continue;
      }
      const prev = seen.get(sample.sha256);
      if (prev) {
        // The same bytes under both labels is a labelling error: keep the first, report it.
        if (prev.label !== label) skipped.conflict += 1;
        else skipped.duplicate += 1;
        continue;
      }
      seen.set(sample.sha256, sample);
      byLabel[label].push(sample);
    }
    byLabel[label].sort((a, b) => a.path.localeCompare(b.path));
  }
  return { samples: [...byLabel.malicious, ...byLabel.clean], skipped };
}

const pct = (n, d) => (d ? n / d : null);
const round = (v, digits = 4) => (v === null ? null : Number(v.toFixed(digits)));

/** Confusion matrix and the usual rates for one threshold. */
export function confusion(results, threshold) {
  const m = { threshold, tp: 0, fn: 0, fp: 0, tn: 0 };
  for (const r of results) {
    if (r.error) continue;
    const flagged = isFlagged(r.level, threshold);
    if (r.label === 'malicious') flagged ? (m.tp += 1) : (m.fn += 1);
    else flagged ? (m.fp += 1) : (m.tn += 1);
  }
  const precision = pct(m.tp, m.tp + m.fp);
  const recall = pct(m.tp, m.tp + m.fn);
  return {
    ...m,
    detectionRate: round(recall),
    falsePositiveRate: round(pct(m.fp, m.fp + m.tn)),
    precision: round(precision),
    f1: round(precision !== null && recall !== null && precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : null),
    accuracy: round(pct(m.tp + m.tn, m.tp + m.tn + m.fp + m.fn)),
  };
}

function percentile(sorted, p) {
  if (!sorted.length) return 0;
  return sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];
}

/** Aggregates per-sample results into the benchmark metrics. */
export function computeMetrics(results, threshold = DEFAULT_THRESHOLD) {
  const ok = results.filter((r) => !r.error);
  const thresholds = LEVELS.slice(1).map((level) => confusion(results, level));

  const byKind = {};
  for (const r of ok) {
    const k = (byKind[r.kind] ??= { kind: r.kind, malicious: 0, detected: 0, clean: 0, falsePositives: 0 });
    if (r.label === 'malicious') {
      k.malicious += 1;
      if (isFlagged(r.level, threshold)) k.detected += 1;
    } else {
      k.clean += 1;
      if (isFlagged(r.level, threshold)) k.falsePositives += 1;
    }
  }

  // Which rules fire on which side: rules that fire mostly on clean files drive false
  // positives; rules that fire only on malicious files are the strongest signals.
  const rules = new Map();
  for (const r of ok) {
    for (const id of r.rules) {
      const e = rules.get(id) ?? { ruleId: id, malicious: 0, clean: 0 };
      e[r.label] += 1;
      rules.set(id, e);
    }
  }
  const counts = { malicious: ok.filter((r) => r.label === 'malicious').length, clean: ok.filter((r) => r.label === 'clean').length };
  const ruleList = [...rules.values()].map((e) => ({
    ...e,
    maliciousRate: round(pct(e.malicious, counts.malicious)),
    cleanRate: round(pct(e.clean, counts.clean)),
  }));

  const levels = Object.fromEntries(
    LABELS.map((label) => [label, Object.fromEntries(LEVELS.map((l) => [l, ok.filter((r) => r.label === label && r.level === l).length]))]),
  );
  const times = ok.map((r) => r.ms).sort((a, b) => a - b);

  return {
    threshold,
    samples: { ...counts, errors: results.length - ok.length },
    primary: confusion(results, threshold),
    thresholds,
    levels,
    byKind: Object.values(byKind).sort((a, b) => b.malicious + b.clean - (a.malicious + a.clean)),
    falsePositiveDrivers: ruleList.filter((e) => e.clean > 0).sort((a, b) => b.clean - a.clean || a.malicious - b.malicious).slice(0, 25),
    strongestSignals: ruleList
      .filter((e) => e.malicious > 0 && e.clean === 0)
      .sort((a, b) => b.malicious - a.malicious)
      .slice(0, 25),
    timing: {
      totalMs: times.reduce((a, b) => a + b, 0),
      p50Ms: percentile(times, 50),
      p95Ms: percentile(times, 95),
      maxMs: times.at(-1) ?? 0,
    },
  };
}

/** Reduces a full scan report to what the benchmark keeps per sample. */
function summariseReport(sample, report, ms) {
  const rules = [...new Set(report.findings.filter((f) => f.severity !== 'info').map((f) => f.ruleId ?? f.id))];
  const top = report.findings
    .filter((f) => f.severity === 'critical' || f.severity === 'high')
    .slice(0, 5)
    .map((f) => `${f.severity}: ${f.title}`);
  return {
    path: sample.path,
    label: sample.label,
    sha256: sample.sha256,
    size: sample.size,
    kind: report.target.kind ?? 'unknown',
    score: report.verdict.score,
    level: report.verdict.level,
    rules,
    top,
    yaraMatches: report.yara?.matches ?? 0,
    ms,
  };
}

/**
 * Runs the benchmark.
 * @param {{
 *   malicious?: string[], clean?: string[], threshold?: string, limit?: number, seed?: number,
 *   jobs?: number, maxBytes?: number, scanOptions?: object, scan?: Function,
 *   onSample?: (done: number, total: number, result: object) => void,
 * }} opts  `scan` replaces scanFile (tests).
 */
export async function runBenchmark(opts = {}) {
  const threshold = parseLevel(opts.threshold ?? DEFAULT_THRESHOLD);
  const startedAt = new Date();
  const corpus = await collectCorpus(opts);
  if (!corpus.samples.length) throw new Error('The corpus is empty: no readable, non-empty files were found.');
  const scan = opts.scan ?? scanFile;
  const jobs = Math.max(1, Math.min(8, Number(opts.jobs) || 1));

  const results = new Array(corpus.samples.length);
  let next = 0;
  let done = 0;
  const worker = async () => {
    while (next < corpus.samples.length) {
      const index = next++;
      const sample = corpus.samples[index];
      const t0 = performance.now();
      let result;
      try {
        const report = await scan(sample.path, { ...opts.scanOptions, ...(Number.isFinite(opts.maxBytes) ? { maxInputBytes: opts.maxBytes } : {}) });
        result = summariseReport(sample, report, Math.round(performance.now() - t0));
      } catch (err) {
        result = { path: sample.path, label: sample.label, sha256: sample.sha256, size: sample.size, error: err?.message ?? String(err) };
      }
      results[index] = result;
      done += 1;
      opts.onSample?.(done, corpus.samples.length, result);
    }
  };
  await Promise.all(Array.from({ length: Math.min(jobs, corpus.samples.length) }, worker));

  const finishedAt = new Date();
  return {
    schema: BENCH_SCHEMA,
    tool: TOOL,
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    durationMs: finishedAt - startedAt,
    config: {
      threshold,
      limit: opts.limit ?? null,
      extensions: opts.extensions ?? null,
      seed: opts.seed ?? 1,
      jobs,
      sources: { malicious: (opts.malicious ?? []).map((p) => path.resolve(p)), clean: (opts.clean ?? []).map((p) => path.resolve(p)) },
      scanOptions: { useRea: opts.scanOptions?.useRea ?? true, verifySignature: opts.scanOptions?.verifySignature ?? true, useYara: opts.scanOptions?.useYara ?? true },
    },
    skipped: corpus.skipped,
    metrics: computeMetrics(results, threshold),
    missed: results.filter((r) => !r.error && r.label === 'malicious' && !isFlagged(r.level, threshold)),
    falsePositives: results.filter((r) => !r.error && r.label === 'clean' && isFlagged(r.level, threshold)),
    errors: results.filter((r) => r.error),
    results,
  };
}

const fmtPct = (v) => (v === null || v === undefined ? 'n/a' : `${(v * 100).toFixed(1)}%`);
const cell = (s) => String(s).replace(/\|/g, '\\|');

/** Renders the benchmark result as Markdown. */
export function benchmarkToMarkdown(b) {
  const m = b.metrics;
  const p = m.primary;
  const lines = [];
  lines.push(`# ${b.tool.name} detection benchmark`, '');
  lines.push(`${b.tool.name} ${b.tool.version} · ${b.finishedAt} · ${(b.durationMs / 1000).toFixed(1)} s`, '');
  lines.push(`A sample counts as **detected** when its verdict is **${b.config.threshold}** or higher.`, '');
  lines.push('## Summary', '');
  lines.push('| Metric | Value |', '|---|---|');
  lines.push(`| Malicious samples | ${m.samples.malicious} |`);
  lines.push(`| Clean samples | ${m.samples.clean} |`);
  lines.push(`| Errors | ${m.samples.errors} |`);
  lines.push(`| Detection rate (recall) | **${fmtPct(p.detectionRate)}** (${p.tp}/${p.tp + p.fn}) |`);
  lines.push(`| False positive rate | **${fmtPct(p.falsePositiveRate)}** (${p.fp}/${p.fp + p.tn}) |`);
  lines.push(`| Precision | ${fmtPct(p.precision)} |`);
  lines.push(`| F1 score | ${p.f1 ?? 'n/a'} |`);
  lines.push(`| Scan time p50 / p95 / max | ${m.timing.p50Ms} / ${m.timing.p95Ms} / ${m.timing.maxMs} ms |`);
  const sk = b.skipped;
  lines.push(`| Skipped | ${sk.duplicate} duplicate, ${sk.conflict} labelled both ways, ${sk.empty} empty, ${sk.tooLarge} too large, ${sk.extension} other extension, ${sk.unreadable} unreadable |`, '');

  lines.push('## By threshold', '');
  lines.push('| Threshold | Detected | Detection rate | False positives | FP rate | Precision | F1 |', '|---|---|---|---|---|---|---|');
  for (const t of m.thresholds) {
    lines.push(`| ${t.threshold}+ | ${t.tp} | ${fmtPct(t.detectionRate)} | ${t.fp} | ${fmtPct(t.falsePositiveRate)} | ${fmtPct(t.precision)} | ${t.f1 ?? 'n/a'} |`);
  }
  lines.push('');

  lines.push('## Verdict distribution', '');
  lines.push(`| Label | ${LEVELS.join(' | ')} |`, `|---|${LEVELS.map(() => '---').join('|')}|`);
  for (const label of LABELS) lines.push(`| ${label} | ${LEVELS.map((l) => m.levels[label][l]).join(' | ')} |`);
  lines.push('');

  if (m.byKind.length) {
    lines.push('## By file type', '');
    lines.push('| Type | Malicious | Detected | Clean | False positives |', '|---|---|---|---|---|');
    for (const k of m.byKind) lines.push(`| ${k.kind} | ${k.malicious} | ${k.detected} (${fmtPct(pct(k.detected, k.malicious))}) | ${k.clean} | ${k.falsePositives} (${fmtPct(pct(k.falsePositives, k.clean))}) |`);
    lines.push('');
  }

  if (m.falsePositiveDrivers.length) {
    lines.push('## Rules that fire on clean files', '');
    lines.push('Rules near the top are the main false-positive sources (findings of severity low or higher).', '');
    lines.push('| Rule | Clean hits | Malicious hits |', '|---|---|---|');
    for (const r of m.falsePositiveDrivers) lines.push(`| \`${r.ruleId}\` | ${r.clean} (${fmtPct(r.cleanRate)}) | ${r.malicious} (${fmtPct(r.maliciousRate)}) |`);
    lines.push('');
  }
  if (m.strongestSignals.length) {
    lines.push('## Rules seen only on malicious files', '');
    lines.push('| Rule | Malicious hits |', '|---|---|');
    for (const r of m.strongestSignals) lines.push(`| \`${r.ruleId}\` | ${r.malicious} (${fmtPct(r.maliciousRate)}) |`);
    lines.push('');
  }

  const listing = (title, rows, note) => {
    if (!rows.length) return;
    lines.push(`## ${title} (${rows.length})`, '');
    if (note) lines.push(note, '');
    lines.push('| File | Type | Size | Score | Verdict | SHA-256 |', '|---|---|---|---|---|---|');
    for (const r of rows.slice(0, 200)) {
      lines.push(`| ${cell(path.basename(r.path))} | ${r.kind} | ${formatBytes(r.size)} | ${r.score} | ${r.level} | \`${r.sha256.slice(0, 16)}…\` |`);
    }
    if (rows.length > 200) lines.push('', `… and ${rows.length - 200} more (see the JSON file).`);
    lines.push('');
  };
  listing('Missed malicious samples', b.missed, 'These are the most useful samples for improving detection.');
  listing('False positives', b.falsePositives);
  if (b.errors.length) {
    lines.push(`## Errors (${b.errors.length})`, '');
    for (const e of b.errors.slice(0, 100)) lines.push(`- ${cell(path.basename(e.path))}: ${cell(e.error)}`);
    lines.push('');
  }
  lines.push('---', '', 'Static analysis only: nothing was executed. Results depend on the corpus; a small or biased corpus gives misleading rates.');
  return `${lines.join('\n')}\n`;
}
