/**
 * Tests for the detection benchmark. The corpus is generated at runtime from
 * harmless synthetic samples; the metric tests use a stubbed scanner.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { SUSPICIOUS_PY, BENIGN_JS, ELECTRON_MAIN } from './fixtures.mjs';
import { collectCorpus, runBenchmark, computeMetrics, confusion, benchmarkToMarkdown, parseLevel } from '../src/analyzer/benchmark.mjs';

let dir;
let bad;
let good;

before(async () => {
  dir = await fs.mkdtemp(path.join(os.tmpdir(), 'reap-bench-'));
  bad = path.join(dir, 'malicious');
  good = path.join(dir, 'clean');
  await fs.mkdir(path.join(bad, 'nested'), { recursive: true });
  await fs.mkdir(good, { recursive: true });
  await fs.writeFile(path.join(bad, 'stealer.py'), SUSPICIOUS_PY);
  await fs.writeFile(path.join(bad, 'nested', 'main.js'), ELECTRON_MAIN);
  await fs.writeFile(path.join(bad, 'nested', 'copy.py'), SUSPICIOUS_PY); // duplicate bytes
  await fs.writeFile(path.join(good, 'add.js'), BENIGN_JS);
  await fs.writeFile(path.join(good, 'notes.txt'), 'Shopping list: milk, bread, apples.\n');
  await fs.writeFile(path.join(good, 'empty.txt'), '');
});

after(async () => {
  await fs.rm(dir, { recursive: true, force: true });
});

test('corpus collection walks folders, deduplicates and skips empty files', async () => {
  const { samples, skipped } = await collectCorpus({ malicious: [bad], clean: [good] });
  assert.equal(samples.filter((s) => s.label === 'malicious').length, 2);
  assert.equal(samples.filter((s) => s.label === 'clean').length, 2);
  assert.equal(skipped.duplicate, 1);
  assert.equal(skipped.empty, 1);
  assert.match(samples[0].sha256, /^[0-9a-f]{64}$/);

  const limited = await collectCorpus({ malicious: [bad], clean: [good], limit: 1, seed: 7 });
  const again = await collectCorpus({ malicious: [bad], clean: [good], limit: 1, seed: 7 });
  assert.equal(limited.samples.length, 2, 'one sample per label');
  assert.deepEqual(limited.samples.map((s) => s.path), again.samples.map((s) => s.path), 'the seeded subset is reproducible');

  await assert.rejects(collectCorpus({ clean: [path.join(dir, 'missing')] }), /Corpus path not found/);
});

test('the same file under both labels is reported as a labelling conflict', async () => {
  const { samples, skipped } = await collectCorpus({ malicious: [path.join(bad, 'stealer.py')], clean: [path.join(bad, 'stealer.py')] });
  assert.equal(samples.length, 1);
  assert.equal(skipped.conflict, 1);
});

test('metrics: confusion matrix, rates, thresholds and rule drivers', () => {
  const r = (label, level, rules = [], kind = 'pe') => ({ label, level, score: 0, rules, kind, ms: 10 });
  const results = [
    r('malicious', 'Critical', ['net.webhook']),
    r('malicious', 'High', ['net.webhook', 'imports.inject']),
    r('malicious', 'Medium', ['imports.inject']),
    r('malicious', 'Low', [], 'script'),
    r('clean', 'Low', ['imports.inject']),
    r('clean', 'Medium', ['imports.inject']),
    r('clean', 'Low'),
    r('clean', 'Low'),
    { label: 'clean', error: 'unreadable' },
  ];
  const m = computeMetrics(results, 'Medium');
  assert.deepEqual([m.primary.tp, m.primary.fn, m.primary.fp, m.primary.tn], [3, 1, 1, 3]);
  assert.equal(m.primary.detectionRate, 0.75);
  assert.equal(m.primary.falsePositiveRate, 0.25);
  assert.equal(m.primary.precision, 0.75);
  assert.equal(m.samples.errors, 1);
  assert.equal(confusion(results, 'Critical').tp, 1);
  assert.equal(confusion(results, 'Critical').fp, 0);
  assert.deepEqual(m.thresholds.map((t) => t.threshold), ['Medium', 'High', 'Critical']);
  assert.equal(m.falsePositiveDrivers[0].ruleId, 'imports.inject');
  assert.equal(m.strongestSignals[0].ruleId, 'net.webhook');
  assert.equal(m.byKind.find((k) => k.kind === 'script').detected, 0);
  assert.equal(m.levels.malicious.Critical, 1);
  assert.throws(() => parseLevel('severe'), /Unknown verdict level/);
});

test('scan errors are kept per sample and do not stop the run', async () => {
  const scan = async (file) => {
    if (file.endsWith('notes.txt')) throw new Error('quarantined by antivirus');
    return { target: { kind: 'text' }, verdict: { score: 50, level: 'High' }, findings: [], yara: { matches: 0 } };
  };
  const seen = [];
  const b = await runBenchmark({ malicious: [bad], clean: [good], scan, jobs: 3, onSample: (done, total) => seen.push(`${done}/${total}`) });
  assert.equal(b.errors.length, 1);
  assert.match(b.errors[0].error, /quarantined/);
  assert.equal(seen.at(-1), '4/4');
  assert.equal(b.metrics.primary.fp, 1);
});

test('end to end: real static scans separate synthetic malicious and clean samples', async () => {
  const b = await runBenchmark({
    malicious: [bad],
    clean: [good],
    scanOptions: { useRea: false, verifySignature: false, useYara: false, sandboxRoot: path.join(dir, 'sandbox') },
  });
  assert.equal(b.schema, 'reap-shield/benchmark@1');
  assert.equal(b.metrics.primary.detectionRate, 1, JSON.stringify(b.missed.map((x) => [x.path, x.level])));
  assert.equal(b.metrics.primary.falsePositiveRate, 0, JSON.stringify(b.falsePositives.map((x) => [x.path, x.level])));
  const md = benchmarkToMarkdown(b);
  assert.match(md, /# REAP-Shield detection benchmark/);
  assert.match(md, /Detection rate \(recall\) \| \*\*100\.0%\*\* \(2\/2\)/);
  assert.match(md, /## By threshold/);
});
