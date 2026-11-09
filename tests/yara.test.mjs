/**
 * Tests for YARA-X signature matching. Rules and samples are generated at
 * runtime; the rule folder is an isolated temporary directory.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { buildZip } from './fixtures.mjs';
import { scanFile } from '../src/analyzer/index.mjs';
import { yaraDirs, yaraSeverity, countRules, updateForgeRules, forgeInfo, loadRules } from '../src/analyzer/yara.mjs';

let dir;
let sample;

const DEMO_RULES = `
private rule IsPython { strings: $i = "import " condition: $i }

rule REAP_Test_Marker : test {
  meta:
    description = "Synthetic marker string used by the test suite"
    severity = "high"
    author = "REAP-Shield tests"
    reference = "https://example.com/rule"
  strings:
    $m = "REAP-YARA-TEST-MARKER" ascii wide
  condition:
    IsPython and $m
}

rule REAP_Test_Scored {
  meta:
    score = 92
  strings:
    $s = "scored-marker"
  condition:
    $s
}
`;

before(async () => {
  dir = await fs.mkdtemp(path.join(os.tmpdir(), 'reap-yara-'));
  process.env.REAP_YARA_DIR = path.join(dir, 'rules');
  const { custom } = yaraDirs();
  await fs.mkdir(custom, { recursive: true });
  await fs.writeFile(path.join(custom, 'demo.yar'), DEMO_RULES);
  await fs.writeFile(path.join(custom, 'broken.yar'), 'rule broken { strings: $a = "x" condition: $b }\n');
  sample = path.join(dir, 'sample.py');
  await fs.writeFile(sample, 'import os\nmarker = "REAP-YARA-TEST-MARKER"\nother = "scored-marker"\n');
});

after(async () => {
  await fs.rm(dir, { recursive: true, force: true });
});

const scan = (p, extra = {}) => scanFile(p, { useRea: false, verifySignature: false, sandboxRoot: path.join(dir, 'sandbox'), ...extra });

test('custom YARA rules match and become findings with evidence', async () => {
  const r = await scan(sample);
  const hit = r.findings.find((f) => f.ruleId === 'yara.REAP_Test_Marker');
  assert.ok(hit, 'marker rule should match');
  assert.equal(hit.category, 'yara');
  assert.equal(hit.severity, 'high');
  assert.equal(hit.source, 'yara');
  assert.match(hit.description, /Synthetic marker string/);
  assert.ok(hit.evidence.some((e) => /\$m @ 0x[0-9a-f]+: "REAP-YARA-TEST-MARKER"/.test(e)));
  assert.ok(hit.evidence.includes('Reference: https://example.com/rule'));
  assert.equal(r.findings.find((f) => f.ruleId === 'yara.REAP_Test_Scored')?.severity, 'critical', 'score 92 maps to critical');
  assert.ok(!r.findings.some((f) => f.ruleId === 'yara.IsPython'), 'private rules are never reported');
  assert.equal(r.yara.ruleCount, 2);
  assert.equal(r.yara.matchedFiles, 1);
});

test('a broken rule file is skipped and reported, the others still load', async () => {
  const r = await scan(sample);
  const broken = r.yara.sources.find((s) => s.name === 'broken.yar');
  assert.equal(broken.ok, false);
  assert.match(broken.error, /unknown pattern/);
  assert.ok(r.yara.sources.find((s) => s.name === 'demo.yar').ok);
  assert.ok(r.errors.some((e) => /broken\.yar was skipped/.test(e)));
});

test('files inside archives are matched and extra rule paths are loaded', async () => {
  const extra = path.join(dir, 'extra.yar');
  await fs.writeFile(extra, 'rule REAP_Extra { strings: $x = "zip-only-marker" condition: $x }\n');
  const zip = path.join(dir, 'bundle.zip');
  await fs.writeFile(zip, buildZip([{ name: 'inner/readme.txt', data: 'hello zip-only-marker' }]));
  const r = await scan(zip, { yaraRules: [extra] });
  const hit = r.findings.find((f) => f.ruleId === 'yara.REAP_Extra');
  assert.ok(hit);
  assert.match(hit.file, /bundle\.zip!\/inner\/readme\.txt$/);
  assert.ok(r.yara.sources.some((s) => s.kind === 'extra' && s.ok));
});

test('YARA can be turned off, and a missing rule set is explained', async () => {
  const off = await scan(sample, { useYara: false });
  assert.equal(off.yara.enabled, false);
  assert.ok(!off.findings.some((f) => f.source === 'yara'));

  const saved = process.env.REAP_YARA_DIR;
  process.env.REAP_YARA_DIR = path.join(dir, 'empty-rules');
  try {
    const none = await scan(sample);
    assert.equal(none.yara.ruleCount, 0);
    assert.match(none.yara.note, /No YARA rules are installed/);
  } finally {
    process.env.REAP_YARA_DIR = saved;
  }
});

test('severity mapping and rule counting', () => {
  assert.equal(yaraSeverity({ severity: 'LOW' }), 'low');
  assert.equal(yaraSeverity({ score: 75 }), 'high');
  assert.equal(yaraSeverity({ score: 60 }), 'medium');
  assert.equal(yaraSeverity({ score: 10 }), 'info');
  assert.equal(yaraSeverity({}), 'medium');
  assert.equal(countRules(DEMO_RULES), 2);
});

test('YARA Forge update validates, installs and records the package', async () => {
  const saved = process.env.REAP_YARA_DIR;
  process.env.REAP_YARA_DIR = path.join(dir, 'forge-test');
  try {
    const yar = '/*\n * Creation Date: 2026-01-02\n * YARA-Forge Version: 0.9.1\n */\nrule FORGE_Test { meta: score = 80 strings: $a = "forge-marker" condition: $a }\n';
    const zip = buildZip([{ name: 'packages/core/yara-rules-core.yar', data: yar }]);
    let requested = '';
    const fetchImpl = async (url) => {
      requested = url;
      return new Response(zip, { status: 200, headers: { 'content-length': String(zip.length) } });
    };
    const info = await updateForgeRules({ pkg: 'core', fetchImpl });
    assert.match(requested, /yara-forge-rules-core\.zip$/);
    assert.equal(info.rules, 1);
    assert.equal(info.created, '2026-01-02');
    assert.equal((await forgeInfo()).sha256, info.sha256);
    const loaded = await loadRules();
    assert.equal(loaded.ruleCount, 1);
    assert.equal(loaded.sources[0].kind, 'forge');
    const again = await loadRules();
    assert.equal(again.cached, true, 'unchanged rule files are not recompiled');
    assert.equal(again.compileMs, 0);

    const badZip = buildZip([{ name: 'rules.yar', data: 'rule bad { condition: $nope }' }]);
    await assert.rejects(updateForgeRules({ pkg: 'core', fetchImpl: async () => new Response(badZip) }), /do not compile/);
    assert.equal((await forgeInfo()).sha256, info.sha256, 'a failed update keeps the installed rules');
    await assert.rejects(updateForgeRules({ pkg: 'nope', fetchImpl }), /Unknown YARA Forge package/);
  } finally {
    process.env.REAP_YARA_DIR = saved;
  }
});
