/**
 * Builds src/ui/demo-report.json: a real scan of the synthetic test fixtures
 * (plus a copy of notepad.exe on Windows for the PE view), with local paths
 * removed. Used by the dashboard's browser-only demo mode.
 */
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanFile } from '../src/analyzer/index.mjs';
import { writeFixtures, buildZip, ELECTRON_MAIN, ELECTRON_PRELOAD, SUSPICIOUS_PY, buildAsar } from '../tests/fixtures.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'reap-demo-'));
try {
  await writeFixtures(path.join(tmp, 'fx'));
  const entries = [
    {
      name: 'resources/app.asar',
      data: buildAsar({
        'package.json': JSON.stringify({ name: 'demo-app', main: 'main.js', devDependencies: { electron: '30.0.0' } }),
        'main.js': ELECTRON_MAIN,
        'preload.js': ELECTRON_PRELOAD,
      }),
    },
    { name: 'scripts/installer.py', data: SUSPICIOUS_PY },
    { name: '../../escape.txt', data: 'zip-slip probe' },
    { name: 'invoice.pdf.exe', data: 'not a PE' },
  ];
  const notepad = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'notepad.exe');
  if (fsSync.existsSync(notepad)) entries.push({ name: 'payload/updater.exe', data: await fs.readFile(notepad) });
  const zipPath = path.join(tmp, 'demo-sample.zip');
  await fs.writeFile(zipPath, buildZip(entries));

  // `--zip-out <path>` only writes the synthetic sample archive (used for screenshots).
  const zipOutIdx = process.argv.indexOf('--zip-out');
  if (zipOutIdx !== -1) {
    const dest = path.resolve(process.argv[zipOutIdx + 1]);
    await fs.mkdir(path.dirname(dest), { recursive: true });
    await fs.copyFile(zipPath, dest);
    console.log(`Wrote ${dest}`);
    process.exit(0);
  }

  const report = await scanFile(zipPath, { useRea: false, verifySignature: true, sandboxRoot: path.join(tmp, 'sb') });
  report.target.path = 'C:\\Samples\\demo-sample.zip';
  report.sandbox.dir = 'temp/sandbox/<scan-id>';
  report.rea = { available: false, source: 'Demo mode', runs: [] };
  const out = path.join(root, 'src', 'ui', 'demo-report.json');
  await fs.writeFile(out, JSON.stringify(report, null, 2));
  console.log(`Wrote ${out}: ${report.verdict.level} ${report.verdict.score}/100, ${report.findings.length} findings`);
} finally {
  await fs.rm(tmp, { recursive: true, force: true });
}
