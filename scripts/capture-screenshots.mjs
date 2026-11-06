/**
 * Launches the real Electron app in capture mode and writes the README
 * screenshots to docs/screenshots/. Local paths are anonymised in the page
 * before every capture (see runCapture in src/main/main.mjs).
 */
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const electronBin = createRequire(import.meta.url)('electron');
const child = spawn(electronBin, ['.'], {
  cwd: root,
  stdio: 'inherit',
  env: {
    ...process.env,
    REAP_CAPTURE_DIR: path.join(root, 'docs', 'screenshots'),
    REAP_CAPTURE_TARGET: path.join(root, 'temp', 'demo', 'demo-sample.zip'),
  },
});
child.on('exit', (code) => process.exit(code ?? 1));
