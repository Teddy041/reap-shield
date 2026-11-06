/**
 * Development launcher: waits for the Vite dev server, then starts Electron
 * pointed at it.
 */
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const electronBin = require('electron');
const URL_ = 'http://127.0.0.1:5173';

async function waitFor(url, timeoutMs = 60000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 400));
  }
  throw new Error(`Dev server did not start at ${url}`);
}

await waitFor(URL_);
const child = spawn(electronBin, ['.'], { stdio: 'inherit', env: { ...process.env, VITE_DEV_SERVER_URL: URL_ } });
child.on('exit', (code) => process.exit(code ?? 0));
