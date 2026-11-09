/**
 * Worker thread that runs scans so the Electron main process (and the UI) stays
 * responsive while large files are parsed.
 *
 * The worker is long-lived: it handles one scan at a time and stays alive between
 * scans, so compiled YARA rules are reused instead of being recompiled for every
 * scan. Cancelling a scan terminates the worker; the next scan starts a new one.
 */
import { parentPort } from 'node:worker_threads';
import { scanFile } from '../analyzer/index.mjs';

// Electron patches `fs` so that *.asar files look like directories. The analyzer must see
// them as plain files (to parse and audit them), so Electron's ASAR support is turned off
// for this worker. Static imports above are already resolved at this point.
process.noAsar = true;

parentPort.on('message', async (msg) => {
  if (msg?.type !== 'scan') return;
  try {
    const report = await scanFile(msg.filePath, {
      ...msg.options,
      onSandbox: (dir) => parentPort.postMessage({ type: 'sandbox', dir }),
      onProgress: (event) => parentPort.postMessage({ type: 'progress', event }),
    });
    parentPort.postMessage({ type: 'result', report });
  } catch (err) {
    parentPort.postMessage({ type: 'error', message: err?.message ?? String(err) });
  }
});
