/**
 * Worker thread that runs one scan so the Electron main process (and the UI)
 * stays responsive while large files are parsed.
 */
import { parentPort, workerData } from 'node:worker_threads';
import { scanFile } from '../analyzer/index.mjs';

// Electron patches `fs` so that *.asar files look like directories. The analyzer must see
// them as plain files (to parse and audit them), so Electron's ASAR support is turned off
// for this worker. Static imports above are already resolved at this point.
process.noAsar = true;

const { filePath, options } = workerData;

try {
  const report = await scanFile(filePath, {
    ...options,
    onSandbox: (dir) => parentPort.postMessage({ type: 'sandbox', dir }),
    onProgress: (event) => parentPort.postMessage({ type: 'progress', event }),
  });
  parentPort.postMessage({ type: 'result', report });
} catch (err) {
  parentPort.postMessage({ type: 'error', message: err?.message ?? String(err) });
}
