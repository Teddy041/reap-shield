/**
 * Worker thread that downloads and validates the YARA Forge rule package, so the
 * multi-second YARA-X compilation never blocks the Electron main process.
 */
import { parentPort, workerData } from 'node:worker_threads';
import { updateForgeRules } from '../analyzer/yara.mjs';

try {
  const info = await updateForgeRules({
    pkg: workerData.pkg,
    onProgress: (message) => parentPort.postMessage({ type: 'progress', message }),
  });
  parentPort.postMessage({ type: 'result', info });
} catch (err) {
  parentPort.postMessage({ type: 'error', message: err?.message ?? String(err) });
}
