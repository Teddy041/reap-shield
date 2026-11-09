/**
 * Renderer-side API. Inside Electron it is the preload bridge (window.reap).
 * In a plain browser (UI development / preview) it falls back to a demo mode
 * that replays a bundled sample report, so the dashboard can be designed
 * without the desktop shell.
 */
import demoReport from './demo-report.json';

const demoListeners = new Set();

const demo = {
  demo: true,
  info: async () => ({
    name: 'REAP-Shield',
    version: demoReport.tool.version,
    platform: 'browser',
    rea: { available: false, kind: 'demo', source: 'Demo mode: open the desktop app to run real scans' },
  }),
  pickFile: async () => 'C:\\Samples\\demo-sample.zip',
  pickFolder: async () => 'C:\\Samples\\demo-folder',
  trashTarget: async () => ({ trashed: window.confirm('Demo mode: pretend to move the file to the Recycle Bin?'), path: 'C:\\Samples\\demo-sample.zip' }),
  pathForFile: (file) => file?.name ?? 'demo-sample.zip',
  startScan: async () => {
    const steps = [
      ['init', 'Validating input', 2],
      ['extract', 'Extracting demo-sample.zip', 12],
      ['inventory', 'Hashing 6 file(s)', 25],
      ['analyze', 'Analyzing demo-sample.zip!/payload/updater.exe', 45],
      ['analyze', 'Analyzing demo-sample.zip!/resources/app.asar!/main.js', 70],
      ['score', 'Scoring findings', 92],
      ['done', `Scan complete: ${demoReport.verdict.level} (${demoReport.verdict.score}/100)`, 100],
    ];
    for (const [stage, message, percent] of steps) {
      await new Promise((r) => setTimeout(r, 350));
      demoListeners.forEach((cb) => cb({ stage, message, percent }));
    }
    return demoReport;
  },
  cancelScan: async () => true,
  exportReport: async (_id, format) => {
    const blob = new Blob([JSON.stringify(demoReport, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `reap-shield-demo.${format === 'json' ? 'json' : 'json'}`;
    a.click();
    return `Downloaded demo report (${format} export needs the desktop app)`;
  },
  reveal: async () => {},
  yaraStatus: async () => ({
    engine: { name: 'YARA-X', version: 'demo' },
    forge: null,
    customFiles: 0,
    customRules: 0,
    packages: ['core', 'extended', 'full'],
    note: 'Demo mode: open the desktop app to download and use YARA rules.',
  }),
  yaraUpdate: async () => {
    throw new Error('Downloading rules needs the desktop app.');
  },
  yaraOpenCustom: async () => {
    throw new Error('The custom rules folder is available in the desktop app.');
  },
  onYaraProgress: () => () => {},
  onProgress: (cb) => {
    demoListeners.add(cb);
    return () => demoListeners.delete(cb);
  },
};

export const api = typeof window !== 'undefined' && window.reap ? window.reap : demo;
