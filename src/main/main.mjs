/**
 * REAP-Shield Electron main process.
 *
 * Security posture of this app itself (it handles hostile files, so it must
 * not become the weak link):
 *  - contextIsolation: true, nodeIntegration: false, sandbox: true
 *  - a strict Content-Security-Policy in the renderer
 *  - every IPC handler validates the sending frame
 *  - navigation and new windows are blocked
 *  - scans run in a worker thread; nothing extracted is ever executed
 */
import { app, BrowserWindow, ipcMain, dialog, shell, session } from 'electron';
import { Worker } from 'node:worker_threads';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';
import { toHtml, toMarkdown } from '../analyzer/report.mjs';
import { locateRea } from '../analyzer/rea.mjs';
import { purgeStaleSandboxes, removeSandboxDir } from '../analyzer/sandbox.mjs';
import { DEFAULT_SANDBOX_ROOT, maxSizeGbToBytes, MAX_SIZE_CHOICES_GB, SAFE_SIZE_RANGE_NOTE } from '../analyzer/config.mjs';
import { TOOL } from '../analyzer/index.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
/** Electron's unpatched fs: sees *.asar targets as files, not virtual directories. */
const originalFs = createRequire(import.meta.url)('original-fs');
const ROOT = path.resolve(here, '..', '..');
const DEV_URL = app.isPackaged ? undefined : process.env.VITE_DEV_SERVER_URL;
/**
 * Sandbox root. The portable exe unpacks itself into a fresh temp folder on every
 * launch, so a packaged build keeps its sandbox under the user profile instead.
 */
const SANDBOX_ROOT = app.isPackaged ? path.join(app.getPath('userData'), 'sandbox') : DEFAULT_SANDBOX_ROOT;
configureReaForPackagedBuild();

/**
 * A packaged app cannot find REA next to the project folder, so the build
 * records the REA checkout path in build-info.json. REA_HOME (inherited by the
 * scan worker) points there unless the user already set REA_BIN / REA_HOME.
 */
function configureReaForPackagedBuild() {
  if (!app.isPackaged || process.env.REA_BIN || process.env.REA_HOME) return;
  try {
    const info = JSON.parse(originalFs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), 'build-info.json'), 'utf8'));
    if (info.reaHome && originalFs.existsSync(path.join(info.reaHome, 'scripts', 'rea.mjs'))) process.env.REA_HOME = info.reaHome;
  } catch {
    /* no build info: REA is looked up on PATH */
  }
}
const UI_INDEX = path.join(ROOT, 'dist', 'ui', 'index.html');

/** @type {BrowserWindow | null} */
let mainWindow = null;
/** @type {{worker: Worker, sandboxDir: string | null} | null} */
let activeScan = null;
/** Reports kept in the main process so exports never trust renderer data. */
const reports = new Map();

app.enableSandbox();

function isTrustedSender(event) {
  const url = event.senderFrame?.url ?? '';
  if (DEV_URL) return url.startsWith(DEV_URL);
  return url.startsWith(pathToFileURL(path.join(ROOT, 'dist', 'ui')).href);
}

function handle(channel, fn) {
  ipcMain.handle(channel, async (event, ...args) => {
    if (!isTrustedSender(event)) throw new Error('Rejected IPC from untrusted frame.');
    return fn(event, ...args);
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1360,
    height: 900,
    minWidth: 980,
    minHeight: 680,
    backgroundColor: '#070b12',
    title: 'REAP-Shield',
    autoHideMenuBar: true,
    show: false,
    webPreferences: {
      preload: path.join(here, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      spellcheck: false,
    },
  });
  mainWindow.once('ready-to-show', () => mainWindow?.show());
  if (process.env.REAP_SMOKE_TEST) runSmokeTest(mainWindow, process.env.REAP_SMOKE_TEST);
  if (process.env.REAP_CAPTURE_DIR && process.env.REAP_CAPTURE_TARGET) runCapture(mainWindow, process.env.REAP_CAPTURE_TARGET, process.env.REAP_CAPTURE_DIR);
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  mainWindow.webContents.on('will-navigate', (e) => e.preventDefault());
  if (DEV_URL) mainWindow.loadURL(DEV_URL);
  else mainWindow.loadFile(UI_INDEX);
  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// ------------------------------------------------------------------ IPC

handle('app:info', () => {
  const rea = locateRea({ refresh: true });
  return {
    name: TOOL.name,
    version: TOOL.version,
    platform: process.platform,
    rea: { available: rea.kind === 'node-script' || rea.kind === 'binary', kind: rea.kind, source: rea.source },
    sizeLimit: { choicesGb: MAX_SIZE_CHOICES_GB, defaultGb: 1, note: SAFE_SIZE_RANGE_NOTE },
  };
});

handle('dialog:pickFile', async () => {
  const res = await dialog.showOpenDialog(mainWindow, {
    title: 'Select a file to inspect',
    properties: ['openFile'],
    filters: [
      {
        name: 'Supported files',
        extensions: [
          'exe', 'dll', 'sys', 'scr', 'cpl', 'ocx', 'msi', 'msp', 'cab',
          'zip', 'rar', '7z', 'tar', 'gz', 'tgz', 'xz', 'txz', 'bz2', 'zst', 'iso', 'img', 'vhd', 'vhdx', 'wim', 'chm', 'lzh', 'arj', 'cpio',
          'asar', 'jar', 'apk',
          'js', 'mjs', 'cjs', 'jse', 'py', 'ps1', 'bat', 'cmd', 'vbs', 'vbe', 'wsf', 'hta', 'html', 'htm', 'svg',
          'lnk', 'url', 'pdf', 'doc', 'docm', 'docx', 'xls', 'xlsm', 'xlsx', 'ppt', 'pptm', 'pptx', 'rtf', 'msg',
        ],
      },
      { name: 'All files', extensions: ['*'] },
    ],
  });
  return res.canceled ? null : res.filePaths[0];
});

handle('dialog:pickFolder', async () => {
  const res = await dialog.showOpenDialog(mainWindow, { title: 'Select a folder to inspect', properties: ['openDirectory'] });
  return res.canceled ? null : res.filePaths[0];
});

handle('scan:start', async (event, filePath, options = {}) => {
  if (typeof filePath !== 'string' || !path.isAbsolute(filePath)) throw new Error('A valid absolute file path is required.');
  if (activeScan) throw new Error('A scan is already running.');
  let stat;
  try {
    stat = await originalFs.promises.stat(filePath);
  } catch (err) {
    throw new Error(
      err.code === 'ENOENT'
        ? `The item no longer exists: ${filePath}`
        : err.code === 'EPERM' || err.code === 'EACCES'
          ? `Access denied (the file may be locked by another program or blocked by antivirus): ${filePath}`
          : `Cannot open ${filePath} (${err.code ?? err.message}).`,
    );
  }
  if (!stat.isFile() && !stat.isDirectory()) throw new Error(`This item is neither a file nor a folder (device, pipe or special file): ${filePath}`);

  const safeOptions = {
    useRea: options.useRea !== false,
    deep: options.deep === true,
    verifySignature: options.verifySignature !== false,
    // Renderer input is validated here: only a number inside the supported GB range is accepted.
    maxInputBytes: options.maxSizeGb === undefined ? undefined : maxSizeGbToBytes(options.maxSizeGb),
    provider: typeof options.provider === 'string' && /^[a-z][\w-]{0,30}$/i.test(options.provider) ? options.provider : undefined,
    sandboxRoot: SANDBOX_ROOT,
  };
  const sender = event.sender;
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./scanWorker.mjs', import.meta.url), { workerData: { filePath, options: safeOptions } });
    activeScan = { worker, sandboxDir: null };
    const finish = () => {
      activeScan = null;
    };
    worker.on('message', (msg) => {
      if (msg.type === 'sandbox' && activeScan) activeScan.sandboxDir = msg.dir;
      else if (msg.type === 'progress' && !sender.isDestroyed()) sender.send('scan:progress', msg.event);
      else if (msg.type === 'result') {
        reports.set(msg.report.scanId, msg.report);
        if (reports.size > 20) reports.delete(reports.keys().next().value);
        finish();
        resolve(msg.report);
      } else if (msg.type === 'error') {
        finish();
        reject(new Error(msg.message));
      }
    });
    worker.on('error', (err) => {
      finish();
      reject(err);
    });
    worker.on('exit', (code) => {
      if (activeScan?.worker === worker) {
        const dir = activeScan.sandboxDir;
        finish();
        if (dir) removeSandboxDir(dir, SANDBOX_ROOT);
        reject(new Error(code === 1 ? 'Scan cancelled.' : `Scan worker exited with code ${code}.`));
      }
    });
  });
});

handle('scan:cancel', async () => {
  if (!activeScan) return false;
  const { worker, sandboxDir } = activeScan;
  await worker.terminate();
  if (sandboxDir) await removeSandboxDir(sandboxDir, SANDBOX_ROOT);
  return true;
});

handle('report:export', async (_event, scanId, format) => {
  const report = reports.get(scanId);
  if (!report) throw new Error('Report not found. Run the scan again.');
  if (!['pdf', 'md', 'json', 'html'].includes(format)) throw new Error('Unsupported export format.');
  const base = `reap-shield-${report.target.name.replace(/[^\w.-]+/g, '_')}-${report.verdict.level.toLowerCase()}`;
  const res = await dialog.showSaveDialog(mainWindow, {
    title: 'Export report',
    defaultPath: path.join(app.getPath('documents'), `${base}.${format}`),
    filters: [{ name: format.toUpperCase(), extensions: [format] }],
  });
  if (res.canceled || !res.filePath) return null;

  if (format === 'md') await fs.writeFile(res.filePath, toMarkdown(report), 'utf8');
  else if (format === 'json') await fs.writeFile(res.filePath, JSON.stringify(report, null, 2), 'utf8');
  else if (format === 'html') await fs.writeFile(res.filePath, toHtml(report), 'utf8');
  else await exportPdf(report, res.filePath);
  return res.filePath;
});

handle('shell:reveal', (_event, filePath) => {
  if (typeof filePath === 'string' && path.isAbsolute(filePath)) shell.showItemInFolder(filePath);
});

/**
 * Move the scanned target to the Recycle Bin (recoverable, never a permanent
 * delete). The path comes from the report stored in the main process, not from
 * the renderer, and the user confirms in a native dialog first.
 */
handle('target:trash', async (_event, scanId) => {
  const report = reports.get(scanId);
  if (!report) throw new Error('Report not found. Run the scan again.');
  const target = report.target.path;
  const exists = await originalFs.promises.stat(target).catch(() => null);
  if (!exists) throw new Error('The item no longer exists at its original location.');
  const isDir = exists.isDirectory();
  const { response } = await dialog.showMessageBox(mainWindow, {
    type: 'warning',
    title: 'Move to Recycle Bin',
    message: `Move this ${isDir ? 'folder' : 'file'} to the Recycle Bin?`,
    detail: `${target}\n\nThreat level: ${report.verdict.level} (${report.verdict.score}/100)\n\nYou can restore it from the Recycle Bin later.`,
    buttons: ['Move to Recycle Bin', 'Cancel'],
    defaultId: 1,
    cancelId: 1,
    noLink: true,
  });
  if (response !== 0) return { trashed: false };
  try {
    await shell.trashItem(target);
  } catch (err) {
    throw new Error(`Could not move to the Recycle Bin: ${err.message}. The file may be open in another program.`);
  }
  return { trashed: true, path: target };
});

/** Render the HTML report in an offscreen, JavaScript-disabled window and print it. */
async function exportPdf(report, outPath) {
  const tmp = path.join(os.tmpdir(), `reap-shield-report-${process.pid}-${Date.now()}.html`);
  await fs.writeFile(tmp, toHtml(report), 'utf8');
  const win = new BrowserWindow({
    show: false,
    webPreferences: { javascript: false, sandbox: true, contextIsolation: true, nodeIntegration: false },
  });
  try {
    await win.loadFile(tmp);
    const pdf = await win.webContents.printToPDF({ printBackground: true, pageSize: 'A4', margins: { marginType: 'default' } });
    await fs.writeFile(outPath, pdf);
  } finally {
    win.destroy();
    await fs.rm(tmp, { force: true });
  }
}

/**
 * REAP_SMOKE_TEST=1            checks that the UI renders and the preload bridge works.
 * REAP_SMOKE_TEST=<file path>  additionally scans that file through IPC + worker.
 * Prints one "SMOKE {json}" line and exits (0 = pass, 1 = fail).
 */
/**
 * Documentation screenshots: REAP_CAPTURE_DIR=<out dir> REAP_CAPTURE_TARGET=<sample file>.
 * Drives the real UI (home → scanning → report → tabs) and saves PNGs, then exits.
 */
function runCapture(win, target, outDir) {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const js = (code) => win.webContents.executeJavaScript(code);
  // Documentation screenshots must not reveal the capturing machine's user name or folders:
  // local paths are rewritten in the page (plain and JSON-escaped forms) before each capture.
  const workspace = path.resolve(ROOT, '..', '..');
  const replacements = [
    [workspace, 'C:\\tools'],
    [os.homedir(), 'C:\\Users\\analyst'],
  ].flatMap(([from, to]) => [
    [from, to],
    [from.replace(/\\/g, '\\\\'), to.replace(/\\/g, '\\\\')],
    [from.replace(/\\/g, '/'), to.replace(/\\/g, '/')],
  ]);
  const anonymise = () =>
    js(`(() => {
      const pairs = ${JSON.stringify(replacements)};
      const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
      for (let n = walker.nextNode(); n; n = walker.nextNode()) {
        let t = n.nodeValue;
        for (const [from, to] of pairs) t = t.split(from).join(to);
        if (t !== n.nodeValue) n.nodeValue = t;
      }
      document.querySelectorAll('[title]').forEach((el) => {
        let t = el.getAttribute('title');
        for (const [from, to] of pairs) t = t.split(from).join(to);
        el.setAttribute('title', t);
      });
    })()`);
  const shot = async (name) => {
    await anonymise();
    const image = await win.webContents.capturePage();
    await fs.mkdir(outDir, { recursive: true });
    await fs.writeFile(path.join(outDir, name), image.toPNG());
    process.stdout.write(`captured ${name}\n`);
  };
  const waitFor = async (condition, timeoutMs = 180000) => {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      if (await js(condition)) return;
      await sleep(100);
    }
    throw new Error(`Timed out waiting for: ${condition}`);
  };
  const clickTab = (label) => js(`[...document.querySelectorAll('[role=tab]')].find((b) => b.textContent.startsWith(${JSON.stringify(label)}))?.click()`);
  const toTabs = () => js(`window.scrollTo(0, document.querySelector('[role=tablist]').getBoundingClientRect().top + window.scrollY - 80)`);

  win.webContents.once('did-finish-load', async () => {
    try {
      win.setContentSize(1440, 900);
      await sleep(1200);
      await shot('01-home.png');
      win.webContents.send('app:auto-scan', target);
      await waitFor(`Boolean(document.querySelector('[role=progressbar]')) || document.body.innerText.includes('THREAT SEVERITY')`);
      await sleep(600);
      if (await js(`Boolean(document.querySelector('[role=progressbar]'))`)) await shot('02-scanning.png');
      await waitFor(`document.body.innerText.includes('THREAT SEVERITY')`);
      await sleep(900);
      await shot('03-report.png');
      await toTabs();
      await sleep(400);
      await shot('04-findings.png');
      await clickTab('PE Inspection');
      await sleep(400);
      await toTabs();
      await shot('05-pe-inspection.png');
      await clickTab('Files');
      await sleep(400);
      await toTabs();
      await shot('06-files.png');
      await clickTab('REA Evidence');
      await sleep(300);
      await js(`document.querySelector('details')?.setAttribute('open', '')`);
      await sleep(400);
      await toTabs();
      await shot('07-rea-evidence.png');
      app.exit(0);
    } catch (err) {
      process.stdout.write(`capture failed: ${err.message}\n`);
      app.exit(1);
    }
  });
}

/** Print the smoke result; also write it to REAP_SMOKE_OUT (the portable launcher hides stdout). */
function reportSmoke(result) {
  const line = `SMOKE ${JSON.stringify(result)}\n`;
  process.stdout.write(line);
  if (process.env.REAP_SMOKE_OUT) originalFs.writeFileSync(process.env.REAP_SMOKE_OUT, line);
}

function runSmokeTest(win, target) {
  win.webContents.once('did-finish-load', async () => {
    try {
      const result = await win.webContents.executeJavaScript(`(async () => {
        await new Promise((r) => setTimeout(r, 500));
        const info = await window.reap.info();
        const target = ${JSON.stringify(target)};
        let verdict = null;
        if (target !== '1') {
          const r = await window.reap.startScan(target, { useRea: info.rea.available });
          verdict = r.verdict.level + ' ' + r.verdict.score + '/100, ' + r.findings.length + ' findings';
        }
        return {
          rendered: document.body.innerText.includes('Inspect before you execute'),
          bridge: typeof window.reap === 'object',
          nodeIsolated: typeof require === 'undefined' && typeof process === 'undefined',
          rea: info.rea.available,
          verdict,
        };
      })()`);
      // REAP_SMOKE_PDF=<path> also renders the last report to PDF through the export path.
      if (process.env.REAP_SMOKE_PDF && reports.size > 0) {
        await exportPdf([...reports.values()].at(-1), process.env.REAP_SMOKE_PDF);
        result.pdfBytes = (await fs.stat(process.env.REAP_SMOKE_PDF)).size;
      }
      const pass = result.rendered && result.bridge && result.nodeIsolated && (target === '1' || Boolean(result.verdict));
      reportSmoke({ pass, ...result });
      app.exit(pass ? 0 : 1);
    } catch (err) {
      reportSmoke({ pass: false, error: err.message });
      app.exit(1);
    }
  });
}

// ------------------------------------------------------------------ lifecycle

app.whenReady().then(async () => {
  // Deny every permission request (camera, notifications, ...); the UI needs none.
  session.defaultSession.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
  await purgeStaleSandboxes(SANDBOX_ROOT);
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('web-contents-created', (_e, contents) => {
  contents.on('will-attach-webview', (e) => e.preventDefault());
});

app.on('window-all-closed', async () => {
  if (activeScan) {
    const { worker, sandboxDir } = activeScan;
    await worker.terminate();
    if (sandboxDir) await removeSandboxDir(sandboxDir, SANDBOX_ROOT);
  }
  if (process.platform !== 'darwin') app.quit();
});
