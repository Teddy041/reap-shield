/**
 * Synthetic test fixtures. They contain suspicious-looking *strings and
 * configuration only*; nothing here is functional malware. Indicators such as
 * the webhook are random placeholders.
 */
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import * as tar from 'tar';

// Keep tests independent of the YARA rules installed on this machine: every test
// process gets its own (empty unless a test fills it) rule folder.
if (!process.env.REAP_YARA_DIR) process.env.REAP_YARA_DIR = path.join(os.tmpdir(), `reap-yara-test-${process.pid}`);

const FAKE_WEBHOOK = `https://discord.com/api/webhooks/123456789012345678/${'Ab3_'.repeat(17)}`;

export const ELECTRON_MAIN = `
const { app, BrowserWindow, ipcMain, shell } = require('electron');
const { exec } = require('child_process');
function createWindow() {
  const win = new BrowserWindow({
    webPreferences: { nodeIntegration: true, contextIsolation: false, webSecurity: false, sandbox: false },
  });
  win.loadURL('http://updates.example-cdn.net/app.html');
}
ipcMain.handle('run-command', async (event, cmd) => { exec(cmd); return true; });
ipcMain.on('open', (event, url) => { shell.openExternal(url); });
app.whenReady().then(createWindow);
const report = '${FAKE_WEBHOOK}';
`;

export const ELECTRON_PRELOAD = `
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('api', {
  invoke: (channel, ...args) => ipcRenderer.invoke(channel, ...args),
  ipcRenderer: ipcRenderer,
});
`;

export const SUSPICIOUS_PY = `
import base64, subprocess, winreg
payload = "aW1wb3J0IG9z"
exec(base64.b64decode(payload))
subprocess.Popen("powershell -w hidden -ep bypass -c whoami", shell=True)
key = r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
winreg.SetValueEx(None, "Updater", 0, winreg.REG_SZ, "C:\\\\Users\\\\Public\\\\u.exe")
C2 = "45.137.21.9:4444"
`;

export const BENIGN_JS = `
export function add(a, b) { return a + b; }
console.log('hello world', add(1, 2));
`;

/** Build an ASAR archive in memory (same layout Electron uses). */
export function buildAsar(files) {
  const header = { files: {} };
  const chunks = [];
  let offset = 0;
  for (const [name, content] of Object.entries(files)) {
    const data = Buffer.from(content);
    const parts = name.split('/');
    let node = header;
    for (const dir of parts.slice(0, -1)) {
      node.files[dir] ??= { files: {} };
      node = node.files[dir];
    }
    node.files[parts.at(-1)] = { size: data.length, offset: String(offset) };
    chunks.push(data);
    offset += data.length;
  }
  const json = Buffer.from(JSON.stringify(header));
  const pad = (4 - (json.length % 4)) % 4;
  const pickle = Buffer.alloc(8 + json.length + pad);
  pickle.writeUInt32LE(4 + json.length + pad, 0);
  pickle.writeUInt32LE(json.length, 4);
  json.copy(pickle, 8);
  const sizePickle = Buffer.alloc(8);
  sizePickle.writeUInt32LE(4, 0);
  sizePickle.writeUInt32LE(pickle.length, 4);
  return Buffer.concat([sizePickle, pickle, ...chunks]);
}

/** Minimal ZIP writer (deflate). Names are written verbatim, including "../". */
export function buildZip(entries) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const { name, data } of entries) {
    const raw = Buffer.from(data);
    const comp = zlib.deflateRawSync(raw);
    const nameBuf = Buffer.from(name);
    const crc = zlib.crc32(raw);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(8, 8);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(comp.length, 18);
    local.writeUInt32LE(raw.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(8, 10);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(comp.length, 20);
    central.writeUInt32LE(raw.length, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt32LE(offset, 42);
    locals.push(local, nameBuf, comp);
    centrals.push(central, nameBuf);
    offset += 30 + nameBuf.length + comp.length;
  }
  const cd = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cd.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, end]);
}

/** Write all fixtures to `dir` and return their paths. */
export async function writeFixtures(dir) {
  await fs.mkdir(dir, { recursive: true });
  const asar = buildAsar({
    'package.json': JSON.stringify({ name: 'evil-app', main: 'main.js', devDependencies: { electron: '30.0.0' } }),
    'main.js': ELECTRON_MAIN,
    'preload.js': ELECTRON_PRELOAD,
  });
  const asarPath = path.join(dir, 'app.asar');
  await fs.writeFile(asarPath, asar);

  const pyPath = path.join(dir, 'installer.py');
  await fs.writeFile(pyPath, SUSPICIOUS_PY);

  const benignPath = path.join(dir, 'benign.js');
  await fs.writeFile(benignPath, BENIGN_JS);

  const innerZip = buildZip([{ name: 'scripts/installer.py', data: SUSPICIOUS_PY }]);
  const zipPath = path.join(dir, 'bundle.zip');
  await fs.writeFile(
    zipPath,
    buildZip([
      { name: 'resources/app.asar', data: asar },
      { name: 'nested/inner.zip', data: innerZip },
      { name: '../../escape.txt', data: 'zip-slip probe' },
      { name: 'invoice.pdf.exe', data: 'not really a PE' },
    ]),
  );

  const tarSrc = path.join(dir, 'tar-src');
  await fs.mkdir(path.join(tarSrc, 'pkg'), { recursive: true });
  await fs.writeFile(path.join(tarSrc, 'pkg', 'installer.py'), SUSPICIOUS_PY);
  const tgzPath = path.join(dir, 'bundle.tar.gz');
  await tar.c({ gzip: true, file: tgzPath, cwd: tarSrc }, ['pkg']);

  const garbagePath = path.join(dir, 'broken.zip');
  await fs.writeFile(garbagePath, Buffer.concat([Buffer.from('PK\x03\x04'), Buffer.alloc(64, 0xff)]));

  return { asarPath, pyPath, benignPath, zipPath, tgzPath, garbagePath, tarSrc };
}
