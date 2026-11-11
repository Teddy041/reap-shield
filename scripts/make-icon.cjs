/**
 * Renders the REAP-Shield logo (assets/logo-source.webp) to the PNG files the
 * project uses, with Electron's own offscreen renderer, so no image tooling is needed:
 *   build/icon.png          1024x1024  application / installer / launcher icon, README logo
 *   src/ui/public/logo.png   256x256   app header logo, page icon and window icon
 * Run with: electron scripts/make-icon.cjs
 */
const { app, BrowserWindow } = require('electron');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const SOURCE = path.join(root, 'assets', 'logo-source.webp');
const OUTPUTS = [
  { file: path.join(root, 'build', 'icon.png'), size: 1024 },
  { file: path.join(root, 'src', 'ui', 'public', 'logo.png'), size: 256 },
];

const RENDER_SIZE = 1024;

/** Renders the source image once at full size; smaller outputs are resized from it. */
async function render(size = RENDER_SIZE) {
  const win = new BrowserWindow({
    width: size,
    height: size,
    show: false,
    frame: false,
    useContentSize: true,
    webPreferences: { offscreen: true },
  });
  try {
    // A small HTML page next to the source image avoids huge data: URLs.
    const page = path.join(path.dirname(SOURCE), `.render-${size}.html`);
    fs.writeFileSync(page, `<html><body style="margin:0;background:#000;overflow:hidden">
      <img src="${path.basename(SOURCE)}" style="display:block;width:${size}px;height:${size}px"></body></html>`);
    try {
      await win.loadFile(page);
    } finally {
      fs.rmSync(page, { force: true });
    }
    await win.webContents.executeJavaScript('document.images[0].decode().then(() => true)');
    await new Promise((r) => setTimeout(r, 300));
    const image = await win.webContents.capturePage({ x: 0, y: 0, width: size, height: size });
    return image.resize({ width: size, height: size, quality: 'best' });
  } finally {
    win.destroy();
  }
}

app.disableHardwareAcceleration();
app.whenReady().then(async () => {
  try {
    const full = await render();
    for (const { file, size } of OUTPUTS) {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, full.resize({ width: size, height: size, quality: 'best' }).toPNG());
      console.log(`Wrote ${path.relative(root, file)} (${size}x${size})`);
    }
  } catch (err) {
    console.error(`Icon generation failed: ${err?.message ?? err}`);
    process.exitCode = 1;
  }
  app.quit();
});
