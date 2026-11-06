/**
 * Preload bridge. Exposes a narrow, fixed API to the renderer; the raw
 * ipcRenderer object is never exposed and channel names are not caller-chosen.
 */
const { contextBridge, ipcRenderer, webUtils } = require('electron');

contextBridge.exposeInMainWorld('reap', {
  info: () => ipcRenderer.invoke('app:info'),
  pickFile: () => ipcRenderer.invoke('dialog:pickFile'),
  pickFolder: () => ipcRenderer.invoke('dialog:pickFolder'),
  trashTarget: (scanId) => ipcRenderer.invoke('target:trash', scanId),
  /** Resolve the on-disk path of a dropped File object. */
  pathForFile: (file) => {
    try {
      return webUtils.getPathForFile(file) || null;
    } catch {
      return null;
    }
  },
  startScan: (filePath, options) => ipcRenderer.invoke('scan:start', filePath, options),
  cancelScan: () => ipcRenderer.invoke('scan:cancel'),
  exportReport: (scanId, format) => ipcRenderer.invoke('report:export', scanId, format),
  reveal: (filePath) => ipcRenderer.invoke('shell:reveal', filePath),
  /** Main-initiated scan (screenshot capture mode only). */
  onAutoScan: (callback) => {
    const listener = (_event, filePath) => callback(filePath);
    ipcRenderer.on('app:auto-scan', listener);
    return () => ipcRenderer.removeListener('app:auto-scan', listener);
  },
  onProgress: (callback) => {
    const listener = (_event, payload) => callback(payload);
    ipcRenderer.on('scan:progress', listener);
    return () => ipcRenderer.removeListener('scan:progress', listener);
  },
});
