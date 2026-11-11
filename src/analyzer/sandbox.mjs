/**
 * Isolated per-scan workspace.
 *
 * Every scan gets its own directory under temp/sandbox/<scan-id>/. Nothing in
 * the sandbox is ever executed: REAP-Shield only reads bytes. The sandbox
 * enforces path containment (zip-slip protection) and global byte / entry
 * budgets so a hostile archive cannot escape the workspace or fill the disk.
 */
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { DEFAULT_SANDBOX_ROOT, LIMITS } from './config.mjs';

export class SandboxLimitError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SandboxLimitError';
  }
}

export class Sandbox {
  /**
   * @param {object} [opts]
   * @param {string} [opts.root] Sandbox root directory.
   */
  constructor(opts = {}) {
    this.root = path.resolve(opts.root ?? DEFAULT_SANDBOX_ROOT);
    this.id = `scan-${new Date().toISOString().replace(/[:.]/g, '-')}-${crypto.randomBytes(4).toString('hex')}`;
    this.dir = path.join(this.root, this.id);
    this.bytesWritten = 0;
    this.entriesWritten = 0;
  }

  async init() {
    await fs.mkdir(this.dir, { recursive: true });
    // Marker file so humans know never to run anything from here.
    await fs.writeFile(
      path.join(this.dir, 'DO-NOT-EXECUTE.txt'),
      'This directory contains untrusted files extracted by REAP-Shield for static analysis.\n' +
        'Never run, open or double-click anything in it. It is deleted after the scan.\n',
    );
    return this;
  }

  /**
   * Resolve an archive-supplied relative name inside `baseDir`, rejecting any
   * path that would escape it (absolute paths, drive letters, "..", UNC, NUL).
   * Returns null when the name is unsafe.
   */
  safeJoin(baseDir, entryName) {
    if (typeof entryName !== 'string' || entryName.length === 0 || entryName.includes('\0')) return null;
    let name = entryName.replace(/\\/g, '/');
    // Strip drive letters and leading slashes; treat as relative.
    name = name.replace(/^[a-zA-Z]:/, '').replace(/^\/+/, '');
    const parts = [];
    for (const part of name.split('/')) {
      if (part === '' || part === '.') continue;
      if (part === '..') return null;
      // Windows-reserved characters and device names would misbehave on NTFS.
      const cleaned = part.replace(/[<>:"|?*\x00-\x1f]/g, '_');
      // Windows ignores trailing spaces when it resolves device names ("NUL .txt").
      const stem = cleaned.split('.')[0].trim().toUpperCase();
      parts.push(/^(CON|PRN|AUX|NUL|COM\d|LPT\d)$/.test(stem) ? `_${cleaned}` : cleaned);
    }
    if (parts.length === 0) return null;
    const resolvedBase = path.resolve(baseDir);
    const target = path.resolve(resolvedBase, ...parts);
    const rel = path.relative(resolvedBase, target);
    if (rel.startsWith('..') || path.isAbsolute(rel)) return null;
    if (!target.startsWith(path.resolve(this.dir))) return null;
    return target;
  }

  /** Reserve budget for one entry before writing it. Throws when exhausted. */
  reserve(bytes) {
    if (this.entriesWritten + 1 > LIMITS.maxEntries) {
      throw new SandboxLimitError(`Entry limit reached (${LIMITS.maxEntries}); remaining entries skipped.`);
    }
    if (bytes > LIMITS.maxEntryBytes) {
      throw new SandboxLimitError(`Entry exceeds per-file limit (${bytes} > ${LIMITS.maxEntryBytes} bytes).`);
    }
    if (this.bytesWritten + bytes > LIMITS.maxExtractedTotalBytes) {
      throw new SandboxLimitError('Total extraction budget exhausted; possible archive bomb.');
    }
    this.entriesWritten += 1;
    this.bytesWritten += bytes;
  }

  /** Track bytes discovered while streaming (declared sizes can lie). */
  account(extraBytes) {
    this.bytesWritten += extraBytes;
    if (this.bytesWritten > LIMITS.maxExtractedTotalBytes) {
      throw new SandboxLimitError('Total extraction budget exhausted while streaming; possible archive bomb.');
    }
  }

  /**
   * Write a buffer to a safe path inside the sandbox.
   * Returns the path that was actually written: when `target` already exists (duplicate
   * entry names, or names that differ only by case on Windows) the data goes to a
   * unique sibling name, so both versions are kept and analyzed.
   * @returns {Promise<string>}
   */
  async writeBuffer(target, data) {
    this.reserve(data.byteLength);
    await fs.mkdir(path.dirname(target), { recursive: true });
    // 0o600: owner read/write only, never executable.
    try {
      await fs.writeFile(target, data, { mode: 0o600, flag: 'wx' });
      return target;
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
      const alt = uniqueName(target);
      await fs.writeFile(alt, data, { mode: 0o600, flag: 'wx' });
      return alt;
    }
  }

  /** Remove the scan directory. Never throws. */
  async cleanup() {
    try {
      await fs.rm(this.dir, { recursive: true, force: true, maxRetries: 3, retryDelay: 200 });
    } catch {
      /* best effort: antivirus or indexers may briefly lock files on Windows */
    }
  }

  /** Synchronous cleanup used from process exit handlers. */
  cleanupSync() {
    try {
      fsSync.rmSync(this.dir, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  }
}

/**
 * Remove sandboxes left behind by crashed or cancelled scans.
 * Only directories named "scan-*" older than `maxAgeMs` are removed.
 */
export async function purgeStaleSandboxes(root = DEFAULT_SANDBOX_ROOT, maxAgeMs = 60 * 60 * 1000) {
  let removed = 0;
  try {
    for (const entry of await fs.readdir(root, { withFileTypes: true })) {
      if (!entry.isDirectory() || !entry.name.startsWith('scan-')) continue;
      const full = path.join(root, entry.name);
      const { mtimeMs } = await fs.stat(full);
      if (Date.now() - mtimeMs > maxAgeMs) {
        await fs.rm(full, { recursive: true, force: true });
        removed += 1;
      }
    }
  } catch {
    /* root may not exist yet */
  }
  return removed;
}

/** Remove one sandbox directory if it is inside the sandbox root. */
export async function removeSandboxDir(dir, root = DEFAULT_SANDBOX_ROOT) {
  const resolved = path.resolve(dir);
  const rel = path.relative(path.resolve(root), resolved);
  if (!rel || rel.startsWith('..') || path.isAbsolute(rel) || !path.basename(resolved).startsWith('scan-')) return false;
  await fs.rm(resolved, { recursive: true, force: true }).catch(() => {});
  return true;
}

export function uniqueName(target) {
  const ext = path.extname(target);
  return `${target.slice(0, target.length - ext.length)}.${crypto.randomBytes(3).toString('hex')}${ext}`;
}

/**
 * Run `fn` and convert any thrown error into a structured result so that a
 * malformed input never crashes the caller.
 */
export async function guard(label, fn) {
  try {
    return { ok: true, value: await fn() };
  } catch (err) {
    return { ok: false, error: `${label}: ${err?.message ?? String(err)}`, limit: err instanceof SandboxLimitError };
  }
}
