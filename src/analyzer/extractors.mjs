/**
 * Safe archive extractors. None of them execute content, follow symlinks,
 * honour absolute paths or write outside the sandbox.
 *
 * Supported: ZIP (yauzl), TAR / TAR.GZ / plain GZIP (node-tar, zlib),
 * passwordless RAR4/RAR5 (node-unrar-js, WASM, no native unrar binary),
 * Electron ASAR (built-in parser, no dependency on Electron).
 */
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import zlib from 'node:zlib';
import { pipeline } from 'node:stream/promises';
import { Transform } from 'node:stream';
import yauzl from 'yauzl';
import * as tar from 'tar';
import { createExtractorFromData } from 'node-unrar-js';
import { createRequire } from 'node:module';
import { LIMITS } from './config.mjs';
import { SandboxLimitError } from './sandbox.mjs';
import { SEVENZIP_KINDS } from './fileType.mjs';

/**
 * @typedef {object} ExtractionResult
 * @property {string[]} files      Absolute paths of extracted regular files.
 * @property {string[]} warnings   Human-readable notes (skipped entries etc.).
 * @property {{encrypted:number, symlinks:number, unsafePaths:number, bombSuspects:number}} stats
 */

function newResult() {
  return { files: [], warnings: [], stats: { encrypted: 0, symlinks: 0, unsafePaths: 0, bombSuspects: 0 } };
}

/** Byte-counting transform that aborts when a stream exceeds its budget. */
function byteLimiter(sandbox, maxBytes, label) {
  let seen = 0;
  return new Transform({
    transform(chunk, _enc, cb) {
      seen += chunk.length;
      if (seen > maxBytes) {
        cb(new SandboxLimitError(`${label}: decompressed size exceeds limit; possible archive bomb.`));
        return;
      }
      try {
        sandbox.account(chunk.length);
      } catch (err) {
        cb(err);
        return;
      }
      cb(null, chunk);
    },
  });
}

// ---------------------------------------------------------------- ZIP

/** @returns {Promise<ExtractionResult>} */
export function extractZip(archivePath, destDir, sandbox) {
  const result = newResult();
  return new Promise((resolve, reject) => {
    yauzl.open(
      archivePath,
      // decodeStrings:false disables yauzl's own name validation, which would abort the
      // whole archive on the first "../" entry and let one hostile entry hide the rest.
      // Names are decoded here and every one goes through sandbox.safeJoin instead.
      { lazyEntries: true, autoClose: true, validateEntrySizes: true, strictFileNames: false, decodeStrings: false },
      (openErr, zip) => {
        if (openErr) return reject(new Error(`Malformed ZIP: ${openErr.message}`));
        let stopped = false;
        const stop = (err) => {
          if (stopped) return;
          stopped = true;
          zip.close();
          if (err && !(err instanceof SandboxLimitError)) return reject(err);
          if (err) result.warnings.push(err.message);
          resolve(result);
        };

        zip.on('error', (err) => stop(new Error(`ZIP read error: ${err.message}`)));
        zip.on('end', () => stop());
        zip.on('entry', async (entry) => {
          // Bit 11 = UTF-8 names; otherwise CP437 (latin1 is a close, lossless-enough stand-in).
          const name = Buffer.isBuffer(entry.fileName)
            ? entry.fileName.toString(entry.generalPurposeBitFlag & 0x800 ? 'utf8' : 'latin1')
            : String(entry.fileName);
          entry.fileName = name;
          try {
            if (name.endsWith('/') || name.endsWith('\\')) return zip.readEntry();
            const unixMode = (entry.externalFileAttributes >>> 16) & 0o170000;
            if (unixMode === 0o120000) {
              result.stats.symlinks += 1;
              result.warnings.push(`Skipped symbolic link entry: ${name}`);
              return zip.readEntry();
            }
            if (entry.generalPurposeBitFlag & 0x1) {
              result.stats.encrypted += 1;
              result.warnings.push(`Skipped password-protected entry: ${name}`);
              return zip.readEntry();
            }
            const target = sandbox.safeJoin(destDir, name);
            if (!target) {
              result.stats.unsafePaths += 1;
              result.warnings.push(`Blocked path traversal attempt: ${name}`);
              return zip.readEntry();
            }
            const ratio = entry.compressedSize > 0 ? entry.uncompressedSize / entry.compressedSize : 0;
            if (ratio > LIMITS.maxCompressionRatio && entry.uncompressedSize > 10 * 1024 * 1024) {
              result.stats.bombSuspects += 1;
              result.warnings.push(`Skipped entry with suspicious compression ratio ${ratio.toFixed(0)}:1 (${name})`);
              return zip.readEntry();
            }
            sandbox.reserve(0);
            await fsp.mkdir(path.dirname(target), { recursive: true });
            await new Promise((res, rej) => {
              zip.openReadStream(entry, async (streamErr, readStream) => {
                if (streamErr) return rej(streamErr);
                try {
                  await pipeline(
                    readStream,
                    byteLimiter(sandbox, Math.min(LIMITS.maxEntryBytes, Math.max(entry.uncompressedSize, 1) + 1024), name),
                    fs.createWriteStream(target, { mode: 0o600 }),
                  );
                  res();
                } catch (e) {
                  rej(e);
                }
              });
            });
            result.files.push(target);
            zip.readEntry();
          } catch (err) {
            if (err instanceof SandboxLimitError) return stop(err);
            result.warnings.push(`Failed to extract ${entry.fileName}: ${err.message}`);
            zip.readEntry();
          }
        });
        zip.readEntry();
      },
    );
  });
}

// ---------------------------------------------------------------- TAR / GZIP

/** @returns {Promise<ExtractionResult>} */
export async function extractTar(archivePath, destDir, sandbox) {
  const result = newResult();
  await fsp.mkdir(destDir, { recursive: true });
  let budgetError = null;
  await tar.x({
    file: archivePath,
    cwd: destDir,
    strict: false,
    preservePaths: false, // strips absolute paths and refuses ".." (node-tar default)
    preserveOwner: false,
    noChmod: true,
    unlink: false,
    // Only plain files and directories; never links, devices or FIFOs.
    filter: (entryPath, entry) => {
      const type = entry?.type;
      if (type && type !== 'File' && type !== 'OldFile' && type !== 'ContiguousFile' && type !== 'Directory') {
        if (type === 'SymbolicLink' || type === 'Link') result.stats.symlinks += 1;
        result.warnings.push(`Skipped ${type} entry: ${entryPath}`);
        return false;
      }
      if (type === 'Directory') return true;
      const safeTarget = sandbox.safeJoin(destDir, entryPath);
      if (!safeTarget) {
        result.stats.unsafePaths += 1;
        result.warnings.push(`Blocked path traversal attempt: ${entryPath}`);
        return false;
      }
      try {
        sandbox.reserve(entry?.size ?? 0);
      } catch (err) {
        budgetError ??= err;
        return false;
      }
      result.files.push(safeTarget);
      return true;
    },
    onwarn: (_code, message) => result.warnings.push(`TAR: ${message}`),
  });
  if (budgetError) result.warnings.push(budgetError.message);
  result.files = (await Promise.all(result.files.map(async (f) => ((await isFile(f)) ? f : null)))).filter(Boolean);
  return result;
}

/** Plain .gz (not a tarball): decompress the single stream with a size cap. */
export async function extractGzipSingle(archivePath, destDir, sandbox) {
  const result = newResult();
  const base = path.basename(archivePath).replace(/\.gz$/i, '') || 'decompressed';
  const target = sandbox.safeJoin(destDir, base);
  await fsp.mkdir(destDir, { recursive: true });
  sandbox.reserve(0);
  await pipeline(
    fs.createReadStream(archivePath),
    zlib.createGunzip(),
    byteLimiter(sandbox, LIMITS.maxEntryBytes, base),
    fs.createWriteStream(target, { mode: 0o600 }),
  );
  result.files.push(target);
  return result;
}

/** GZIP may wrap a tarball or a single file; try tar first. */
export async function extractGzip(archivePath, destDir, sandbox) {
  try {
    const res = await extractTar(archivePath, destDir, sandbox);
    if (res.files.length > 0) return res;
  } catch {
    /* not a tarball; fall through */
  }
  return extractGzipSingle(archivePath, destDir, sandbox);
}

// ---------------------------------------------------------------- RAR

/** @returns {Promise<ExtractionResult>} */
export async function extractRar(archivePath, destDir, sandbox) {
  const result = newResult();
  const { size } = await fsp.stat(archivePath);
  if (size > LIMITS.maxRarBytes) {
    throw new SandboxLimitError(`RAR archive larger than ${LIMITS.maxRarBytes} bytes is not decoded in memory.`);
  }
  const data = await fsp.readFile(archivePath);
  const extractor = await createExtractorFromData({
    data: data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength),
  });
  const list = extractor.getFileList();
  if (list.arcHeader?.flags?.headerEncrypted) {
    result.stats.encrypted += 1;
    result.warnings.push('RAR archive headers are encrypted (password required); contents cannot be inspected.');
    return result;
  }
  const wanted = new Set();
  for (const header of list.fileHeaders) {
    if (header.flags.directory) continue;
    if (header.flags.encrypted) {
      result.stats.encrypted += 1;
      result.warnings.push(`Skipped password-protected entry: ${header.name}`);
      continue;
    }
    if (!sandbox.safeJoin(destDir, header.name)) {
      result.stats.unsafePaths += 1;
      result.warnings.push(`Blocked path traversal attempt: ${header.name}`);
      continue;
    }
    if (header.unpSize > LIMITS.maxEntryBytes || (header.packSize > 0 && header.unpSize / header.packSize > LIMITS.maxCompressionRatio && header.unpSize > 10 * 1024 * 1024)) {
      result.stats.bombSuspects += 1;
      result.warnings.push(`Skipped oversized or bomb-like entry: ${header.name}`);
      continue;
    }
    wanted.add(header.name);
  }
  if (wanted.size === 0) return result;
  const extracted = extractor.extract({ files: (h) => wanted.has(h.name) });
  for (const file of extracted.files) {
    const name = file.fileHeader.name;
    if (!file.extraction) continue;
    const target = sandbox.safeJoin(destDir, name);
    try {
      await sandbox.writeBuffer(target, Buffer.from(file.extraction));
      result.files.push(target);
    } catch (err) {
      if (err instanceof SandboxLimitError) {
        result.warnings.push(err.message);
        break;
      }
      result.warnings.push(`Failed to extract ${name}: ${err.message}`);
    }
  }
  return result;
}

// ---------------------------------------------------------------- ASAR

/**
 * Parse an Electron ASAR header without loading Electron.
 * Layout: uint32(4) | uint32(headerPickleSize) | pickle{uint32 payload, uint32 len, json}
 */
export async function readAsarHeader(archivePath) {
  const fh = await fsp.open(archivePath, 'r');
  try {
    const sizeBuf = Buffer.alloc(8);
    await fh.read(sizeBuf, 0, 8, 0);
    if (sizeBuf.readUInt32LE(0) !== 4) throw new Error('Not an ASAR archive (bad size pickle).');
    const headerPickleSize = sizeBuf.readUInt32LE(4);
    if (headerPickleSize < 8 || headerPickleSize > 256 * 1024 * 1024) throw new Error('ASAR header size out of range.');
    const headerBuf = Buffer.alloc(headerPickleSize);
    await fh.read(headerBuf, 0, headerPickleSize, 8);
    const jsonLen = headerBuf.readUInt32LE(4);
    if (jsonLen > headerPickleSize - 8) throw new Error('ASAR header JSON length out of range.');
    const header = JSON.parse(headerBuf.toString('utf8', 8, 8 + jsonLen));
    return { header, dataOffset: 8 + headerPickleSize };
  } finally {
    await fh.close();
  }
}

/** @returns {Promise<ExtractionResult>} */
export async function extractAsar(archivePath, destDir, sandbox) {
  const result = newResult();
  const { header, dataOffset } = await readAsarHeader(archivePath);
  const { size: archiveSize } = await fsp.stat(archivePath);
  const fh = await fsp.open(archivePath, 'r');
  try {
    const stack = [{ node: header, rel: '' }];
    let visited = 0;
    while (stack.length > 0) {
      const { node, rel } = stack.pop();
      if (++visited > LIMITS.maxEntries * 2) {
        result.warnings.push('ASAR tree too large; traversal stopped.');
        break;
      }
      if (!node || typeof node !== 'object' || !node.files || typeof node.files !== 'object') continue;
      for (const [name, child] of Object.entries(node.files)) {
        const childRel = rel ? `${rel}/${name}` : name;
        if (child?.files) {
          stack.push({ node: child, rel: childRel });
          continue;
        }
        if (child?.link) {
          result.stats.symlinks += 1;
          continue;
        }
        if (child?.unpacked) {
          result.warnings.push(`Unpacked entry stored outside the archive (app.asar.unpacked): ${childRel}`);
          continue;
        }
        const size = Number(child?.size ?? 0);
        const offset = Number(child?.offset ?? NaN);
        if (!Number.isFinite(offset) || size < 0 || dataOffset + offset + size > archiveSize) {
          result.warnings.push(`Corrupt ASAR entry bounds: ${childRel}`);
          continue;
        }
        const target = sandbox.safeJoin(destDir, childRel);
        if (!target) {
          result.stats.unsafePaths += 1;
          result.warnings.push(`Blocked path traversal attempt: ${childRel}`);
          continue;
        }
        try {
          const buf = Buffer.alloc(size);
          if (size > 0) await fh.read(buf, 0, size, dataOffset + offset);
          await sandbox.writeBuffer(target, buf);
          result.files.push(target);
        } catch (err) {
          if (err instanceof SandboxLimitError) {
            result.warnings.push(err.message);
            return result;
          }
          result.warnings.push(`Failed to extract ${childRel}: ${err.message}`);
        }
      }
    }
  } finally {
    await fh.close();
  }
  return result;
}

// ---------------------------------------------------------------- 7-Zip (WASM)

const require = createRequire(import.meta.url);

/**
 * Extract with 7-Zip compiled to WebAssembly. The archive is copied into the
 * module's in-memory file system, unpacked there, and every resulting file is
 * written to the sandbox through safeJoin. No native 7-Zip binary is run and
 * 7-Zip never touches the real disk.
 *
 * Covers 7z, XZ, BZIP2, Zstandard, CAB, MSI / OLE (Office 97-2003, VBA projects),
 * ISO, CHM, WIM, LZH, ARJ, CPIO, VHD and NSIS installers (type "Nsis").
 *
 * @param {string} [forcedType] 7-Zip -t switch value, e.g. "Nsis".
 * @returns {Promise<ExtractionResult>}
 */
export async function extract7z(archivePath, destDir, sandbox, forcedType) {
  const result = newResult();
  const { size } = await fsp.stat(archivePath);
  if (size > LIMITS.maxRarBytes) {
    throw new SandboxLimitError(`Archive larger than ${LIMITS.maxRarBytes} bytes is not decoded in memory.`);
  }
  const data = await fsp.readFile(archivePath);
  const typeArgs = forcedType ? [`-t${forcedType}`] : [];
  // Keep the real file name: single-stream formats (xz, bz2) name their output after it,
  // so "x.tar.xz" yields "x.tar", which is then unpacked as a nested archive.
  const inName = `/in/${path.basename(archivePath).replace(/[^\w.-]+/g, '_').slice(-120) || 'archive'}`;

  // 1) List entries to count encrypted items and reject bombs before decompressing.
  const listing = await run7z(data, inName, ['l', '-slt', '-ba', '-bsp0', ...typeArgs, '-pREAPNOPASSWORD', inName]);
  if (listing.error && /Is not archive|Can not open/i.test(listing.errText)) {
    throw new Error(`Not a readable ${forcedType ?? ''} archive: ${listing.errText.trim().slice(0, 200)}`);
  }
  if (listing.error && listing.lines.length === 0) {
    result.stats.encrypted += 1;
    result.warnings.push('Archive could not be listed: headers are encrypted (password required) or the file is corrupt.');
    return result;
  }
  const entries = parseSlt(listing.lines);
  let declaredTotal = 0;
  for (const e of entries) {
    if (e.isDir) continue;
    if (e.encrypted) {
      result.stats.encrypted += 1;
      result.warnings.push(`Skipped password-protected entry: ${e.path}`);
    }
    declaredTotal += e.size;
    if (e.size > LIMITS.maxEntryBytes) {
      result.stats.bombSuspects += 1;
      result.warnings.push(`Entry exceeds the per-file limit: ${e.path} (${e.size} bytes)`);
    }
  }
  const ratio = declaredTotal / Math.max(1, size);
  if (declaredTotal > LIMITS.maxExtractedTotalBytes / 2 || (ratio > LIMITS.maxCompressionRatio && declaredTotal > 64 * 1024 * 1024)) {
    result.stats.bombSuspects += 1;
    throw new SandboxLimitError(`Declared content (${declaredTotal} bytes, ratio ${ratio.toFixed(0)}:1) exceeds the in-memory extraction budget; possible archive bomb.`);
  }
  if (entries.length > 0 && entries.every((e) => e.isDir || e.encrypted)) return result;

  // 2) Extract inside the WASM file system, then copy out through the sandbox.
  const run = await run7z(data, inName, ['x', ...typeArgs, '-y', '-snld', '-pREAPNOPASSWORD', '-bso0', '-bsp0', '-o/out', inName], true);
  if (run.error) result.warnings.push(`7-Zip reported errors: ${(run.errText || 'unknown error').trim().slice(0, 300)}`);
  const FS = run.module?.FS;
  if (!FS) return result;
  const stack = ['/out'];
  while (stack.length) {
    const dir = stack.pop();
    let names;
    try {
      names = FS.readdir(dir);
    } catch {
      continue;
    }
    for (const name of names) {
      if (name === '.' || name === '..') continue;
      const full = `${dir}/${name}`;
      let st;
      try {
        st = FS.lstat(full);
      } catch {
        continue;
      }
      if (FS.isLink(st.mode)) {
        result.stats.symlinks += 1;
        continue;
      }
      if (FS.isDir(st.mode)) {
        stack.push(full);
        continue;
      }
      if (!FS.isFile(st.mode)) continue;
      const rel = full.slice('/out/'.length);
      const target = sandbox.safeJoin(destDir, rel);
      if (!target) {
        result.stats.unsafePaths += 1;
        result.warnings.push(`Blocked path traversal attempt: ${rel}`);
        continue;
      }
      try {
        await sandbox.writeBuffer(target, Buffer.from(FS.readFile(full)));
        result.files.push(target);
        FS.unlink(full); // free WASM memory as we go
      } catch (err) {
        if (err instanceof SandboxLimitError) {
          result.warnings.push(err.message);
          return result;
        }
        result.warnings.push(`Failed to extract ${rel}: ${err.message}`);
      }
    }
  }
  return result;
}

/** Run one 7-Zip command in a fresh WASM instance (fresh, isolated memory file system). */
async function run7z(data, inName, args, keepModule = false) {
  const SevenZip = require('7z-wasm');
  const lines = [];
  const errLines = [];
  // Emscripten writes 7-Zip's exit status into process.exitCode; the CLI's own
  // exit codes (CI gates) must not be overwritten by an archive error.
  const savedExitCode = process.exitCode;
  const module = await SevenZip({
    print: (s) => lines.push(s),
    printErr: (s) => errLines.push(s),
    stdin: () => null, // never block on a password prompt
  });
  module.FS.mkdir('/in');
  module.FS.writeFile(inName, data);
  let error = false;
  try {
    module.callMain(args);
  } catch {
    error = true; // 7-Zip throws (ExitStatus / C++ exception) on fatal archive errors
  } finally {
    process.exitCode = savedExitCode;
  }
  const errText = errLines.join('\n');
  if (/ERROR|Is not archive|Can not open|Wrong password|Data Error|CRC Failed/i.test(errText)) error = true;
  return { lines, errText, error, module: keepModule ? module : null };
}

/** Parse `7z l -slt -ba` output into entries. */
function parseSlt(lines) {
  const entries = [];
  let cur = null;
  for (const raw of lines) {
    // Strip any progress-indicator residue ("...\b\b\bPath = x").
    const line = raw.includes('\b') ? raw.slice(raw.lastIndexOf('\b') + 1) : raw;
    const m = /^(\w[\w ]*?) = (.*)$/.exec(line);
    if (!m) continue;
    const [, key, value] = m;
    if (key === 'Path') {
      cur = { path: value, size: 0, encrypted: false, isDir: false };
      entries.push(cur);
    } else if (cur) {
      if (key === 'Size') cur.size = Number(value) || 0;
      else if (key === 'Encrypted') cur.encrypted = value === '+';
      else if (key === 'Folder') cur.isDir = value === '+';
      else if (key === 'Attributes') cur.isDir ||= /^D/.test(value);
    }
  }
  return entries;
}

async function isFile(p) {
  try {
    return (await fsp.lstat(p)).isFile();
  } catch {
    return false;
  }
}

/** Dispatch by detected kind. */
export async function extractArchive(kind, archivePath, destDir, sandbox) {
  // ZIP / RAR variants the Node extractors reject (SFX-carved zips with shifted offsets,
  // unusual RAR versions, damaged central directories) get a second attempt through 7-Zip.
  if (kind === 'zip' || kind === 'rar') {
    try {
      return await (kind === 'zip' ? extractZip : extractRar)(archivePath, destDir, sandbox);
    } catch (err) {
      if (err instanceof SandboxLimitError) throw err;
      const res = await extract7z(archivePath, destDir, sandbox).catch(() => null);
      if (!res || res.files.length === 0) throw err;
      res.warnings.unshift(`Primary ${kind.toUpperCase()} parser failed (${err.message}); recovered with 7-Zip.`);
      return res;
    }
  }
  switch (kind) {
    case 'zip':
      return extractZip(archivePath, destDir, sandbox);
    case 'tar':
      return extractTar(archivePath, destDir, sandbox);
    case 'gzip':
      return extractGzip(archivePath, destDir, sandbox);
    case 'rar':
      return extractRar(archivePath, destDir, sandbox);
    case 'asar':
      return extractAsar(archivePath, destDir, sandbox);
    case 'nsis':
      return extract7z(archivePath, destDir, sandbox, 'Nsis');
    default:
      if (SEVENZIP_KINDS.has(kind)) return extract7z(archivePath, destDir, sandbox);
      throw new Error(`No extractor for kind "${kind}".`);
  }
}
