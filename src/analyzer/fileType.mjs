/**
 * File type detection by magic bytes first, extension second.
 * Attackers rename files, so the extension alone is never trusted.
 */
import fs from 'node:fs/promises';
import path from 'node:path';
import { PE_EXTENSIONS, SCRIPT_EXTENSIONS } from './config.mjs';
import { decodeText, sniffTextEncoding } from './strings.mjs';

/**
 * @typedef {'pe'|'elf'|'macho'|'zip'|'rar'|'tar'|'gzip'|'asar'|'7z'|'script'|'json'|'text'|'binary'|'empty'} FileKind
 */

/** Read the first `n` bytes of a file. */
async function readHead(filePath, n = 1024) {
  const fh = await fs.open(filePath, 'r');
  try {
    const buf = Buffer.alloc(n);
    const { bytesRead } = await fh.read(buf, 0, n, 0);
    return buf.subarray(0, bytesRead);
  } finally {
    await fh.close();
  }
}

function looksLikeText(buf) {
  if (buf.length === 0) return false;
  if (sniffTextEncoding(buf).encoding !== 'utf8') {
    // UTF-16: judge the decoded characters, not the NUL-padded bytes.
    const text = decodeText(buf);
    if (text.length === 0) return false;
    let ok = 0;
    for (let i = 0; i < text.length; i += 1) {
      const c = text.charCodeAt(i);
      if (c === 9 || c === 10 || c === 13 || (c >= 32 && c !== 0x7f && c !== 0xfffd)) ok += 1;
    }
    return ok / text.length > 0.95;
  }
  let printable = 0;
  for (const b of buf) {
    if (b === 0) return false;
    if (b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127) || b >= 128) printable += 1;
  }
  return printable / buf.length > 0.95;
}

/**
 * True when the first 4 KiB of a file read as text (any magic bytes at the start included).
 * Stricter than looksLikeText: it decides whether a file that claims to be an archive or an
 * executable is really a script, so bytes above 0x7f do not count as printable here.
 */
export async function headLooksTextual(filePath) {
  const head = await readHead(filePath, 4096);
  if (!looksLikeText(head)) return false;
  if (sniffTextEncoding(head).encoding !== 'utf8') return true;
  let ascii = 0;
  for (const b of head) if (b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127)) ascii += 1;
  return ascii / head.length > 0.85;
}

/** Validate the ASAR pickle header layout: [4][headerSize][payloadSize][jsonLen]{json */
function looksLikeAsar(buf) {
  if (buf.length < 17) return false;
  if (buf.readUInt32LE(0) !== 4) return false;
  const headerSize = buf.readUInt32LE(4);
  const jsonLen = buf.readUInt32LE(12);
  return headerSize > 8 && jsonLen > 0 && jsonLen <= headerSize && buf[16] === 0x7b; // '{'
}

/**
 * Detect the kind of a file.
 * @param {string} filePath
 * @returns {Promise<{kind: FileKind, ext: string, size: number, label: string}>}
 */
export async function detectFileType(filePath) {
  const stat = await fs.stat(filePath);
  const ext = path.extname(filePath).toLowerCase();
  const name = path.basename(filePath).toLowerCase();
  if (stat.size === 0) return { kind: 'empty', ext, size: 0, label: 'Empty file' };

  const head = await readHead(filePath, 1024);
  const kind = (k, label) => ({ kind: k, ext, size: stat.size, label });

  if (head[0] === 0x4d && head[1] === 0x5a) {
    // MZ: confirm the PE signature when possible.
    if (head.length >= 0x40) {
      const lfanew = head.readUInt32LE(0x3c);
      if (lfanew + 4 <= head.length && head.toString('latin1', lfanew, lfanew + 4) === 'PE\0\0') {
        return kind('pe', 'Windows PE executable');
      }
    }
    return kind('pe', 'MZ executable (PE header not in first 1 KiB)');
  }
  if (head.length >= 4 && head.readUInt32BE(0) === 0x7f454c46) return kind('elf', 'ELF executable');
  if (head.length >= 4 && [0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe].includes(head.readUInt32BE(0))) {
    // 0xcafebabe is also Java class; extension disambiguates.
    return ext === '.class' ? kind('binary', 'Java class file') : kind('macho', 'Mach-O executable');
  }
  if (head[0] === 0x50 && head[1] === 0x4b && (head[2] === 0x03 || head[2] === 0x05) ) return kind('zip', 'ZIP archive');
  if (head.toString('latin1', 0, 6) === 'Rar!\x1a\x07') return kind('rar', 'RAR archive');
  if (head[0] === 0x1f && head[1] === 0x8b) return kind('gzip', 'GZIP stream');
  if (head.length >= 262 && head.toString('latin1', 257, 262) === 'ustar') return kind('tar', 'TAR archive');
  if (head.length >= 6 && head.toString('hex', 0, 6) === '377abcaf271c') return kind('7z', '7-Zip archive');
  if (looksLikeAsar(head)) return kind('asar', 'Electron ASAR archive');

  // ---- Formats unpacked through the 7-Zip WASM engine
  const hex = (n) => head.toString('hex', 0, n);
  if (hex(6) === 'fd377a585a00') return kind('xz', 'XZ stream');
  if (head.toString('latin1', 0, 3) === 'BZh' && head[3] >= 0x31 && head[3] <= 0x39) return kind('bz2', 'BZIP2 stream');
  if (hex(4) === '28b52ffd') return kind('zstd', 'Zstandard stream');
  if (head.toString('latin1', 0, 4) === 'MSCF') return kind('cab', 'Microsoft Cabinet archive');
  if (hex(8) === 'd0cf11e0a1b11ae1') return kind('ole', oleLabel(ext));
  if (head.toString('latin1', 0, 4) === 'ITSF') return kind('chm', 'Compiled HTML Help (CHM)');
  if (head.toString('latin1', 0, 8) === 'MSWIM\0\0\0') return kind('wim', 'Windows Imaging (WIM) archive');
  // LHA method id at offset 2: "-lh0-" .. "-lh7-", "-lhd-", "-lzs-", "-lz4-", "-lz5-".
  if (/^-l[hz][0-9a-z]-$/.test(head.toString('latin1', 2, 7))) return kind('lzh', 'LZH/LHA archive');
  if (head[0] === 0x60 && head[1] === 0xea) return kind('arj', 'ARJ archive');
  if (/^07070[127]/.test(head.toString('latin1', 0, 6))) return kind('cpio', 'CPIO archive');
  if (head.toString('latin1', 0, 8) === 'conectix' || head.toString('latin1', 0, 8) === 'vhdxfile') return kind('vhd', 'Virtual hard disk (VHD/VHDX)');
  if (await isIso(filePath, stat.size)) return kind('iso', 'ISO 9660 disk image');

  // ---- Documents and shortcuts with dedicated analyzers
  if (head.length >= 20 && head.readUInt32LE(0) === 0x4c && hex(20).slice(8) === '0114020000000000c000000000000046') return kind('lnk', 'Windows shortcut (LNK)');
  if (head.indexOf('%PDF-') !== -1 && head.indexOf('%PDF-') < 1024) return kind('pdf', 'PDF document');

  if (ext === '.json' || name === 'package.json') return kind('json', 'JSON document');
  if (SCRIPT_EXTENSIONS.has(ext)) return kind('script', `Script (${ext})`);
  if (looksLikeText(head)) return kind('text', 'Text file');
  if (PE_EXTENSIONS.has(ext)) return kind('binary', `Binary with PE extension but no MZ header`);
  return kind('binary', 'Unknown binary data');
}

function oleLabel(ext) {
  if (ext === '.msi' || ext === '.msp' || ext === '.mst') return 'Windows Installer package (MSI)';
  if (['.doc', '.dot', '.xls', '.xlt', '.ppt', '.pot', '.pps'].includes(ext)) return 'Office 97-2003 document (OLE)';
  if (ext === '.msg') return 'Outlook message (OLE)';
  if (ext === '.bin') return 'OLE compound file (VBA project)';
  return 'OLE compound file';
}

/** ISO 9660: "CD001" at sector 16 (+1), or 17/18 for some hybrid images. */
async function isIso(filePath, size) {
  if (size < 0x9006) return false;
  const fh = await fs.open(filePath, 'r');
  try {
    const buf = Buffer.alloc(5);
    for (const off of [0x8001, 0x8801, 0x9001]) {
      await fh.read(buf, 0, 5, off);
      if (buf.toString('latin1') === 'CD001') return true;
    }
    return false;
  } finally {
    await fh.close();
  }
}

/** Kinds unpacked by the built-in Node extractors. */
export const NODE_ARCHIVE_KINDS = new Set(['zip', 'rar', 'tar', 'gzip', 'asar']);
/** Kinds unpacked by the 7-Zip WASM engine (no native binary is executed). */
export const SEVENZIP_KINDS = new Set(['7z', 'xz', 'bz2', 'zstd', 'cab', 'ole', 'chm', 'wim', 'lzh', 'arj', 'cpio', 'vhd', 'iso']);

export function isArchiveKind(kind) {
  return NODE_ARCHIVE_KINDS.has(kind) || SEVENZIP_KINDS.has(kind);
}
