/**
 * Central safety limits and constants for REAP-Shield.
 * Every limit exists to keep a hostile input (zip bomb, deeply nested
 * archive, gigantic binary) from exhausting memory, disk or time.
 */
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));

/** Project root (two levels above src/analyzer). */
export const PROJECT_ROOT = path.resolve(here, '..', '..');

/** Default sandbox root. Override with REAP_SANDBOX_DIR. */
export const DEFAULT_SANDBOX_ROOT = process.env.REAP_SANDBOX_DIR
  ? path.resolve(process.env.REAP_SANDBOX_DIR)
  : path.join(PROJECT_ROOT, 'temp', 'sandbox');

export const LIMITS = Object.freeze({
  /** Largest input file accepted for scanning. */
  maxInputBytes: 1024 * 1024 * 1024, // 1 GiB
  /** Total bytes that may be written to one sandbox across all extractions. */
  maxExtractedTotalBytes: 2 * 1024 * 1024 * 1024, // 2 GiB
  /** Largest single extracted entry. */
  maxEntryBytes: 512 * 1024 * 1024, // 512 MiB
  /** Maximum number of extracted entries per scan. */
  maxEntries: 20000,
  /** Maximum archive nesting depth (archive inside archive inside ...). */
  maxNestingDepth: 4,
  /** Per-entry compression ratio that is treated as a zip bomb. */
  maxCompressionRatio: 250,
  /** RAR archives are decoded in memory (WASM), so they get a tighter cap. */
  maxRarBytes: 384 * 1024 * 1024,
  /** Bytes of each file read for string / IOC extraction. */
  maxStringScanBytes: 96 * 1024 * 1024,
  /** Bytes of each script read for script rules. */
  maxScriptBytes: 48 * 1024 * 1024,
  /** Maximum strings kept per file. */
  maxStringsPerFile: 250000,
  /** Maximum files that get the full analysis pass. */
  maxAnalyzedFiles: 5000,
  /** Timeout for one REA command. */
  reaTimeoutMs: 120000,
  /** Timeout for the REA deep (JavaScript application) analysis. */
  reaDeepTimeoutMs: 600000,
  /** Bytes of each file matched against YARA rules. */
  maxYaraScanBytes: 96 * 1024 * 1024,
  /** YARA-X timeout for one file. */
  yaraTimeoutMs: 15000,
  /** Matches kept per YARA pattern (evidence only; the rule result is unaffected). */
  yaraMaxMatchesPerPattern: 5,
  /** YARA findings kept per scan (a noisy rule set must not flood the report). */
  maxYaraFindings: 500,
});

/**
 * User-selectable "max file size" for the scanned file itself (in GB).
 * The default is LIMITS.maxInputBytes (1 GB). The archive-extraction budgets
 * above stay fixed regardless of this choice: they protect against archive bombs.
 */
export const MAX_SIZE_CHOICES_GB = Object.freeze([0.25, 0.5, 1, 2, 4, 8, 16]);
export const MAX_SIZE_MIN_GB = 0.05;
export const MAX_SIZE_MAX_GB = 16;
export const SAFE_SIZE_RANGE_NOTE =
  'Recommended: 1 GB. Safe range: 0.5-2 GB (almost all malware is under 200 MB). ' +
  'Larger limits work, but scans take longer, text and IoC search covers only the first 96 MB of each file, ' +
  'and data extracted from archives stays capped at 2 GB.';

/** Convert a GB value to bytes, or throw when it is outside the supported range. */
export function maxSizeGbToBytes(gb) {
  const n = Number(gb);
  if (!Number.isFinite(n) || n < MAX_SIZE_MIN_GB || n > MAX_SIZE_MAX_GB) {
    throw new Error(`Max file size must be between ${MAX_SIZE_MIN_GB} and ${MAX_SIZE_MAX_GB} GB.`);
  }
  return Math.round(n * 1024 * 1024 * 1024);
}

/** Human-readable size: "512 MB", "5.2 GB". */
export function formatBytes(bytes) {
  if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(bytes % 1024 ** 3 === 0 ? 0 : 1)} GB`;
  if (bytes >= 1024 ** 2) return `${Math.round(bytes / 1024 ** 2)} MB`;
  if (bytes >= 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${bytes} bytes`;
}

export const SEVERITIES = Object.freeze(['info', 'low', 'medium', 'high', 'critical']);

export const SEVERITY_WEIGHT = Object.freeze({
  info: 0,
  low: 3,
  medium: 8,
  high: 18,
  critical: 35,
});

/** Finding categories shown as accordion sections in the dashboard. */
export const CATEGORIES = Object.freeze({
  network: 'Network Indicators',
  imports: 'Suspicious Imports',
  fileops: 'File Operations',
  persistence: 'Persistence & Registry',
  execution: 'Code Execution',
  obfuscation: 'Obfuscation & Packing',
  credentials: 'Credential & Data Theft',
  evasion: 'Anti-Analysis & Evasion',
  electron: 'Electron & IPC Security',
  integrity: 'Signature & Integrity',
  archive: 'Archive & Container',
  yara: 'YARA Signature Matches',
  coverage: 'Scan Coverage & Limits',
});

/**
 * Why results become less reliable as files grow. Shown in the desktop app,
 * the CLI help and the README so the explanation stays in one place.
 */
export const LARGE_FILE_RELIABILITY = Object.freeze([
  'Partial reading: text and IoC search reads only the first 96 MB of each file (scripts: 48 MB, PE headers: 256 MB). In a 5 GB file that is under 2% of the content, so anything stored later is never examined.',
  'REA limit: REA inspects files up to 64 MB; larger executables get no REA evidence.',
  'Archive caps: RAR / 7z archives over 384 MB are not unpacked, single extracted entries over 512 MB are skipped and extraction stops at 2 GB in total, so the inside of big containers is only partly seen.',
  'Inflation trick: attackers pad malware with hundreds of MB of junk data on purpose, because many scanners skip or truncate large files. Size itself is a common evasion technique.',
  'Volume caps: very large installers and disk images can exceed the 5,000-file and 25-REA-file budgets, so later files get less or no analysis.',
  'Result: on large files a Low verdict is weaker evidence. Check the report\'s Scan Coverage section and, for anything important, inspect the file in an isolated virtual machine.',
]);

export const SCRIPT_EXTENSIONS = new Set([
  '.js', '.cjs', '.mjs', '.jsx', '.ts', '.tsx', '.py', '.pyw',
  '.ps1', '.psm1', '.psd1', '.bat', '.cmd', '.vbs', '.vbe', '.jse', '.wsf', '.wsh', '.sct', '.sh',
  '.html', '.htm', '.xhtml', '.hta', '.svg', '.mht', '.mhtml',
  '.vba', '.bas', '.cls', '.frm',
  '.reg', '.url', '.scf', '.inf', '.iqy', '.slk', '.library-ms', '.searchconnector-ms',
  '.xml', '.rels', '.xaml', '.config', '.manifest',
]);

export const PE_EXTENSIONS = new Set(['.exe', '.dll', '.sys', '.scr', '.cpl', '.ocx', '.node', '.drv', '.efi']);
