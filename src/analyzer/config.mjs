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
});

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
});

export const SCRIPT_EXTENSIONS = new Set([
  '.js', '.cjs', '.mjs', '.jsx', '.ts', '.tsx', '.py', '.pyw',
  '.ps1', '.psm1', '.psd1', '.bat', '.cmd', '.vbs', '.vbe', '.jse', '.wsf', '.wsh', '.sct', '.sh',
  '.html', '.htm', '.xhtml', '.hta', '.svg', '.mht', '.mhtml',
  '.vba', '.bas', '.cls', '.frm',
  '.reg', '.url', '.scf', '.inf', '.iqy', '.slk', '.library-ms', '.searchconnector-ms',
  '.xml', '.rels', '.xaml', '.config', '.manifest',
]);

export const PE_EXTENSIONS = new Set(['.exe', '.dll', '.sys', '.scr', '.cpl', '.ocx', '.node', '.drv', '.efi']);
