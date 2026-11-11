/**
 * REAP-Shield analysis pipeline.
 *
 *   input ─► sandbox ─► safe recursive extraction ─► inventory (type + hashes)
 *         ─► per-file analysis (PE, strings/IOC, scripts, Electron IPC)
 *         ─► REA evidence (PE imports, certificates, hardening, entropy, JS app)
 *         ─► scoring ─► structured JSON report
 *
 * The pipeline never executes the target or anything extracted from it.
 * Each stage is wrapped so that a malformed file produces an error entry in
 * the report instead of crashing the caller.
 */
import fs from 'node:fs/promises';
import path from 'node:path';
import { createRequire } from 'node:module';
import { CATEGORIES, LIMITS, SEVERITIES, SCRIPT_EXTENSIONS, formatBytes } from './config.mjs';
import { Sandbox, guard } from './sandbox.mjs';
import { detectFileType, isArchiveKind, headLooksTextual } from './fileType.mjs';
import { extractArchive, extract7z } from './extractors.mjs';
import { hashFile } from './hashing.mjs';
import { parsePE, parsePEBuffer } from './pe.mjs';
import { parseLnk, lnkFindings, analyzePdf, extractVbaSources } from './documents.mjs';
import { readCapped, extractStrings, scanIocs, decodeText } from './strings.mjs';
import { API_COMBOS, lookupApi } from './apiCatalog.mjs';
import { scanScript, scriptLang, looksLikeElectron, scriptShape } from './scripts.mjs';
import {
  locateRea,
  reaInspect,
  normaliseReaImports,
  compactEvidence,
  summariseReaCertificates,
  summariseReaHardening,
  summariseReaEntropy,
} from './rea.mjs';
import { verifyAuthenticodeMany } from './signature.mjs';
import { YARA_ENGINE, loadRules, createYaraScanner, yaraMatchToFinding } from './yara.mjs';
import { scoreFindings, summarise } from './scoring.mjs';

const require = createRequire(import.meta.url);
const pkg = require('../../package.json');

export const TOOL = { name: 'REAP-Shield', version: pkg.version };

/**
 * @typedef {object} ScanOptions
 * @property {boolean} [useRea=true]      Call REA tools when available.
 * @property {boolean} [deep=false]       Run heavy REA workflows (JavaScript app reconstruction).
 * @property {string}  [provider]         REA native provider for decompilation (e.g. "ghidra").
 * @property {boolean} [keepSandbox=false] Keep extracted files for manual review.
 * @property {boolean} [verifySignature=true] Windows Authenticode verification.
 * @property {boolean} [useYara=true]     Match files against installed YARA rules (YARA-X).
 * @property {string[]} [yaraRules]       Extra YARA rule files or folders for this scan.
 * @property {string}  [sandboxRoot]
 * @property {number}  [maxInputBytes] Largest file accepted (default 1 GB; user-selectable).
 * @property {(e: {stage:string, message:string, percent:number}) => void} [onProgress]
 * @property {(dir: string) => void} [onSandbox] Called with the sandbox directory once created.
 */

/**
 * Scan one file.
 * @param {string} inputPath
 * @param {ScanOptions} [options]
 */
export async function scanFile(inputPath, options = {}) {
  const opts = { useRea: true, deep: false, keepSandbox: false, verifySignature: true, useYara: true, ...options };
  /** Largest file accepted for scanning (user-selectable; see MAX_SIZE_CHOICES_GB). */
  const maxInputBytes = Number.isFinite(opts.maxInputBytes) && opts.maxInputBytes > 0 ? opts.maxInputBytes : LIMITS.maxInputBytes;
  const progress = (stage, message, percent) => {
    try {
      opts.onProgress?.({ stage, message, percent: Math.max(0, Math.min(100, Math.round(percent))) });
    } catch {
      /* a broken progress listener must not break the scan */
    }
  };
  const startedAt = new Date();
  const abs = path.resolve(inputPath);
  const findings = [];
  const errors = [];
  const archiveWarnings = [];

  progress('init', 'Validating input', 1);
  const stat = await fs.stat(abs).catch((err) => {
    throw new Error(err.code === 'ENOENT' ? `File not found: ${abs}` : `Cannot open ${abs}: ${err.code ?? err.message}`);
  });
  const isDir = stat.isDirectory();
  if (!isDir && !stat.isFile()) throw new Error(`Unsupported item (not a file or folder): ${abs}`);
  if (!isDir && stat.size > maxInputBytes) {
    throw new Error(
      `"${path.basename(abs)}" is ${formatBytes(stat.size)}, above the current max file size of ${formatBytes(maxInputBytes)}. ` +
        'Raise "Max file size" in the scan options (CLI: --max-size <GB>) to scan it.',
    );
  }

  const sandbox = await new Sandbox({ root: opts.sandboxRoot }).init();
  try {
    opts.onSandbox?.(sandbox.dir);
  } catch {
    /* listener errors are ignored */
  }
  const onExit = () => sandbox.cleanupSync();
  if (!opts.keepSandbox) process.once('exit', onExit);

  /** @type {Array<{abs:string, rel:string, depth:number, type?:any, hashes?:any}>} */
  const inventory = [];
  try {
    // ------------------------------------------------ extraction + inventory
    progress('extract', isDir ? 'Listing folder contents' : 'Inspecting container structure', 4);
    let queue = [{ abs, rel: path.basename(abs), depth: 0 }];
    let folderBytes = 0;
    if (isDir) {
      // Folders are read in place (nothing is copied); only archives inside them are
      // extracted into the sandbox. Symlinks and junctions are never followed.
      const walk = await walkDirectory(abs, LIMITS.maxAnalyzedFiles, maxInputBytes);
      folderBytes = walk.bytes;
      queue = walk.files.map((f) => ({ abs: f.abs, rel: `${path.basename(abs)}/${f.rel}`, depth: 0 }));
      if (walk.links) archiveWarnings.push(`${walk.links} symbolic link(s) / junction(s) were not followed.`);
      if (walk.skippedLarge) archiveWarnings.push(`${walk.skippedLarge} file(s) larger than the ${formatBytes(maxInputBytes)} max file size were skipped (raise "Max file size" to include them).`);
      if (walk.truncated) archiveWarnings.push(`The folder holds more than ${LIMITS.maxAnalyzedFiles} files; only the first ${LIMITS.maxAnalyzedFiles} were analyzed.`);
      if (walk.errors.length) errors.push(...walk.errors.slice(0, 50));
      if (queue.length === 0) archiveWarnings.push('The folder contains no readable files.');
    }
    let archiveIndex = 0;
    while (queue.length > 0) {
      if (inventory.length >= LIMITS.maxAnalyzedFiles) {
        archiveWarnings.push(`More than ${LIMITS.maxAnalyzedFiles} files; the rest were not analyzed.`);
        break;
      }
      const item = queue.shift();
      const typeRes = await guard(`Type detection failed for ${item.rel}`, () => detectFileType(item.abs));
      if (!typeRes.ok) {
        errors.push(typeRes.error);
        continue;
      }
      item.type = typeRes.value;
      inventory.push(item);
      // Payloads hidden inside executables and documents become nested items too.
      if ((item.type.kind === 'pe' || item.type.kind === 'pdf') && item.depth < LIMITS.maxNestingDepth) {
        archiveIndex += 1;
        const dest = path.join(sandbox.dir, `c${archiveIndex}-${safeLabel(path.basename(item.abs))}`);
        const carve = await guard(`Payload carving failed for ${item.rel}`, () =>
          item.type.kind === 'pe' ? carvePe(item, dest, sandbox, findings) : carvePdf(item, dest, sandbox),
        );
        if (!carve.ok) errors.push(carve.error);
        else {
          archiveWarnings.push(...carve.value.warnings.map((w) => `${item.rel}: ${w}`));
          for (const child of carve.value.children) queue.push({ abs: child.abs, rel: `${item.rel}!/${child.name}`, depth: item.depth + 1 });
        }
      }
      if (!isArchiveKind(item.type.kind)) continue;
      if (item.depth >= LIMITS.maxNestingDepth) {
        findings.push(mk('archive.nesting', 'archive', 'medium', 'Excessive archive nesting', `Archive nesting deeper than ${LIMITS.maxNestingDepth} levels is a common evasion technique; deeper levels were not unpacked.`, item.rel));
        continue;
      }
      archiveIndex += 1;
      progress('extract', `Extracting ${item.rel}`, 5 + Math.min(15, archiveIndex));
      const dest = path.join(sandbox.dir, `x${archiveIndex}-${safeLabel(path.basename(item.abs))}`);
      const ex = await guard(`Extraction failed for ${item.rel}`, () => extractArchive(item.type.kind, item.abs, dest, sandbox));
      if (!ex.ok) {
        errors.push(ex.error);
        findings.push(mk('archive.malformed', 'archive', ex.limit ? 'high' : 'low', ex.limit ? 'Archive exceeded safety limits' : 'Malformed or unreadable archive', ex.error, item.rel));
        continue;
      }
      const { files, warnings, stats } = ex.value;
      item.unpacked = files.length > 0;
      archiveWarnings.push(...warnings.map((w) => `${item.rel}: ${w}`));
      if (stats.truncated > 0) findings.push(mk('archive.truncated', 'archive', 'high', 'Archive only partly unpacked (safety limit reached)', `Extraction stopped at a sandbox limit (${LIMITS.maxEntries} entries, ${formatBytes(LIMITS.maxExtractedTotalBytes)} in total). The remaining entries were not inspected, so they may hide content from this scan.`, item.rel));
      if (stats.oversized > 0) findings.push(mk('archive.oversized-entry', 'archive', 'medium', 'Oversized archive entries were not inspected', `${stats.oversized} entr${stats.oversized === 1 ? 'y is' : 'ies are'} larger than the ${formatBytes(LIMITS.maxEntryBytes)} per-file limit and ${stats.oversized === 1 ? 'was' : 'were'} skipped; the other entries were unpacked and scanned.`, item.rel));
      if (stats.unsafePaths > 0) findings.push(mk('archive.path-traversal', 'archive', 'high', 'Path traversal entries in archive', `${stats.unsafePaths} entr${stats.unsafePaths === 1 ? 'y tries' : 'ies try'} to write outside the extraction folder (zip-slip). They were blocked.`, item.rel));
      if (stats.encrypted > 0) findings.push(mk('archive.encrypted', 'archive', 'medium', 'Password-protected content', `${stats.encrypted} encrypted entr${stats.encrypted === 1 ? 'y' : 'ies'} could not be inspected. Malware is often shipped in password-protected archives to evade scanners.`, item.rel));
      if (stats.bombSuspects > 0) findings.push(mk('archive.bomb', 'archive', 'high', 'Decompression bomb characteristics', `${stats.bombSuspects} entr${stats.bombSuspects === 1 ? 'y has' : 'ies have'} an extreme compression ratio and were skipped.`, item.rel));
      if (stats.symlinks > 0) findings.push(mk('archive.symlinks', 'archive', 'low', 'Symbolic links in archive', `${stats.symlinks} link entr${stats.symlinks === 1 ? 'y was' : 'ies were'} skipped.`, item.rel));
      for (const f of files) {
        const childRel = `${item.rel}!/${path.relative(dest, f).split(path.sep).join('/')}`;
        queue.push({ abs: f, rel: childRel, depth: item.depth + 1 });
      }
    }

    progress('inventory', `Hashing ${inventory.length} file(s)`, 22);
    for (const [i, item] of inventory.entries()) {
      const h = await guard(`Hashing failed for ${item.rel}`, () => hashFile(item.abs));
      if (h.ok) item.hashes = h.value;
      else errors.push(h.error);
      if (i % 25 === 0) progress('inventory', `Hashing ${i + 1}/${inventory.length}`, 22 + (8 * i) / inventory.length);
    }
    detectDoubleExtensions(inventory, findings);
    findings.push(...officeContainerFindings(inventory));

    // ------------------------------------------------ Electron context
    const electronApp = inventory.some((it) => it.type.kind === 'asar') || (await hasElectronManifest(inventory));

    // ------------------------------------------------ per-file analysis
    const reaRuns = [];
    const reaLoc = opts.useRea ? locateRea() : { kind: 'disabled', source: 'REA disabled by option' };
    const reaAvailable = reaLoc.kind === 'node-script' || reaLoc.kind === 'binary';
    // Authenticode for every PE in one batched PowerShell process (Windows only).
    let signatures = new Map();
    // Authenticode also covers MSI / CAB packages and PowerShell scripts at the top level.
    const rootItem = isDir ? null : inventory[0];
    const rootSignable = rootItem && rootItem.type.kind !== 'pe' && (['ole', 'cab'].includes(rootItem.type.kind) || ['.msi', '.msp', '.cab', '.ps1', '.psm1', '.vbs', '.js'].includes(rootItem.type.ext));
    if (opts.verifySignature) {
      const pes = inventory.filter((it) => it.type.kind === 'pe').slice(0, 1000);
      if (pes.length) progress('analyze', `Verifying signatures of ${pes.length} executable(s)`, 30);
      signatures = await verifyAuthenticodeMany([...(rootSignable ? [rootItem.abs] : []), ...pes.map((it) => it.abs)].map((p) => path.resolve(p))).catch(() => new Map());
    }
    let trustedSignature = false;
    if (rootSignable && signatures.has(path.resolve(rootItem.abs))) {
      const sig = signatures.get(path.resolve(rootItem.abs));
      if (sig.status !== 'NotSigned') {
        const f = signatureFinding(sig, rootItem.rel, true);
        if (f) findings.push(f);
      }
      if (sig.status === 'Valid') trustedSignature = true;
    }
    const peCount = inventory.filter((x) => x.type.kind === 'pe').length;
    /** Files whose Authenticode signature Windows reports as Valid. */
    const signedFiles = new Set();
    /** REA spawns several processes per PE; cap how many PE files get the REA pass. */
    let reaPeBudget = 25;
    const fileSummaries = [];

    /** Script / markup / text rules + IoC search. `textKind` is 'script', 'json' or 'text'. */
    const analyzeText = async (item, summary, textKind) => {
      const { buf, truncated } = await readCapped(item.abs, LIMITS.maxScriptBytes);
      // BOM-aware: PowerShell, batch and Windows Script Host files are often UTF-16.
      const text = decodeText(buf);
      const ext = item.type.ext;
      const lang = textKind === 'text' ? 'other' : scriptLang(ext);
      const shape = scriptShape(text);
      summary.script = { lang, lines: shape.lines, minified: shape.minified, truncated };
      const ctx = { electron: electronApp || looksLikeElectron(text) };
      pushScriptHits(findings, scanScript(text, lang, ctx), item.rel);
      findings.push(...iocFindings(scanIocs(text), item.rel));
      if (['.jse', '.vbe'].includes(ext) || /#@~\^/.test(text.slice(0, 4096))) {
        findings.push(mk('script.encoded-file', 'obfuscation', 'high', 'Encoded Windows script file', 'JSE / VBE files are encoded with the Microsoft Script Encoder; legitimate software almost never ships them.', item.rel));
      }
    };
    /** True when a file that merely starts with a container / executable magic is really text. */
    const reallyText = async (item) => SCRIPT_EXTENSIONS.has(item.type.ext) || (await headLooksTextual(item.abs).catch(() => false));

    for (const [i, item] of inventory.entries()) {
      const pct = 30 + (55 * i) / Math.max(1, inventory.length);
      let kind = item.type.kind;
      const summary = { rel: item.rel, kind, label: item.type.label, size: item.type.size, depth: item.depth, ...pickHashes(item.hashes) };
      fileSummaries.push(summary);
      if (kind === 'empty') continue;
      if (isArchiveKind(kind)) {
        if (item.unpacked) continue;
        // Nothing came out of it (corrupt, encrypted, too deeply nested, or a script that only
        // starts with archive magic bytes so that scanners treat it as a broken archive):
        // analyze the raw bytes instead of skipping the file unseen.
        kind = (await reallyText(item)) ? 'script' : 'binary';
        summary.analyzedAs = kind;
      }

      progress('analyze', `Analyzing ${item.rel}`, pct);

      if (kind === 'pe') {
        const res = await guard(`PE analysis failed for ${item.rel}`, async () => {
          const pe = await parsePE(item.abs);
          summary.pe = peSummary(pe);
          findings.push(...peFindings(pe, item.rel));
          // "MZ" followed by script text is not an executable: cmd.exe and the script hosts
          // skip the bogus first line and run the rest, so apply the script rules to it.
          if (!pe.valid && (await reallyText(item))) {
            summary.analyzedAs = 'script';
            await analyzeText(item, summary, 'script');
            return;
          }
          let imports = pe.imports;

          if (reaAvailable && reaPeBudget > 0) {
            reaPeBudget -= 1;
            progress('rea', `REA: inspecting ${item.rel}`, pct);
            const runs = await reaInspect(item.abs, 'pe', { deep: opts.deep, provider: opts.provider, workDir: sandbox.dir });
            for (const r of runs) reaRuns.push(reaRecord(r, item.rel));
            const [importsRun, certRun, hardeningRun, entropyRun] = runs;
            const reaImports = importsRun?.ok ? normaliseReaImports(importsRun.json) : null;
            if (reaImports && reaImports.length) {
              imports = mergeImports(imports, reaImports);
              summary.reaImportsMerged = true;
            }
            summary.rea = {
              certificates: certRun?.ok ? summariseReaCertificates(certRun.json) : null,
              hardening: hardeningRun?.ok ? summariseReaHardening(hardeningRun.json) : null,
              entropy: entropyRun?.ok ? summariseReaEntropy(entropyRun.json) : null,
            };
            const highRuns = summary.rea.entropy?.highRuns ?? 0;
            if (highRuns >= 64) {
              findings.push({ ...mk('rea.entropy-runs', 'obfuscation', 'low', 'Many high-entropy regions (REA)', `REA byte-entropy analysis found ${highRuns} high-entropy runs; compressed or encrypted payload data is embedded in the image.`, item.rel), source: 'rea' });
            }
          }

          const { buf } = await readCapped(item.abs, LIMITS.maxStringScanBytes);
          const strs = extractStrings(buf);
          summary.strings = strs.total;
          const corpus = strs.ascii.join('\n') + '\n' + strs.unicode.join('\n');
          findings.push(...apiFindings(imports, corpus, item.rel));
          findings.push(...iocFindings(scanIocs(corpus), item.rel));

          if (opts.verifySignature) {
            const sig = signatures.get(path.resolve(item.abs)) ?? null;
            if (sig) {
              summary.signature = sig;
              const f = signatureFinding(sig, item.rel, item.depth === 0 || peCount === 1);
              if (f) findings.push(f);
              if (sig.status === 'Valid') {
                signedFiles.add(item.rel);
                // Only a single signed target lowers the overall score, never one file in a folder.
                if (item.abs === abs) trustedSignature = true;
              }
            } else if (!pe.certificate.present) {
              findings.push(mk('integrity.unsigned', 'integrity', 'medium', 'Executable is not digitally signed', 'No Authenticode security directory is present. Most legitimate commercial software is signed.', item.rel));
            }
          }
        });
        if (!res.ok) errors.push(res.error);
        continue;
      }

      if (kind === 'script' || kind === 'json' || kind === 'text') {
        const res = await guard(`Script analysis failed for ${item.rel}`, () => analyzeText(item, summary, kind));
        if (!res.ok) errors.push(res.error);
        continue;
      }

      if (kind === 'lnk') {
        const res = await guard(`Shortcut analysis failed for ${item.rel}`, async () => {
          const { buf } = await readCapped(item.abs, 4 * 1024 * 1024);
          const lnk = parseLnk(buf);
          summary.lnk = { target: lnk.target, args: lnk.args?.slice(0, 2000) ?? null, workingDir: lnk.workingDir, icon: lnk.icon };
          for (const f of lnkFindings(lnk)) findings.push({ ...mk(f.ruleId, f.category, f.severity, f.title, f.description, item.rel), evidence: f.evidence });
          const commandLine = `${lnk.target ?? ''} ${lnk.args ?? ''}`;
          pushScriptHits(findings, scanScript(commandLine, 'bat', { electron: false }), item.rel);
          const strs = extractStrings(buf);
          findings.push(...iocFindings(scanIocs(`${commandLine}\n${strs.ascii.join('\n')}\n${strs.unicode.join('\n')}`), item.rel));
        });
        if (!res.ok) errors.push(res.error);
        continue;
      }

      if (kind === 'pdf') {
        const res = await guard(`PDF analysis failed for ${item.rel}`, async () => {
          const pdf = item.pdf ?? analyzePdf((await readCapped(item.abs, LIMITS.maxStringScanBytes)).buf);
          summary.pdf = { streams: pdf.streams, keywords: pdf.keywords, embeddedFiles: pdf.embedded.length, encrypted: pdf.encrypted };
          for (const f of pdf.findings) findings.push({ ...mk(f.ruleId, f.category, f.severity, f.title, f.description, item.rel), evidence: f.evidence, occurrences: f.occurrences });
          if (pdf.decodedText) {
            pushScriptHits(findings, scanScript(pdf.decodedText, 'js', { electron: false }), item.rel, 'decoded stream');
            findings.push(...iocFindings(scanIocs(pdf.decodedText), item.rel));
          }
          const { buf } = await readCapped(item.abs, LIMITS.maxStringScanBytes);
          findings.push(...iocFindings(scanIocs(buf.toString('latin1')), item.rel));
        });
        if (!res.ok) errors.push(res.error);
        continue;
      }

      // ELF, Mach-O, OLE streams and unknown binary blobs: strings + IOC + VBA macros
      // (+ REA hardening for native images).
      const res = await guard(`Binary analysis failed for ${item.rel}`, async () => {
        const { buf } = await readCapped(item.abs, LIMITS.maxStringScanBytes);
        const strs = extractStrings(buf);
        summary.strings = strs.total;
        findings.push(...iocFindings(scanIocs(strs.ascii.join('\n') + '\n' + strs.unicode.join('\n')), item.rel));
        const vba = extractVbaSources(buf);
        if (vba.length > 0) {
          summary.vbaModules = vba.length;
          const source = vba.join('\n\n');
          findings.push({
            ...mk('office.vba-source', 'execution', 'info', 'VBA macro source recovered', `${vba.length} compressed VBA module(s) were decompressed and scanned.`, item.rel),
            evidence: vba.map((v) => (/Attribute VB_Name = "([^"]+)"/.exec(v)?.[1] ?? 'module')).slice(0, 20),
          });
          pushScriptHits(findings, scanScript(source, 'vba', { electron: false }), item.rel);
          findings.push(...iocFindings(scanIocs(source), item.rel));
          const auto = findings.some((f) => f.file === item.rel && f.ruleId === 'vba.autoexec');
          const action = findings.some((f) => f.file === item.rel && ['vba.shell', 'vba.download', 'vba.win32-api'].includes(f.ruleId));
          if (auto && action) {
            findings.push(mk('vba.autoexec-dropper', 'execution', 'critical', 'Auto-executing macro that runs or downloads code', 'The macro starts automatically and executes commands, downloads content or calls Windows APIs: the standard malicious-document pattern.', item.rel));
          }
        }
        if (item.hashes && item.hashes.entropy > 7.6 && item.type.size > 64 * 1024 && item.type.kind === 'binary') {
          findings.push(mk('obfuscation.encrypted-blob', 'obfuscation', 'low', 'High-entropy data blob', `Entropy ${item.hashes.entropy.toFixed(2)} bits/byte: the file is compressed or encrypted (possibly an encrypted payload).`, item.rel));
        }
        if (reaAvailable && (kind === 'elf' || kind === 'macho')) {
          const runs = await reaInspect(item.abs, kind, { deep: opts.deep, provider: opts.provider, workDir: sandbox.dir });
          for (const r of runs) reaRuns.push(reaRecord(r, item.rel));
        }
      });
      if (!res.ok) errors.push(res.error);
    }

    // Deep REA JavaScript reconstruction for ASAR containers.
    if (reaAvailable && opts.deep) {
      for (const item of inventory.filter((x) => x.type.kind === 'asar')) {
        progress('rea', `REA: reconstructing JavaScript application ${item.rel}`, 86);
        const res = await guard(`REA JavaScript reconstruction failed for ${item.rel}`, () => reaInspect(item.abs, 'asar', { deep: true, workDir: sandbox.dir }));
        if (!res.ok) errors.push(res.error);
        else for (const r of res.value) reaRuns.push(reaRecord(r, item.rel));
      }
    }

    // ------------------------------------------------ YARA-X signatures
    const yara = await runYara(inventory, opts, findings, errors, progress);

    if (electronApp) findings.push(...electronSummaryFindings(findings, inventory, isDir ? path.basename(abs) : inventory[0]?.rel ?? ""));

    // ------------------------------------------------ scoring + report
    progress('score', 'Scoring findings', 92);
    // Validly signed binaries legitimately import "dangerous" APIs (system DLLs, AV, drivers).
    // Downgrade their findings one level, and import-only capability combinations two levels.
    // Critical indicators that are behaviour rather than capability (webhooks, ransomware
    // commands, shellcode loaders) stay critical: malware signed with stolen certificates exists.
    for (const f of findings) {
      if (!signedFiles.has(f.file) || f.category === 'integrity' || f.severity === 'info') continue;
      const capabilityOnly = f.ruleId.startsWith('combo.') || f.ruleId.startsWith('imports.');
      if (f.severity === 'critical' && !capabilityOnly) continue;
      const steps = capabilityOnly && f.ruleId.startsWith('combo.') ? 2 : 1;
      const from = SEVERITIES.indexOf(f.severity);
      const to = Math.max(1, from - steps);
      if (to >= from) continue; // already at the floor ("low"): nothing was lowered
      f.severity = SEVERITIES[to];
      f.description += ` (Severity lowered ${from - to === 1 ? 'one level' : `${from - to} levels`}: the file carries a valid Authenticode signature.)`;
      f.signedDowngrade = true;
    }
    const coverage = assessCoverage(inventory, findings);
    const deduped = dedupe(findings);
    deduped.sort((a, b) => SEVERITIES.indexOf(b.severity) - SEVERITIES.indexOf(a.severity) || a.category.localeCompare(b.category));
    const verdict = scoreFindings(deduped.filter((f) => f.severity !== 'info'), { trustedSignature });
    let summaryText = summarise(verdict.level, deduped);
    if (!coverage.complete) {
      summaryText += ` Coverage note: ${coverage.partialFiles.length} large file(s) were only partly examined, so this result is weaker evidence than usual.`;
    }
    const root = isDir ? null : inventory[0];
    const topLevelFiles = inventory.filter((it) => it.depth === 0).length;
    const finishedAt = new Date();

    const report = {
      schema: 'reap-shield/report@1',
      tool: TOOL,
      scanId: sandbox.id,
      startedAt: startedAt.toISOString(),
      finishedAt: finishedAt.toISOString(),
      durationMs: finishedAt - startedAt,
      target: {
        name: path.basename(abs),
        path: abs,
        size: isDir ? folderBytes : stat.size,
        kind: isDir ? 'directory' : root?.type.kind,
        label: isDir ? `Folder (${topLevelFiles} file${topLevelFiles === 1 ? '' : 's'})` : root?.type.label,
        ...pickHashes(root?.hashes),
        entropy: root?.hashes?.entropy,
      },
      verdict: { ...verdict, summary: summaryText, electronApp },
      coverage,
      counts: countBy(deduped),
      categories: CATEGORIES,
      findings: deduped.map((f, idx) => ({ ...f, id: `F${String(idx + 1).padStart(3, '0')}` })),
      files: fileSummaries,
      archive: { extractedFiles: inventory.filter((it) => it.depth > 0).length, warnings: archiveWarnings.slice(0, 500) },
      rea: {
        available: reaAvailable,
        source: reaLoc.source,
        runs: reaRuns,
      },
      yara,
      sandbox: { dir: sandbox.dir, kept: opts.keepSandbox },
      limits: { maxFileBytes: maxInputBytes },
      errors,
      disclaimer: 'Static analysis only. A low score does not guarantee a file is safe; always run unknown software in an isolated virtual machine.',
    };
    progress('done', `Scan complete: ${verdict.level} (${verdict.score}/100)`, 100);
    return report;
  } finally {
    if (!opts.keepSandbox) {
      await sandbox.cleanup();
      process.removeListener('exit', onExit);
    }
  }
}

// =================================================================== helpers

/**
 * Match every inventoried file (archives included: some rules target containers)
 * against the installed YARA rules. Returns the report's "yara" section.
 */
async function runYara(inventory, opts, findings, errors, progress) {
  const section = { enabled: !!opts.useYara, engine: `${YARA_ENGINE.name} ${YARA_ENGINE.version}`, ruleCount: 0, sources: [], scannedFiles: 0, matchedFiles: 0, matches: 0, compileMs: 0, scanMs: 0, timeouts: 0, note: null };
  if (!opts.useYara) {
    section.note = 'YARA matching was turned off for this scan.';
    return section;
  }
  progress('yara', 'YARA: compiling rules', 86);
  let loaded;
  try {
    loaded = await loadRules({ extraPaths: opts.yaraRules ?? [] });
  } catch (err) {
    errors.push(`YARA rules could not be loaded: ${err.message}`);
    section.note = 'YARA rules could not be loaded.';
    return section;
  }
  section.sources = loaded.sources.map(({ name, kind, rules, ok, error }) => ({ name, kind, rules, ok, ...(error ? { error } : {}) }));
  section.compileMs = loaded.compileMs;
  section.cachedRules = loaded.cached;
  for (const s of loaded.sources.filter((x) => !x.ok)) errors.push(`YARA rule file ${s.name} was skipped: ${s.error}`);
  if (!loaded.rules) {
    section.note = loaded.sources.length
      ? 'No YARA rule file compiled successfully.'
      : 'No YARA rules are installed. Download the YARA Forge rules in the app or run "reap-shield rules update".';
    return section;
  }
  section.ruleCount = loaded.ruleCount;
  const scanner = createYaraScanner(loaded.rules);
  const started = Date.now();
  let kept = 0;
  try {
    const items = inventory.filter((it) => it.type?.kind !== 'empty');
    for (const [i, item] of items.entries()) {
      if (i % 10 === 0) progress('yara', `YARA: matching ${loaded.ruleCount} rules against ${item.rel}`, 86 + (5 * i) / Math.max(1, items.length));
      const res = await guard(`YARA matching failed for ${item.rel}`, async () => {
        const { buf } = await readCapped(item.abs, LIMITS.maxYaraScanBytes);
        section.scannedFiles += 1;
        const matches = scanner.scan(buf);
        if (matches.length) section.matchedFiles += 1;
        section.matches += matches.length;
        for (const m of matches) {
          if (kept >= LIMITS.maxYaraFindings) break;
          findings.push(yaraMatchToFinding(m, buf, item.rel));
          kept += 1;
        }
      });
      if (!res.ok) {
        if (/timeout/i.test(res.error)) section.timeouts += 1;
        errors.push(res.error);
      }
    }
  } finally {
    // The compiled rules stay cached in this process for the next scan.
    scanner.free();
  }
  section.scanMs = Date.now() - started;
  if (section.matches > kept) section.note = `${section.matches} rule matches; only the first ${LIMITS.maxYaraFindings} are listed as findings.`;
  return section;
}

function mk(ruleId, category, severity, title, description, file) {
  return { ruleId, category, severity, title, description, file, source: 'reap-shield', evidence: [] };
}

/**
 * How much of each analyzed file was actually examined. Large files are read
 * only partially (see LIMITS), which weakens a clean result; this is recorded in
 * the report and surfaced as findings. Also flags executables inflated with
 * padding, a technique used to slip past size-limited scanners.
 */
function assessCoverage(inventory, findings) {
  const partialFiles = [];
  for (const it of inventory) {
    const kind = it.type?.kind;
    if (!kind || kind === 'empty' || isArchiveKind(kind)) continue;
    const limit = kind === 'script' || kind === 'json' || kind === 'text' ? LIMITS.maxScriptBytes : kind === 'lnk' ? 4 * 1024 * 1024 : LIMITS.maxStringScanBytes;
    const size = it.type.size;
    if (size > limit) {
      const percent = Math.max(0.1, Math.round((limit / size) * 1000) / 10);
      partialFiles.push({ rel: it.rel, size, examinedBytes: limit, percent });
    }
    // Large executable that is mostly padding: whole-file entropy far below normal code.
    if (kind === 'pe' && size > 100 * 1024 * 1024 && it.hashes && it.hashes.entropy < 1.5) {
      findings.push({
        ...mk('evasion.inflated-file', 'evasion', 'medium', 'Executable inflated with padding', `This ${formatBytes(size)} executable is mostly filler data (whole-file entropy ${it.hashes.entropy.toFixed(2)} bits/byte). Malware is padded like this so that size-limited scanners skip or truncate it.`, it.rel),
        evidence: [`Size: ${formatBytes(size)}`, `Entropy: ${it.hashes.entropy.toFixed(2)}`],
      });
    }
  }
  if (partialFiles.length > 0) {
    findings.push({
      ...mk('coverage.partial', 'coverage', 'info', 'Large file(s) only partly examined', 'Text, IoC and script analysis reads only the beginning of very large files. Indicators stored later in these files were not examined, so a clean result here is weaker evidence. Inspect important large files in an isolated virtual machine.', partialFiles[0].rel),
      evidence: partialFiles.slice(0, 20).map((p) => `${p.rel}: ${formatBytes(p.examinedBytes)} of ${formatBytes(p.size)} examined (${p.percent}%)`),
      occurrences: partialFiles.length,
    });
  }
  return { complete: partialFiles.length === 0, partialFiles: partialFiles.slice(0, 200) };
}

/**
 * List the regular files under a folder without following symlinks or
 * junctions. ".git" metadata folders are skipped.
 */
async function walkDirectory(root, maxFiles, maxBytes) {
  const out = { files: [], bytes: 0, links: 0, skippedLarge: 0, truncated: false, errors: [] };
  const stack = [''];
  while (stack.length > 0) {
    const rel = stack.pop();
    let entries;
    try {
      entries = await fs.readdir(path.join(root, rel), { withFileTypes: true });
    } catch (err) {
      out.errors.push(`Cannot read folder ${rel || '.'}: ${err.code ?? err.message}`);
      continue;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const childRel = rel ? `${rel}/${entry.name}` : entry.name;
      if (entry.isSymbolicLink()) {
        out.links += 1;
      } else if (entry.isDirectory()) {
        if (entry.name !== '.git') stack.push(childRel);
      } else if (entry.isFile()) {
        if (out.files.length >= maxFiles) {
          out.truncated = true;
          return out;
        }
        const full = path.join(root, childRel);
        const st = await fs.stat(full).catch(() => null);
        if (!st) continue;
        if (st.size > maxBytes) {
          out.skippedLarge += 1;
          continue;
        }
        out.bytes += st.size;
        out.files.push({ abs: full, rel: childRel });
      }
    }
  }
  return out;
}

function pushScriptHits(findings, hits, file, where) {
  for (const hit of hits) {
    findings.push({
      ...mk(hit.rule.id, hit.rule.category, hit.rule.severity, hit.rule.title, hit.rule.description, file),
      occurrences: hit.count,
      evidence: hit.samples.map((s) => `${where ? `${where} ` : ''}L${s.line}: ${s.text}`),
    });
  }
}

const OVERLAY_MAGIC = [
  ['377abcaf271c', '7z', '7-Zip'],
  ['526172211a07', 'rar', 'RAR'],
  ['504b0304', 'zip', 'ZIP'],
  ['4d534346', 'cab', 'CAB'],
  ['1f8b', 'gz', 'GZIP'],
];

/**
 * Carve payloads out of a PE: NSIS installer contents, archives appended as an
 * overlay (SFX droppers) and complete PE images embedded inside the file.
 */
async function carvePe(item, dest, sandbox, findings) {
  const children = [];
  const warnings = [];
  const { buf } = await readCapped(item.abs, LIMITS.maxStringScanBytes);
  const pe = parsePEBuffer(buf, item.type.size);
  if (!pe.valid) return { children, warnings };

  // NSIS installers: 7-Zip's Nsis handler decodes the installer data and script.
  const nsis = pe.packers.includes('NSIS installer') || buf.indexOf('Nullsoft.NSIS') !== -1;
  if (nsis) {
    const res = await guard('NSIS extraction', () => extract7z(item.abs, path.join(dest, 'nsis'), sandbox, 'Nsis'));
    if (res.ok && res.value.files.length) {
      warnings.push(...res.value.warnings);
      for (const f of res.value.files) children.push({ abs: f, name: `[nsis]/${path.relative(path.join(dest, 'nsis'), f).split(path.sep).join('/')}` });
      findings.push(mk('archive.installer-payload', 'archive', 'info', 'Installer payload unpacked', `NSIS installer: ${res.value.files.length} file(s) were extracted from the installer data and scanned.`, item.rel));
    } else if (!res.ok) warnings.push(res.error);
  }

  // Archive appended after the last section (self-extracting archives, droppers).
  // The magic-byte check keeps this precise, so even tiny appended archives are carved.
  if (!nsis && pe.overlay.present && pe.overlay.size >= 64) {
    const head = buf.subarray(pe.overlay.offset, pe.overlay.offset + 8).toString('hex');
    const hit = OVERLAY_MAGIC.find(([magic]) => head.startsWith(magic));
    if (hit) {
      const fh = await fs.open(item.abs, 'r');
      try {
        const size = Math.min(pe.overlay.size, LIMITS.maxEntryBytes);
        const data = Buffer.alloc(size);
        await fh.read(data, 0, size, pe.overlay.offset);
        const target = sandbox.safeJoin(dest, `overlay.${hit[1]}`);
        children.push({ abs: await sandbox.writeBuffer(target, data), name: `[overlay].${hit[1]}` });
      } finally {
        await fh.close();
      }
      findings.push({
        ...mk('archive.overlay-payload', 'archive', 'medium', `${hit[2]} archive appended to executable`, 'An archive is stored in the PE overlay (self-extracting archive or dropper). It was carved out and scanned.', item.rel),
        evidence: [`Overlay offset 0x${pe.overlay.offset.toString(16)}, ${pe.overlay.size} bytes`],
      });
    }
  }

  // Complete PE images embedded elsewhere in the file (resources, data sections).
  const offsets = [];
  let pos = buf.indexOf('MZ', 2);
  let candidates = 0;
  while (pos !== -1 && offsets.length < 8 && candidates < 20000) {
    candidates += 1;
    if (pos + 0x40 <= buf.length) {
      const lfanew = buf.readUInt32LE(pos + 0x3c);
      if (lfanew >= 0x40 && lfanew < 0x1000 && pos + lfanew + 4 <= buf.length && buf.toString('latin1', pos + lfanew, pos + lfanew + 4) === 'PE\0\0') {
        const sub = parsePEBuffer(buf.subarray(pos), buf.length - pos);
        const end = sub.valid ? Math.max(...sub.sections.map((s) => s.rawPtr + s.rawSize), 0) : 0;
        if (end >= 1024 && pos + end <= buf.length) {
          offsets.push(pos);
          const target = sandbox.safeJoin(dest, `embedded-0x${pos.toString(16)}.${sub.isDll ? 'dll' : 'exe'}`);
          children.push({ abs: await sandbox.writeBuffer(target, buf.subarray(pos, pos + end)), name: `[embedded-pe@0x${pos.toString(16)}].${sub.isDll ? 'dll' : 'exe'}` });
          pos = buf.indexOf('MZ', pos + end);
          continue;
        }
      }
    }
    pos = buf.indexOf('MZ', pos + 2);
  }
  if (offsets.length) {
    findings.push({
      ...mk('obfuscation.embedded-pe', 'obfuscation', 'medium', 'Executable embedded inside another executable', 'Complete PE images are stored inside this file (droppers and loaders carry their payload this way; installers do it legitimately). Each one was carved out and scanned.', item.rel),
      evidence: offsets.map((o) => `PE image at offset 0x${o.toString(16)}`),
    });
  }
  return { children, warnings };
}

/** Run the PDF analyzer once during extraction and turn attachments into nested items. */
async function carvePdf(item, dest, sandbox) {
  const children = [];
  const { buf } = await readCapped(item.abs, LIMITS.maxStringScanBytes);
  const pdf = analyzePdf(buf);
  for (const [i, e] of pdf.embedded.entries()) {
    const target = sandbox.safeJoin(dest, `${i + 1}-${e.name}`);
    if (!target) continue;
    children.push({ abs: await sandbox.writeBuffer(target, e.data), name: `[attachment]/${e.name}` });
  }
  item.pdf = { ...pdf, embedded: pdf.embedded.map((e) => ({ name: e.name, size: e.data.length })) };
  return { children, warnings: [] };
}

/** Container-level findings for Office documents (OOXML and OLE). */
function officeContainerFindings(inventory) {
  const out = [];
  const seen = new Set();
  const add = (id, sev, title, desc, rel) => {
    const container = rel.includes('!/') ? rel.slice(0, rel.lastIndexOf('!/')) : rel;
    const key = `${id}|${container}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ ...mk(id, id === 'office.xlm-macros' || id === 'office.macro-project' ? 'execution' : 'archive', sev, title, desc, container), evidence: [rel] });
  };
  for (const it of inventory) {
    const rel = it.rel.replace(/\\/g, '/');
    if (/\/vbaProject\.bin$/i.test(rel) || /\/(?:Macros\/VBA|_VBA_PROJECT_CUR|VBA)\/(?:dir|_VBA_PROJECT)$/i.test(rel)) {
      add('office.macro-project', 'medium', 'Office document contains VBA macros', 'A VBA project is embedded. Its module source is decompressed and scanned in this report.', rel);
    }
    if (/\/xl\/macrosheets\//i.test(rel)) {
      add('office.xlm-macros', 'high', 'Excel 4.0 (XLM) macro sheets', 'Legacy XLM macro sheets are heavily abused because many tools ignore them.', rel);
    }
    if (/\/(?:word|xl|ppt)\/(?:activeX|embeddings)\//i.test(rel)) {
      add('office.embedded-objects', 'low', 'Embedded OLE / ActiveX objects', 'The document embeds objects or ActiveX controls; they are extracted and scanned.', rel);
    }
  }
  return out;
}

function safeLabel(name) {
  return name.replace(/[^\w.-]+/g, '_').slice(0, 60);
}

function pickHashes(h) {
  return h ? { md5: h.md5, sha1: h.sha1, sha256: h.sha256 } : {};
}

function countBy(findings) {
  const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  const byCategory = Object.fromEntries(Object.keys(CATEGORIES).map((c) => [c, 0]));
  for (const f of findings) {
    bySeverity[f.severity] += 1;
    byCategory[f.category] = (byCategory[f.category] ?? 0) + 1;
  }
  return { total: findings.length, bySeverity, byCategory };
}

function dedupe(findings) {
  const map = new Map();
  for (const f of findings) {
    const key = `${f.ruleId}|${f.file}`;
    const prev = map.get(key);
    if (!prev) map.set(key, { ...f, evidence: [...(f.evidence ?? [])] });
    else {
      prev.evidence = [...new Set([...prev.evidence, ...(f.evidence ?? [])])].slice(0, 25);
      prev.occurrences = (prev.occurrences ?? 1) + (f.occurrences ?? 1);
    }
  }
  return [...map.values()];
}

function reaRecord(run, file) {
  return {
    file,
    command: run.command,
    ok: run.ok,
    durationMs: run.durationMs,
    error: run.error ?? null,
    evidence: run.ok ? compactEvidence(run.json) : null,
  };
}

async function hasElectronManifest(inventory) {
  for (const it of inventory) {
    if (path.basename(it.abs).toLowerCase() !== 'package.json' || it.type.size > 2 * 1024 * 1024) continue;
    try {
      const j = JSON.parse(await fs.readFile(it.abs, 'utf8'));
      const deps = { ...j.dependencies, ...j.devDependencies, ...j.optionalDependencies };
      if (deps.electron || deps['electron-nightly'] || j.build?.electronVersion || String(j.main ?? '').includes('electron')) return true;
    } catch {
      /* invalid JSON is fine */
    }
  }
  return inventory.some((it) => /(^|\/)(electron\.exe|resources\/app\.asar)$/i.test(it.rel.replace(/!\//g, '/')));
}

function detectDoubleExtensions(inventory, findings) {
  for (const it of inventory) {
    const name = path.basename(it.rel);
    if (/\.(pdf|docx?|xlsx?|jpe?g|png|txt|mp4|mp3)\.(exe|scr|com|bat|cmd|js|vbs|lnk|ps1|hta)$/i.test(name)) {
      findings.push(mk('evasion.double-extension', 'evasion', 'high', 'Deceptive double file extension', `"${name}" pretends to be a document but is executable.`, it.rel));
    }
    if (/[‮‭]/.test(name)) {
      findings.push(mk('evasion.rtlo', 'evasion', 'high', 'Right-to-left override in file name', 'Unicode RTLO characters are used to disguise executable extensions.', it.rel));
    }
    // Only names a person would see and trust: document / media / text extensions.
    // Stream names inside MSI, CAB or OLE containers ("Binary.CustomAction", "x.dll.GUID")
    // and carved payloads are not deceptive file names.
    if (it.type.kind === 'pe' && /\.(pdf|docx?|xlsx?|pptx?|rtf|odt|txt|csv|jpe?g|png|gif|bmp|ico|svg|mp3|mp4|avi|mov|wav|log|dat|tmp|jar)$/i.test(name) && !name.startsWith('[')) {
      findings.push(mk('evasion.disguised-pe', 'evasion', 'high', 'Executable disguised with a non-executable extension', `"${name}" contains a Windows PE header despite its extension.`, it.rel));
    }
  }
}

function peSummary(pe) {
  return {
    valid: pe.valid,
    architecture: pe.architecture,
    is64: pe.is64,
    isDll: pe.isDll,
    isDriver: pe.isDriver,
    isDotNet: pe.isDotNet,
    subsystem: pe.subsystem,
    compiled: pe.timestampIso,
    entryPointSection: pe.entryPointSection,
    sections: pe.sections.map((s) => ({ name: s.name, entropy: s.entropy, rawSize: s.rawSize, virtualSize: s.virtualSize, flags: `${s.readable ? 'R' : '-'}${s.writable ? 'W' : '-'}${s.executable ? 'X' : '-'}` })),
    importedDlls: pe.imports.length,
    importedFunctions: pe.importCount,
    certificatePresent: pe.certificate.present,
    overlay: pe.overlay,
    packers: pe.packers,
    mitigations: pe.dllCharacteristics,
    errors: pe.errors,
  };
}

function peFindings(pe, file) {
  const out = [];
  if (!pe.valid) {
    out.push(mk('integrity.malformed-pe', 'integrity', 'medium', 'Malformed PE headers', `The file starts with MZ but the PE structure is invalid: ${pe.errors.join(' ')}`, file));
    return out;
  }
  for (const p of pe.packers) {
    const strong = /Themida|VMProtect|Enigma|WinLicense|Y0da|PESpin|SVKP/.test(p);
    const weak = /NSIS/.test(p);
    out.push(mk(`obfuscation.packer.${p.toLowerCase().replace(/\W+/g, '-')}`, 'obfuscation', weak ? 'info' : strong ? 'high' : 'medium', `Packed with ${p}`, weak ? 'NSIS installer sections detected; the real payload is inside the installer data.' : `Section names match the ${p} packer/protector, which hides the real code from static analysis.`, file));
  }
  const hot = pe.sections.filter((s) => s.entropy >= 7.2 && s.rawSize > 4096);
  if (hot.length) {
    out.push({ ...mk('obfuscation.high-entropy-section', 'obfuscation', hot.some((s) => s.executable) ? 'medium' : 'low', 'High-entropy section(s)', 'Sections close to 8 bits/byte of entropy contain compressed or encrypted data, typical of packed payloads.', file), evidence: hot.map((s) => `${s.name || '<unnamed>'}: entropy ${s.entropy.toFixed(2)}, ${s.rawSize} bytes`) });
  }
  const wx = pe.sections.filter((s) => s.writable && s.executable);
  if (wx.length) {
    out.push({ ...mk('obfuscation.wx-section', 'obfuscation', 'medium', 'Writable and executable section', 'W+X sections allow self-modifying code; normal compilers do not emit them.', file), evidence: wx.map((s) => s.name || '<unnamed>') });
  }
  const standard = /^(\.text|CODE|\.code|\.itext|\.textbss|INIT|PAGE|\.orpc)$/i;
  if (pe.entryPointRva && pe.entryPointSection && !standard.test(pe.entryPointSection) && !pe.isDotNet) {
    out.push(mk('obfuscation.entrypoint', 'obfuscation', 'medium', 'Entry point in unusual section', `Execution starts in "${pe.entryPointSection}" instead of the code section, a common packer / infector trait.`, file));
  }
  if (pe.entryPointRva && !pe.entryPointSection && !pe.isDll) {
    out.push(mk('obfuscation.entrypoint-outside', 'obfuscation', 'high', 'Entry point outside all sections', 'The entry point does not fall inside any section; the image is crafted or corrupted.', file));
  }
  if (!pe.isDotNet && pe.importCount > 0 && pe.importCount <= 6) {
    const fns = pe.imports.flatMap((i) => i.functions.map((f) => f.toLowerCase()));
    if (fns.some((f) => f.startsWith('getprocaddress') || f.startsWith('loadlibrary'))) {
      out.push(mk('obfuscation.tiny-iat', 'obfuscation', 'medium', 'Minimal import table with dynamic API loading', 'Only a handful of imports including LoadLibrary/GetProcAddress: the real API usage is resolved at runtime and hidden.', file));
    }
  }
  // DLLs without imports are normal (API-set forwarders, resource-only DLLs); EXEs are not.
  if (!pe.isDotNet && pe.importCount === 0 && !pe.isDriver && !pe.isDll) {
    out.push(mk('obfuscation.no-imports', 'obfuscation', 'medium', 'No import table', 'A Windows executable without imports resolves everything manually, typical of shellcode loaders and packers.', file));
  }
  if (pe.overlay.present && pe.overlay.size > 256 * 1024) {
    out.push(mk('obfuscation.overlay', 'obfuscation', pe.overlay.entropy > 7.5 ? 'medium' : 'low', 'Large overlay data', `${(pe.overlay.size / 1024 / 1024).toFixed(2)} MiB of data is appended after the last section (entropy ${pe.overlay.entropy.toFixed(2)}). Installers do this legitimately; droppers hide payloads there.`, file));
  }
  const now = Date.now() / 1000;
  if (pe.timestamp && pe.timestamp > now + 86400 * 2) {
    out.push(mk('integrity.future-timestamp', 'integrity', 'low', 'Compile timestamp in the future', `Header claims ${pe.timestampIso}; the timestamp was forged.`, file));
  }
  if (!pe.dllCharacteristics.aslr || !pe.dllCharacteristics.dep) {
    const missing = [!pe.dllCharacteristics.aslr && 'ASLR', !pe.dllCharacteristics.dep && 'DEP/NX'].filter(Boolean).join(' and ');
    out.push(mk('integrity.no-mitigations', 'integrity', 'low', `Exploit mitigations disabled (${missing})`, 'Modern toolchains enable these by default; their absence suggests an old, hand-crafted or packed binary.', file));
  }
  if (pe.isDriver) out.push(mk('integrity.kernel-driver', 'integrity', 'medium', 'Kernel-mode driver', 'Drivers run with full kernel privileges; verify the publisher carefully.', file));
  if (pe.isDotNet) out.push(mk('integrity.dotnet', 'integrity', 'info', '.NET assembly', 'Managed code: decompile with REA (inspect-il / inspect-managed-artifact) or dnSpy for full source-level review.', file));
  return out;
}

function mergeImports(own, rea) {
  const map = new Map(own.map((i) => [i.dll.toLowerCase(), new Set(i.functions)]));
  for (const imp of rea) {
    const set = map.get(imp.dll.toLowerCase()) ?? new Set();
    for (const f of imp.functions) set.add(f);
    map.set(imp.dll.toLowerCase(), set);
  }
  return [...map.entries()].map(([dll, set]) => ({ dll, functions: [...set] }));
}

function apiFindings(imports, corpus, file) {
  const out = [];
  const imported = new Set();
  const hits = [];
  for (const imp of imports) {
    for (const fn of imp.functions) {
      const lower = fn.toLowerCase();
      imported.add(lower);
      if (/[aw]$/.test(lower) && /[AW]$/.test(fn)) imported.add(lower.slice(0, -1));
      const entry = lookupApi(fn);
      if (entry) hits.push({ fn, dll: imp.dll, entry });
    }
  }
  const notable = hits.filter((h) => h.entry.severity === 'high' || h.entry.severity === 'medium');
  const byCat = new Map();
  for (const h of notable) {
    const list = byCat.get(h.entry.category) ?? [];
    list.push(h);
    byCat.set(h.entry.category, list);
  }
  const API_GROUP_TITLE = {
    imports: 'Process injection / memory manipulation APIs imported',
    execution: 'Process execution APIs imported',
    credentials: 'Credential access / input capture APIs imported',
    persistence: 'Persistence / service APIs imported',
    evasion: 'Privilege and anti-analysis APIs imported',
    fileops: 'File destruction / encryption APIs imported',
    network: 'Download / network APIs imported',
  };
  for (const [category, list] of byCat) {
    const sev = list.some((h) => h.entry.severity === 'high') ? 'high' : 'medium';
    out.push({
      ...mk(`imports.${category}`, 'imports', sev, API_GROUP_TITLE[category] ?? 'Suspicious APIs imported', 'The import table references APIs frequently abused by malware. Individually they can be legitimate; review them in context.', file),
      category: 'imports',
      evidence: list.slice(0, 25).map((h) => `${h.dll}!${h.fn}: ${h.entry.description}`),
    });
  }
  for (const combo of API_COMBOS) {
    const present = combo.all.map((group) => group.filter((name) => imported.has(name)));
    // Every step needs an API, and the steps need different APIs: an API listed in two
    // groups (GetAsyncKeyState in the keylogger combination) must not satisfy both alone.
    if (present.every((group) => group.length > 0) && distinctPick(present)) {
      out.push({
        ...mk(combo.id, combo.category, combo.severity, combo.title, `${combo.description} (MITRE ATT&CK ${combo.mitre})`, file),
        category: 'imports',
        mitre: combo.mitre,
        evidence: present.map((group) => group.join(' / ')),
      });
    }
  }
  // APIs that appear as strings but are not imported: resolved dynamically.
  const dynamic = [];
  for (const name of ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'NtUnmapViewOfSection', 'NtCreateThreadEx', 'SetWindowsHookExA', 'SetWindowsHookExW', 'URLDownloadToFileA', 'URLDownloadToFileW', 'CryptUnprotectData', 'MiniDumpWriteDump', 'QueueUserAPC', 'NtWriteVirtualMemory', 'RtlCreateUserThread', 'IsDebuggerPresent', 'AdjustTokenPrivileges']) {
    if (!imported.has(name.toLowerCase()) && new RegExp(`(^|[^A-Za-z])${name}($|[^A-Za-z])`, 'm').test(corpus)) dynamic.push(name);
  }
  if (dynamic.length >= 2) {
    out.push({ ...mk('imports.dynamic-resolution', 'imports', dynamic.length >= 4 ? 'high' : 'medium', 'Sensitive APIs resolved dynamically', 'These API names appear as strings but are not in the import table, so they are probably resolved with GetProcAddress to hide them from static scanners.', file), evidence: dynamic });
  }
  return out;
}

/** Can one different name be chosen from every group? (Groups are tiny: plain backtracking.) */
function distinctPick(groups, used = new Set(), i = 0) {
  if (i === groups.length) return true;
  for (const name of groups[i]) {
    if (used.has(name)) continue;
    used.add(name);
    if (distinctPick(groups, used, i + 1)) return true;
    used.delete(name);
  }
  return false;
}

function iocFindings(results, file) {
  return results.map(({ rule, matches }) => ({
    ...mk(rule.id, rule.category, rule.severity, rule.title, rule.description, file),
    occurrences: matches.length,
    evidence: matches,
  }));
}

function signatureFinding(sig, file, primary) {
  const who = sig.subject ? ` Signer: ${sig.subject}.` : '';
  switch (sig.status) {
    case 'Valid':
      return { ...mk('integrity.signed', 'integrity', 'info', 'Valid Authenticode signature', `Signature verified by Windows.${who}${sig.timestamped ? ' Timestamped.' : ''}`, file), evidence: [sig.issuer && `Issuer: ${sig.issuer}`, sig.thumbprint && `Thumbprint: ${sig.thumbprint}`].filter(Boolean) };
    case 'NotSigned':
      return mk('integrity.unsigned', 'integrity', primary ? 'medium' : 'low', 'Executable is not digitally signed', 'No valid Authenticode signature. Most legitimate commercial software is signed.', file);
    case 'HashMismatch':
      return mk('integrity.tampered', 'integrity', 'critical', 'Signature hash mismatch (tampered file)', `The file was modified after signing; the signature is invalid.${who}`, file);
    case 'NotTrusted':
      return mk('integrity.untrusted', 'integrity', 'high', 'Signed with an untrusted certificate', `The certificate chain does not lead to a trusted root (self-signed or revoked).${who}`, file);
    default:
      return mk('integrity.signature-error', 'integrity', 'medium', `Signature problem: ${sig.status}`, `${sig.statusMessage ?? ''}${who}`, file);
  }
}

function electronSummaryFindings(findings, inventory, rootLabel) {
  const out = [];
  const handlers = findings.filter((f) => f.ruleId === 'electron.ipc-handlers').reduce((n, f) => n + (f.occurrences ?? 1), 0);
  const calls = findings.filter((f) => f.ruleId === 'electron.ipc-renderer-calls').reduce((n, f) => n + (f.occurrences ?? 1), 0);
  const hasPreload = inventory.some((it) => /preload[^/]*\.(c|m)?js$/i.test(it.rel));
  const root = rootLabel;
  out.push({
    ...mk('electron.profile', 'electron', 'info', 'Electron application profile', `Electron application detected. ${handlers} ipcMain handler registration(s), ${calls} renderer IPC call site(s), preload script ${hasPreload ? 'present' : 'not found'}.`, root),
    evidence: [`ipcMain handlers: ${handlers}`, `ipcRenderer calls: ${calls}`, `preload: ${hasPreload ? 'yes' : 'no'}`],
  });
  const contextOff = findings.some((f) => f.ruleId === 'electron.context-isolation-off');
  const nodeOn = findings.some((f) => f.ruleId === 'electron.node-integration');
  if (contextOff && nodeOn) {
    out.push(mk('electron.rce-config', 'electron', 'critical', 'Renderer configured for remote code execution', 'nodeIntegration is enabled and contextIsolation is disabled: any injected script in a window gets full operating-system access.', root));
  }
  return out;
}
