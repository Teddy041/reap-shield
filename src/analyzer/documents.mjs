/**
 * Analyzers for common malware delivery formats that are not executables:
 * Windows shortcuts (LNK), PDF documents and Office VBA macro projects.
 * Everything is parsed from bytes; nothing is rendered or executed.
 */
import zlib from 'node:zlib';

// ================================================================ LNK (MS-SHLLINK)

const LNK_FLAGS = {
  HasLinkTargetIDList: 0x1,
  HasLinkInfo: 0x2,
  HasName: 0x4,
  HasRelativePath: 0x8,
  HasWorkingDir: 0x10,
  HasArguments: 0x20,
  HasIconLocation: 0x40,
  IsUnicode: 0x80,
};

/**
 * Parse the fields of a shortcut that decide what it runs.
 * @returns {{target:string|null, args:string|null, workingDir:string|null, icon:string|null, name:string|null, relativePath:string|null, showCommand:number, errors:string[]}}
 */
export function parseLnk(buf) {
  const out = { target: null, args: null, workingDir: null, icon: null, name: null, relativePath: null, showCommand: 1, errors: [] };
  try {
    if (buf.length < 0x4c || buf.readUInt32LE(0) !== 0x4c) throw new Error('Bad LNK header');
    const flags = buf.readUInt32LE(0x14);
    out.showCommand = buf.readUInt32LE(0x3c);
    let off = 0x4c;
    if (flags & LNK_FLAGS.HasLinkTargetIDList) off += 2 + buf.readUInt16LE(off);
    if (flags & LNK_FLAGS.HasLinkInfo) {
      const size = buf.readUInt32LE(off);
      const headerSize = buf.readUInt32LE(off + 4);
      const localBase = buf.readUInt32LE(off + 16);
      if (headerSize >= 0x24) {
        const localBaseUnicode = buf.readUInt32LE(off + 28);
        if (localBaseUnicode) out.target = readUtf16z(buf, off + localBaseUnicode);
      }
      if (!out.target && localBase) out.target = readAnsiz(buf, off + localBase);
      off += size;
    }
    const unicode = Boolean(flags & LNK_FLAGS.IsUnicode);
    const readStr = () => {
      const count = buf.readUInt16LE(off);
      off += 2;
      const bytes = unicode ? count * 2 : count;
      const s = buf.toString(unicode ? 'utf16le' : 'latin1', off, Math.min(buf.length, off + bytes));
      off += bytes;
      return s;
    };
    if (flags & LNK_FLAGS.HasName) out.name = readStr();
    if (flags & LNK_FLAGS.HasRelativePath) out.relativePath = readStr();
    if (flags & LNK_FLAGS.HasWorkingDir) out.workingDir = readStr();
    if (flags & LNK_FLAGS.HasArguments) out.args = readStr();
    if (flags & LNK_FLAGS.HasIconLocation) out.icon = readStr();
    if (!out.target && out.relativePath) out.target = out.relativePath;
  } catch (err) {
    out.errors.push(err.message);
  }
  return out;
}

function readUtf16z(buf, off) {
  let end = off;
  while (end + 1 < buf.length && (buf[end] !== 0 || buf[end + 1] !== 0)) end += 2;
  return buf.toString('utf16le', off, end);
}

function readAnsiz(buf, off) {
  const end = buf.indexOf(0, off);
  return buf.toString('latin1', off, end === -1 ? buf.length : end);
}

const LOLBIN_TARGET = /(?:^|[\\/])(cmd|powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|msiexec|forfiles|conhost|wmic|curl|bash|schtasks|explorer)\.exe$/i;

/** Findings for a parsed shortcut. Each item: {ruleId, category, severity, title, description, evidence}. */
export function lnkFindings(lnk) {
  const f = [];
  const evidence = [
    lnk.target && `Target: ${lnk.target}`,
    lnk.args && `Arguments: ${lnk.args.length > 400 ? `${lnk.args.slice(0, 400)}… (${lnk.args.length} chars)` : lnk.args}`,
    lnk.workingDir && `Working dir: ${lnk.workingDir}`,
    lnk.icon && `Icon: ${lnk.icon}`,
    lnk.name && `Description: ${lnk.name}`,
  ].filter(Boolean);
  const bin = lnk.target?.match(LOLBIN_TARGET)?.[1]?.toLowerCase();
  f.push({ ruleId: 'lnk.profile', category: 'execution', severity: 'info', title: 'Shortcut target', description: 'What the shortcut launches when opened.', evidence });
  if (bin) {
    f.push({
      ruleId: 'lnk.lolbin-target',
      category: 'execution',
      severity: 'high',
      title: `Shortcut launches ${bin}.exe`,
      description: 'Shortcuts that start a command interpreter or script host are a common phishing payload (LNK droppers).',
      evidence,
    });
  }
  const args = lnk.args ?? '';
  if (args.length > 300 || /\s{50,}/.test(args)) {
    f.push({
      ruleId: 'lnk.long-args',
      category: 'obfuscation',
      severity: 'medium',
      title: 'Oversized or padded shortcut arguments',
      description: 'Very long or whitespace-padded arguments hide the real command line from the Properties dialog.',
      evidence: [`${args.length} characters`],
    });
  }
  if (/https?:\/\/|\\\\[^\\\s]+\\/i.test(args) || /^\\\\/.test(lnk.target ?? '')) {
    f.push({ ruleId: 'lnk.remote', category: 'network', severity: 'high', title: 'Shortcut references a remote resource', description: 'The shortcut downloads from or runs something on a URL / network share.', evidence });
  }
  if (bin && lnk.icon && /\.(pdf|docx?|xlsx?|jpe?g|png|txt)|imageres\.dll|shell32\.dll|msedge|acrobat/i.test(lnk.icon)) {
    f.push({ ruleId: 'lnk.disguised-icon', category: 'evasion', severity: 'high', title: 'Shortcut disguised with a document icon', description: 'A command-interpreter shortcut uses a document / browser icon to look harmless.', evidence: [`Icon: ${lnk.icon}`] });
  }
  if (bin && (lnk.showCommand === 7 || lnk.showCommand === 2)) {
    f.push({ ruleId: 'lnk.hidden-window', category: 'evasion', severity: 'low', title: 'Shortcut starts minimized', description: 'The launched window is minimized so the victim does not notice it.', evidence: [`ShowCommand: ${lnk.showCommand}`] });
  }
  return f;
}

// ================================================================ PDF

const PDF_KEYWORDS = [
  ['/JavaScript', 'pdf.javascript', 'medium', 'PDF contains JavaScript', 'JavaScript in PDFs is used to exploit readers or redirect users.'],
  ['/JS', null, null, null, null],
  ['/OpenAction', 'pdf.open-action', 'low', 'PDF performs an action on open', 'An /OpenAction runs automatically when the document is opened.'],
  ['/AA', 'pdf.additional-actions', 'low', 'PDF has automatic actions', '/AA triggers actions on page / form events.'],
  ['/Launch', 'pdf.launch', 'high', 'PDF launches an external program', '/Launch actions can run commands on the reader\'s machine.'],
  ['/EmbeddedFile', 'pdf.embedded-file', 'medium', 'PDF carries embedded files', 'Attachments inside the PDF are extracted and scanned as part of this report.'],
  ['/RichMedia', 'pdf.richmedia', 'medium', 'PDF contains rich media (Flash)', 'Embedded Flash content was a frequent exploit vector.'],
  ['/XFA', 'pdf.xfa', 'low', 'PDF uses XFA forms', 'XFA forms can carry scripts.'],
  ['/SubmitForm', 'pdf.submit-form', 'low', 'PDF submits form data', 'Form submission can exfiltrate typed data (credential phishing).'],
  ['/ImportData', 'pdf.import-data', 'low', 'PDF imports external data', 'Imports data from external files.'],
];

/**
 * Analyze a PDF: keyword inventory, Flate stream decoding (so compressed
 * JavaScript becomes visible) and embedded file extraction.
 * @returns {{keywords: Record<string, number>, decodedText: string, embedded: Array<{name:string, data:Buffer}>, findings: any[], streams: number, encrypted: boolean}}
 */
export function analyzePdf(buf, limits = { maxDecoded: 64 * 1024 * 1024, maxStreams: 4000 }) {
  const latin = buf.toString('latin1');
  const keywords = {};
  for (const [kw] of PDF_KEYWORDS) {
    // Match the name token, including hex-escaped obfuscation such as /J#61vaScript.
    const pattern = kw.slice(1).split('').map((ch) => `(?:${ch}|#${ch.charCodeAt(0).toString(16)})`).join('');
    const re = new RegExp(`/${pattern}(?![A-Za-z0-9])`, 'gi');
    keywords[kw] = (latin.match(re) ?? []).length;
  }
  const obfuscatedNames = (latin.match(/\/[A-Za-z]*#[0-9a-f]{2}[A-Za-z#0-9]*/gi) ?? []).length;
  const encrypted = /\/Encrypt\b/.test(latin);

  const decodedParts = [];
  const embedded = [];
  let decodedBytes = 0;
  let streams = 0;
  const streamRe = /stream\r?\n/g;
  let m;
  while ((m = streamRe.exec(latin)) !== null && streams < limits.maxStreams) {
    const start = m.index + m[0].length;
    const end = latin.indexOf('endstream', start);
    if (end === -1) break;
    streams += 1;
    const dict = latin.slice(Math.max(0, m.index - 600), m.index);
    const dictStart = dict.lastIndexOf('obj');
    const header = dictStart >= 0 ? dict.slice(dictStart) : dict;
    let data = buf.subarray(start, end);
    if (/\/FlateDecode|\/Fl\b/.test(header)) {
      try {
        data = zlib.inflateSync(data, { maxOutputLength: 16 * 1024 * 1024, finishFlush: zlib.constants.Z_SYNC_FLUSH });
      } catch {
        continue;
      }
    } else if (/\/(?:ASCIIHexDecode|ASCII85Decode|LZWDecode|RunLengthDecode|DCTDecode|JPXDecode|CCITTFaxDecode|JBIG2Decode)/.test(header)) {
      continue; // images and rare encodings are skipped
    }
    if (decodedBytes + data.length > limits.maxDecoded) break;
    decodedBytes += data.length;
    if (/\/EmbeddedFile\b/.test(header)) {
      embedded.push({ name: `embedded-${embedded.length + 1}.bin`, data: Buffer.from(data) });
    } else if (looksTextual(data)) {
      decodedParts.push(data.toString('latin1'));
    }
    streamRe.lastIndex = end + 9;
  }
  // Attachment file names (/F (name) or /UF (name)) next to /Filespec dictionaries.
  const names = [...latin.matchAll(/\/Type\s*\/Filespec[^>]{0,400}?\/(?:UF|F)\s*\(([^)]{1,200})\)/g)].map((x) => x[1]);
  embedded.forEach((e, i) => {
    if (names[i]) e.name = names[i].replace(/[^\w.-]+/g, '_');
  });

  const findings = [];
  const js = (keywords['/JavaScript'] ?? 0) + (keywords['/JS'] ?? 0);
  for (const [kw, id, sev, title, desc] of PDF_KEYWORDS) {
    if (!id) continue;
    const count = kw === '/JavaScript' ? js : keywords[kw];
    if (count > 0) findings.push({ ruleId: id, category: id === 'pdf.embedded-file' ? 'archive' : 'execution', severity: sev, title, description: desc, evidence: [`${kw}: ${count}`], occurrences: count });
  }
  if (js > 0 && (keywords['/OpenAction'] > 0 || keywords['/AA'] > 0)) {
    findings.push({ ruleId: 'pdf.auto-js', category: 'execution', severity: 'high', title: 'PDF runs JavaScript automatically', description: 'JavaScript combined with /OpenAction or /AA executes as soon as the document is opened, the classic PDF exploit pattern.', evidence: [`JavaScript: ${js}`, `/OpenAction: ${keywords['/OpenAction']}`, `/AA: ${keywords['/AA']}`] });
  }
  if (obfuscatedNames > 0) {
    findings.push({ ruleId: 'pdf.obfuscated-names', category: 'obfuscation', severity: 'medium', title: 'Hex-obfuscated PDF names', description: 'Names such as /J#61vaScript are written with hex escapes to evade keyword scanners.', evidence: [`${obfuscatedNames} obfuscated name(s)`] });
  }
  if (encrypted) {
    findings.push({ ruleId: 'pdf.encrypted', category: 'obfuscation', severity: 'low', title: 'Encrypted PDF', description: 'Encrypted streams cannot be inspected; content analysis is partial.', evidence: [] });
  }
  return { keywords, decodedText: decodedParts.join('\n'), embedded, findings, streams, encrypted };
}

function looksTextual(buf) {
  const n = Math.min(buf.length, 2048);
  if (n === 0) return false;
  let printable = 0;
  for (let i = 0; i < n; i += 1) {
    const b = buf[i];
    if (b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127)) printable += 1;
  }
  return printable / n > 0.85;
}

// ================================================================ VBA (MS-OVBA)

/**
 * MS-OVBA 2.4.1 decompression of a CompressedContainer starting at `offset`
 * (first byte must be the 0x01 signature).
 */
export function decompressVba(buf, offset, maxOut = 8 * 1024 * 1024) {
  if (buf[offset] !== 0x01) return null;
  const out = [];
  let outLen = 0;
  let pos = offset + 1;
  while (pos + 2 <= buf.length && outLen < maxOut) {
    const header = buf.readUInt16LE(pos);
    const chunkSize = (header & 0x0fff) + 3;
    const compressed = (header & 0x8000) !== 0;
    if (((header >> 12) & 0x7) !== 0b011) break; // signature bits must be 0b011
    const chunkEnd = Math.min(buf.length, pos + chunkSize);
    pos += 2;
    if (!compressed) {
      const raw = buf.subarray(pos, Math.min(pos + 4096, buf.length));
      out.push(...raw);
      outLen += raw.length;
      pos += 4096;
      continue;
    }
    const chunkStart = out.length;
    while (pos < chunkEnd) {
      const flags = buf[pos++];
      for (let bit = 0; bit < 8 && pos < chunkEnd; bit += 1) {
        if ((flags & (1 << bit)) === 0) {
          out.push(buf[pos++]);
        } else {
          if (pos + 2 > chunkEnd) {
            pos = chunkEnd;
            break;
          }
          const token = buf.readUInt16LE(pos);
          pos += 2;
          const decompressedCurrent = out.length - chunkStart;
          let bitCount = 4;
          while ((1 << bitCount) < decompressedCurrent) bitCount += 1;
          bitCount = Math.max(bitCount, 4);
          const lengthMask = 0xffff >> bitCount;
          const offsetMask = ~lengthMask & 0xffff;
          const length = (token & lengthMask) + 3;
          const copyOffset = ((token & offsetMask) >> (16 - bitCount)) + 1;
          const src = out.length - copyOffset;
          if (src < 0) return Buffer.from(out);
          for (let i = 0; i < length; i += 1) out.push(out[src + i]);
        }
      }
    }
    outLen = out.length;
    pos = chunkEnd;
  }
  return Buffer.from(out);
}

/**
 * Find and decompress VBA module source code in a stream or OLE file.
 * Uses the olevba heuristic: compressed module source starts with
 * 0x01, a chunk header, then "\x00Attribut".
 * @returns {string[]} decompressed module sources
 */
export function extractVbaSources(buf, maxModules = 64) {
  const sources = [];
  const needle = Buffer.from('\x00Attribut', 'latin1');
  let idx = buf.indexOf(needle);
  while (idx !== -1 && sources.length < maxModules) {
    const start = idx - 3;
    if (start >= 0 && buf[start] === 0x01) {
      const src = decompressVba(buf, start);
      if (src && /Attribute VB_/i.test(src.toString('latin1', 0, 200))) sources.push(src.toString('latin1'));
    }
    idx = buf.indexOf(needle, idx + needle.length);
  }
  return sources;
}
