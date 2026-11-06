/**
 * Minimal, defensive PE32 / PE32+ parser. It reads headers, sections, the
 * import table, the Authenticode security directory and the CLR directory.
 * Every offset is bounds-checked; malformed images return partial data with
 * `errors[]` instead of throwing.
 */
import fs from 'node:fs/promises';
import { entropy } from './hashing.mjs';

const MACHINES = {
  0x14c: 'x86', 0x8664: 'x64', 0x1c0: 'ARM', 0x1c4: 'ARMv7 Thumb-2', 0xaa64: 'ARM64', 0x200: 'IA-64', 0x0: 'unknown',
};
const SUBSYSTEMS = {
  1: 'Native', 2: 'Windows GUI', 3: 'Windows Console', 5: 'OS/2 Console', 7: 'POSIX Console',
  9: 'Windows CE GUI', 10: 'EFI Application', 11: 'EFI Boot Driver', 12: 'EFI Runtime Driver', 14: 'Xbox', 16: 'Windows Boot Application',
};

const SCN_CNT_CODE = 0x20;
const SCN_MEM_EXECUTE = 0x20000000;
const SCN_MEM_READ = 0x40000000;
const SCN_MEM_WRITE = 0x80000000;

const MAX_DLLS = 1024;
const MAX_FUNCS = 16384;

/** Section names used by well-known packers and protectors. */
export const PACKER_SECTIONS = {
  UPX0: 'UPX', UPX1: 'UPX', UPX2: 'UPX', '.UPX': 'UPX',
  '.aspack': 'ASPack', '.adata': 'ASPack', ASPack: 'ASPack',
  '.MPRESS1': 'MPRESS', '.MPRESS2': 'MPRESS',
  '.themida': 'Themida', '.winlice': 'WinLicense',
  '.vmp0': 'VMProtect', '.vmp1': 'VMProtect', '.vmp2': 'VMProtect',
  '.petite': 'Petite', '.pec1': 'PECompact', PEC2: 'PECompact', pec1: 'PECompact',
  '.enigma1': 'Enigma Protector', '.enigma2': 'Enigma Protector',
  '.nsp0': 'NsPack', '.nsp1': 'NsPack', '.packed': 'Generic packer', '.yP': 'Y0da Protector',
  '.Upack': 'Upack', '.ByDwing': 'Upack', '.perplex': 'Perplex', '.spack': 'Simple Pack',
  '.boom': 'The Boomerang', '.ccg': 'CCG', '.charmve': 'PIN', '.ecode': 'EPL', '.edata': undefined,
  '.mackt': 'ImpRec', '.svkp': 'SVKP', '.taz': 'PESpin', '.tsuarch': 'TSULoader', '.tsustub': 'TSULoader',
  '.Themida': 'Themida', '.MaskPE': 'MaskPE', '.ndata': 'NSIS installer',
};

/**
 * @param {string} filePath
 * @param {number} [maxBytes] Bytes to load (headers + tables live near the start, but imports may be anywhere).
 */
export async function parsePE(filePath, maxBytes = 256 * 1024 * 1024) {
  const { size } = await fs.stat(filePath);
  const fh = await fs.open(filePath, 'r');
  let buf;
  try {
    const len = Math.min(size, maxBytes);
    buf = Buffer.alloc(len);
    await fh.read(buf, 0, len, 0);
  } finally {
    await fh.close();
  }
  return parsePEBuffer(buf, size);
}

export function parsePEBuffer(buf, fileSize = buf.length) {
  const pe = {
    valid: false,
    errors: [],
    machine: null,
    architecture: null,
    is64: false,
    isDll: false,
    isDriver: false,
    isDotNet: false,
    subsystem: null,
    timestamp: null,
    timestampIso: null,
    entryPointRva: 0,
    entryPointSection: null,
    imageBase: null,
    dllCharacteristics: { aslr: false, dep: false, cfg: false, noSeh: false, highEntropyVa: false, forceIntegrity: false },
    sections: [],
    imports: [],
    importCount: 0,
    certificate: { present: false, offset: 0, size: 0 },
    overlay: { present: false, offset: 0, size: 0, entropy: 0 },
    packers: [],
  };
  const u16 = (o) => (o + 2 <= buf.length ? buf.readUInt16LE(o) : null);
  const u32 = (o) => (o + 4 <= buf.length ? buf.readUInt32LE(o) : null);

  if (u16(0) !== 0x5a4d) {
    pe.errors.push('Missing MZ signature.');
    return pe;
  }
  const lfanew = u32(0x3c);
  if (lfanew === null || lfanew + 24 > buf.length || buf.toString('latin1', lfanew, lfanew + 4) !== 'PE\0\0') {
    pe.errors.push('Missing or out-of-range PE signature.');
    return pe;
  }
  const coff = lfanew + 4;
  const machine = u16(coff);
  const numSections = u16(coff + 2);
  const timeDateStamp = u32(coff + 4);
  const sizeOfOptional = u16(coff + 16);
  const characteristics = u16(coff + 18);
  pe.machine = machine;
  pe.architecture = MACHINES[machine] ?? `machine-0x${machine.toString(16)}`;
  pe.isDll = Boolean(characteristics & 0x2000);
  pe.timestamp = timeDateStamp;
  pe.timestampIso = timeDateStamp ? new Date(timeDateStamp * 1000).toISOString() : null;

  const opt = coff + 20;
  const magic = u16(opt);
  if (magic !== 0x10b && magic !== 0x20b) {
    pe.errors.push(`Unknown optional header magic 0x${(magic ?? 0).toString(16)}.`);
    return pe;
  }
  pe.is64 = magic === 0x20b;
  pe.entryPointRva = u32(opt + 16) ?? 0;
  pe.imageBase = pe.is64 && opt + 32 <= buf.length ? `0x${buf.readBigUInt64LE(opt + 24).toString(16)}` : `0x${(u32(opt + 28) ?? 0).toString(16)}`;
  const subsystem = u16(opt + 68);
  pe.subsystem = SUBSYSTEMS[subsystem] ?? `subsystem-${subsystem}`;
  pe.isDriver = subsystem === 1;
  const dllChars = u16(opt + 70) ?? 0;
  pe.dllCharacteristics = {
    highEntropyVa: Boolean(dllChars & 0x0020),
    aslr: Boolean(dllChars & 0x0040),
    forceIntegrity: Boolean(dllChars & 0x0080),
    dep: Boolean(dllChars & 0x0100),
    noSeh: Boolean(dllChars & 0x0400),
    cfg: Boolean(dllChars & 0x4000),
  };
  const numRva = u32(opt + (pe.is64 ? 108 : 92)) ?? 0;
  const dirBase = opt + (pe.is64 ? 112 : 96);
  const dataDir = (i) => (i < Math.min(numRva, 16) ? { rva: u32(dirBase + i * 8) ?? 0, size: u32(dirBase + i * 8 + 4) ?? 0 } : { rva: 0, size: 0 });

  // Sections
  const secBase = opt + sizeOfOptional;
  const count = Math.min(numSections ?? 0, 96);
  let lastRawEnd = 0;
  for (let i = 0; i < count; i += 1) {
    const s = secBase + i * 40;
    if (s + 40 > buf.length) {
      pe.errors.push('Section table truncated.');
      break;
    }
    const name = buf.toString('latin1', s, s + 8).replace(/\0.*$/s, '');
    const virtualSize = buf.readUInt32LE(s + 8);
    const virtualAddress = buf.readUInt32LE(s + 12);
    const rawSize = buf.readUInt32LE(s + 16);
    const rawPtr = buf.readUInt32LE(s + 20);
    const flags = buf.readUInt32LE(s + 36);
    const rawEnd = Math.min(rawPtr + rawSize, buf.length);
    const slice = rawPtr < buf.length ? buf.subarray(rawPtr, rawEnd) : Buffer.alloc(0);
    lastRawEnd = Math.max(lastRawEnd, rawPtr + rawSize);
    pe.sections.push({
      name,
      virtualAddress,
      virtualSize,
      rawSize,
      rawPtr,
      entropy: slice.length ? entropy(slice) : 0,
      executable: Boolean(flags & SCN_MEM_EXECUTE) || Boolean(flags & SCN_CNT_CODE),
      writable: Boolean(flags & SCN_MEM_WRITE),
      readable: Boolean(flags & SCN_MEM_READ),
    });
    const packer = PACKER_SECTIONS[name];
    if (packer && !pe.packers.includes(packer)) pe.packers.push(packer);
  }
  pe.valid = true;

  const rvaToOffset = (rva) => {
    for (const sec of pe.sections) {
      const span = Math.max(sec.virtualSize, sec.rawSize);
      if (rva >= sec.virtualAddress && rva < sec.virtualAddress + span) {
        const off = rva - sec.virtualAddress + sec.rawPtr;
        return off < buf.length ? off : null;
      }
    }
    // Headers are mapped 1:1.
    return rva < (pe.sections[0]?.rawPtr ?? buf.length) ? rva : null;
  };

  const ep = pe.sections.find((s) => pe.entryPointRva >= s.virtualAddress && pe.entryPointRva < s.virtualAddress + Math.max(s.virtualSize, s.rawSize));
  pe.entryPointSection = ep?.name ?? null;

  // Overlay (data appended after the last section, common for droppers / SFX).
  const cert = dataDir(4);
  const certEnd = cert.rva && cert.size ? cert.rva + cert.size : 0;
  if (lastRawEnd > 0 && fileSize > lastRawEnd) {
    const overlaySize = fileSize - lastRawEnd - (certEnd === fileSize && cert.rva >= lastRawEnd ? cert.size : 0);
    if (overlaySize > 0) {
      const slice = buf.subarray(lastRawEnd, Math.min(lastRawEnd + overlaySize, buf.length, lastRawEnd + 8 * 1024 * 1024));
      pe.overlay = { present: true, offset: lastRawEnd, size: overlaySize, entropy: slice.length ? entropy(slice) : 0 };
    }
  }

  // Security directory: the "RVA" is a file offset for this directory.
  if (cert.rva && cert.size) pe.certificate = { present: true, offset: cert.rva, size: cert.size };

  // CLR runtime header => .NET assembly.
  pe.isDotNet = dataDir(14).rva !== 0;

  // Import table
  const imp = dataDir(1);
  if (imp.rva) {
    let descOff = rvaToOffset(imp.rva);
    const readCString = (off, max = 512) => {
      if (off === null || off >= buf.length) return null;
      const end = buf.indexOf(0, off);
      const stop = end === -1 ? Math.min(buf.length, off + max) : Math.min(end, off + max);
      return buf.toString('latin1', off, stop);
    };
    let dlls = 0;
    let funcs = 0;
    while (descOff !== null && descOff + 20 <= buf.length && dlls < MAX_DLLS) {
      const oft = buf.readUInt32LE(descOff);
      const nameRva = buf.readUInt32LE(descOff + 12);
      const ft = buf.readUInt32LE(descOff + 16);
      if (oft === 0 && nameRva === 0 && ft === 0) break;
      const dllName = readCString(rvaToOffset(nameRva)) ?? `<unreadable@0x${nameRva.toString(16)}>`;
      const functions = [];
      let thunkOff = rvaToOffset(oft || ft);
      const step = pe.is64 ? 8 : 4;
      while (thunkOff !== null && thunkOff + step <= buf.length && funcs < MAX_FUNCS) {
        let ordinal = false;
        let value;
        if (pe.is64) {
          const v = buf.readBigUInt64LE(thunkOff);
          if (v === 0n) break;
          ordinal = (v & 0x8000000000000000n) !== 0n;
          value = Number(v & (ordinal ? 0xffffn : 0x7fffffffn));
        } else {
          const v = buf.readUInt32LE(thunkOff);
          if (v === 0) break;
          ordinal = (v & 0x80000000) !== 0;
          value = ordinal ? v & 0xffff : v & 0x7fffffff;
        }
        if (ordinal) functions.push(`ord${value}`);
        else {
          const nameOff = rvaToOffset(value);
          const fn = nameOff !== null ? readCString(nameOff + 2, 256) : null;
          if (fn) functions.push(fn);
        }
        funcs += 1;
        thunkOff += step;
      }
      pe.imports.push({ dll: dllName, functions });
      dlls += 1;
      descOff += 20;
    }
    pe.importCount = funcs;
    if (funcs >= MAX_FUNCS) pe.errors.push('Import table truncated at safety cap.');
  }
  return pe;
}
