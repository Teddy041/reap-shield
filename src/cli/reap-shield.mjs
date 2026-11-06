#!/usr/bin/env node
/**
 * REAP-Shield headless CLI.
 *
 *   reap-shield scan <file|folder> [options]
 *   reap-shield doctor
 *
 * Exit codes (for CI/CD gates):
 *   0  scan finished and the verdict is below --fail-on
 *   1  scan finished and the verdict is at or above --fail-on
 *   2  usage error
 *   3  scan could not be completed (I/O error, unsupported input)
 */
import fs from 'node:fs/promises';
import path from 'node:path';
import { scanFile, TOOL } from '../analyzer/index.mjs';
import { toMarkdown, toHtml } from '../analyzer/report.mjs';
import { locateRea } from '../analyzer/rea.mjs';
import { LEVELS } from '../analyzer/scoring.mjs';
import { maxSizeGbToBytes, SAFE_SIZE_RANGE_NOTE, MAX_SIZE_MIN_GB, MAX_SIZE_MAX_GB, LARGE_FILE_RELIABILITY, formatBytes } from '../analyzer/config.mjs';

/** Wrap long help text to the terminal-friendly width with a hanging indent. */
const wrap = (text, indent, width = 100) => {
  const out = [];
  let line = '';
  for (const word of text.split(' ')) {
    if ((line + ' ' + word).trim().length > width - indent.length) {
      out.push(line.trim());
      line = '';
    }
    line += ` ${word}`;
  }
  out.push(line.trim());
  return out.map((l) => indent + l).join('\n');
};
const PAD = ' '.repeat(25);

const HELP = `${TOOL.name} ${TOOL.version} - Reverse Engineering & Automated Privacy Shield

Usage:
  reap-shield scan <file|folder> [options]
  reap-shield doctor
  reap-shield --help | --version

Scan options:
  -f, --format <fmt>     Output format: text (default), json, md, html
  -o, --output <path>    Write the report to a file instead of stdout
      --fail-on <level>  Exit with code 1 at or above: low, medium, high (default), critical, never
      --no-rea           Do not call REA tools even when available
      --deep             Run heavy REA workflows (JavaScript application reconstruction)
      --provider <id>    REA native provider for decompilation (e.g. ghidra)
      --no-signature     Skip Windows Authenticode verification
      --keep-sandbox     Keep extracted files in temp/sandbox for manual review
      --max-size <GB>    Largest file to scan, ${MAX_SIZE_MIN_GB}-${MAX_SIZE_MAX_GB} GB (default 1). Larger files are rejected;
                         inside folders they are skipped.
${wrap(`Note: ${SAFE_SIZE_RANGE_NOTE}`, PAD)}
${PAD}Why larger files are less reliable:
${LARGE_FILE_RELIABILITY.map((r) => wrap(`- ${r}`, PAD)).join('\n')}
  -q, --quiet            Suppress progress output on stderr

Supported inputs: folders, executables (.exe .dll .msi), archives (.zip .rar .7z .tar.* .iso .cab .asar),
documents (.pdf .docm .xlsm .lnk) and scripts (.js .py .ps1 .vbs .hta) - see README for the full list.
Nothing is ever executed: all analysis is static.`;

function parseArgs(argv) {
  const args = { _: [], format: 'text', failOn: 'high', rea: true, deep: false, signature: true, keepSandbox: false, quiet: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    const next = () => {
      const v = argv[++i];
      if (v === undefined) throw new UsageError(`Missing value for ${a}`);
      return v;
    };
    switch (a) {
      case '-h': case '--help': args.help = true; break;
      case '-v': case '--version': args.version = true; break;
      case '-f': case '--format': args.format = next(); break;
      case '-o': case '--output': args.output = next(); break;
      case '--fail-on': args.failOn = next().toLowerCase(); break;
      case '--no-rea': args.rea = false; break;
      case '--deep': args.deep = true; break;
      case '--provider': args.provider = next(); break;
      case '--no-signature': args.signature = false; break;
      case '--keep-sandbox': args.keepSandbox = true; break;
      case '--max-size': args.maxSize = next(); break;
      case '-q': case '--quiet': args.quiet = true; break;
      default:
        if (a.startsWith('-')) throw new UsageError(`Unknown option: ${a}`);
        args._.push(a);
    }
  }
  if (!['text', 'json', 'md', 'markdown', 'html'].includes(args.format)) throw new UsageError(`Unknown format: ${args.format}`);
  if (!['low', 'medium', 'high', 'critical', 'never'].includes(args.failOn)) throw new UsageError(`Unknown --fail-on level: ${args.failOn}`);
  if (args.maxSize !== undefined) {
    try {
      args.maxInputBytes = maxSizeGbToBytes(args.maxSize);
    } catch (err) {
      throw new UsageError(`Invalid --max-size "${args.maxSize}": ${err.message}`);
    }
  }
  return args;
}

class UsageError extends Error {}

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code, s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
const SEV_STYLE = { info: '90', low: '32', medium: '33', high: '38;5;208', critical: '1;31' };
const LEVEL_STYLE = { Low: '1;32', Medium: '1;33', High: '1;38;5;208', Critical: '1;31' };

function toText(r) {
  const out = [];
  out.push(c('1;36', `${r.tool.name} ${r.tool.version}`) + c('90', `  scan ${r.scanId}`));
  out.push('');
  out.push(`Target   ${r.target.name}  (${r.target.label}, ${r.target.size.toLocaleString('en-US')} bytes)`);
  if (r.target.sha256) out.push(`SHA-256  ${r.target.sha256}`);
  if (r.target.md5) out.push(`MD5      ${r.target.md5}`);
  out.push(`Files    ${r.files.length} analyzed${r.verdict.electronApp ? ' · Electron application' : ''}`);
  out.push(`REA      ${r.rea.available ? c('32', 'active') : c('33', 'unavailable')} (${r.rea.source})`);
  out.push('');
  out.push(`Verdict  ${c(LEVEL_STYLE[r.verdict.level], `${r.verdict.level.toUpperCase()}  ${r.verdict.score}/100`)}`);
  out.push(`         ${r.verdict.summary}`);
  out.push('');
  const shown = r.findings.filter((f) => f.severity !== 'info');
  if (shown.length === 0) out.push(c('32', 'No suspicious findings.'));
  for (const f of shown) {
    out.push(`${c(SEV_STYLE[f.severity], `[${f.severity.toUpperCase().padEnd(8)}]`)} ${f.title}  ${c('90', `(${f.file})`)}`);
    for (const e of (f.evidence ?? []).slice(0, 3)) out.push(c('90', `             ${e.length > 140 ? `${e.slice(0, 140)}…` : e}`));
  }
  const info = r.findings.length - shown.length;
  if (info) out.push(c('90', `\n${info} informational finding(s) omitted; use --format json or md for the full report.`));
  if (r.errors.length) out.push(c('33', `\n${r.errors.length} analysis error(s): ${r.errors.slice(0, 3).join(' | ')}`));
  out.push(c('90', `\n${r.disclaimer}`));
  return out.join('\n');
}

async function doctor() {
  const loc = locateRea({ refresh: true });
  const lines = [
    `${TOOL.name} ${TOOL.version}`,
    `Node.js     ${process.version}`,
    `Platform    ${process.platform} ${process.arch}`,
    `REA         ${loc.kind === 'node-script' || loc.kind === 'binary' ? 'found' : loc.kind} - ${loc.source}`,
    `Authenticode ${process.platform === 'win32' ? 'available (Get-AuthenticodeSignature)' : 'not available on this platform'}`,
  ];
  process.stdout.write(`${lines.join('\n')}\n`);
  return 0;
}

async function main(argv) {
  let args;
  try {
    args = parseArgs(argv);
  } catch (err) {
    process.stderr.write(`Error: ${err.message}\n\n${HELP}\n`);
    return 2;
  }
  if (args.version) {
    process.stdout.write(`${TOOL.version}\n`);
    return 0;
  }
  const [command, target] = args._;
  if (args.help || !command) {
    process.stdout.write(`${HELP}\n`);
    return args.help ? 0 : 2;
  }
  if (command === 'doctor') return doctor();
  if (command !== 'scan' || !target) {
    process.stderr.write(`Error: expected "scan <file>" or "doctor".\n\n${HELP}\n`);
    return 2;
  }

  const showProgress = !args.quiet && process.stderr.isTTY;
  let report;
  try {
    report = await scanFile(path.resolve(target), {
      useRea: args.rea,
      deep: args.deep,
      provider: args.provider,
      maxInputBytes: args.maxInputBytes,
      verifySignature: args.signature,
      keepSandbox: args.keepSandbox,
      onProgress: (e) => {
        if (showProgress) process.stderr.write(`\r\x1b[2K[${String(e.percent).padStart(3)}%] ${e.message.slice(0, 100)}`);
        else if (!args.quiet && (e.stage === 'done' || e.stage === 'init')) process.stderr.write(`[${e.percent}%] ${e.message}\n`);
      },
    });
    if (showProgress) process.stderr.write('\r\x1b[2K');
  } catch (err) {
    if (showProgress) process.stderr.write('\r\x1b[2K');
    process.stderr.write(`Scan failed: ${err.message}\n`);
    return 3;
  }

  const fmt = args.format;
  const body =
    fmt === 'json' ? JSON.stringify(report, null, 2)
    : fmt === 'md' || fmt === 'markdown' ? toMarkdown(report)
    : fmt === 'html' ? toHtml(report)
    : toText(report);
  if (args.output) {
    await fs.mkdir(path.dirname(path.resolve(args.output)), { recursive: true });
    await fs.writeFile(args.output, fmt === 'text' ? body.replace(/\x1b\[[\d;]*m/g, '') : body);
    if (!args.quiet) process.stderr.write(`Report written to ${path.resolve(args.output)}\n`);
  } else {
    process.stdout.write(`${body}\n`);
  }

  if (args.failOn === 'never') return 0;
  const threshold = LEVELS.indexOf(args.failOn[0].toUpperCase() + args.failOn.slice(1));
  return LEVELS.indexOf(report.verdict.level) >= threshold ? 1 : 0;
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    process.stderr.write(`Unexpected error: ${err?.stack ?? err}\n`);
    process.exitCode = 3;
  },
);
