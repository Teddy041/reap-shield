/**
 * Report renderers: Markdown and self-contained HTML (the HTML is also the
 * source for PDF export). All strings originating from scanned files are
 * untrusted and are escaped before rendering.
 */
import { CATEGORIES, SEVERITIES } from './config.mjs';

const esc = (s) =>
  String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

/** Markdown-safe inline code (backticks cannot break out). */
const mdCode = (s) => {
  const str = String(s ?? '').replace(/\r?\n/g, ' ');
  const fence = str.includes('`') ? '``' : '`';
  return `${fence}${str.includes('`') ? ` ${str} ` : str}${fence}`;
};
const mdText = (s) => String(s ?? '').replace(/([\\*_[\]<>|#])/g, '\\$1').replace(/\r?\n/g, ' ');

function groupByCategory(findings) {
  const groups = new Map();
  for (const key of Object.keys(CATEGORIES)) groups.set(key, []);
  for (const f of findings) {
    if (!groups.has(f.category)) groups.set(f.category, []);
    groups.get(f.category).push(f);
  }
  return [...groups.entries()].filter(([, list]) => list.length > 0);
}

export function toMarkdown(r) {
  const lines = [];
  lines.push(`# ${r.tool.name} Threat Report`);
  lines.push('');
  lines.push(`**Verdict:** ${r.verdict.level.toUpperCase()} (${r.verdict.score}/100)  `);
  lines.push(`**Summary:** ${mdText(r.verdict.summary)}`);
  lines.push('');
  lines.push('## Target');
  lines.push('');
  lines.push('| Property | Value |');
  lines.push('| --- | --- |');
  lines.push(`| File | ${mdCode(r.target.name)} |`);
  lines.push(`| Type | ${mdText(r.target.label)} |`);
  lines.push(`| Size | ${r.target.size.toLocaleString('en-US')} bytes |`);
  lines.push(`| MD5 | ${mdCode(r.target.md5)} |`);
  lines.push(`| SHA-1 | ${mdCode(r.target.sha1)} |`);
  lines.push(`| SHA-256 | ${mdCode(r.target.sha256)} |`);
  lines.push(`| Entropy | ${r.target.entropy ?? 'n/a'} bits/byte |`);
  lines.push(`| Files analyzed | ${r.files.length} |`);
  lines.push(`| Electron application | ${r.verdict.electronApp ? 'yes' : 'no'} |`);
  lines.push(`| Scan time | ${r.startedAt} (${(r.durationMs / 1000).toFixed(1)} s) |`);
  lines.push(`| REA integration | ${r.rea.available ? 'active' : 'unavailable'}: ${mdText(r.rea.source)} |`);
  if (r.yara) lines.push(`| YARA | ${mdText(yaraLine(r.yara))} |`);
  lines.push('');
  lines.push('## Findings Overview');
  lines.push('');
  lines.push(`| ${SEVERITIES.map((s) => s[0].toUpperCase() + s.slice(1)).join(' | ')} |`);
  lines.push(`| ${SEVERITIES.map(() => '---').join(' | ')} |`);
  lines.push(`| ${SEVERITIES.map((s) => r.counts.bySeverity[s]).join(' | ')} |`);
  lines.push('');
  for (const [cat, list] of groupByCategory(r.findings)) {
    lines.push(`## ${CATEGORIES[cat] ?? cat} (${list.length})`);
    lines.push('');
    for (const f of list) {
      lines.push(`### [${f.severity.toUpperCase()}] ${mdText(f.title)}`);
      lines.push('');
      lines.push(`- **File:** ${mdCode(f.file)}`);
      lines.push(`- **Rule:** ${mdCode(f.ruleId)}${f.mitre ? ` · MITRE ATT&CK ${mdCode(f.mitre)}` : ''}${f.occurrences ? ` · ${f.occurrences} occurrence(s)` : ''}`);
      lines.push(`- ${mdText(f.description)}`);
      if (f.evidence?.length) {
        lines.push('- **Evidence:**');
        for (const e of f.evidence.slice(0, 15)) lines.push(`  - ${mdCode(e)}`);
      }
      lines.push('');
    }
  }
  const pes = r.files.filter((f) => f.pe);
  if (pes.length) {
    lines.push('## PE Details');
    lines.push('');
    for (const f of pes) {
      lines.push(`### ${mdCode(f.rel)}`);
      lines.push('');
      lines.push(`${f.pe.architecture}, ${f.pe.subsystem}${f.pe.isDll ? ', DLL' : ''}${f.pe.isDotNet ? ', .NET' : ''}; compiled ${f.pe.compiled ?? 'unknown'}; ${f.pe.importedDlls} DLLs / ${f.pe.importedFunctions} imported functions.`);
      if (f.signature) lines.push(`Signature: **${mdText(f.signature.status)}**${f.signature.subject ? ` by ${mdText(f.signature.subject)}` : ''}.`);
      lines.push('');
      lines.push('| Section | Flags | Raw size | Entropy |');
      lines.push('| --- | --- | --- | --- |');
      for (const s of f.pe.sections) lines.push(`| ${mdCode(s.name || '<unnamed>')} | ${s.flags} | ${s.rawSize} | ${s.entropy.toFixed(2)} |`);
      lines.push('');
    }
  }
  lines.push('## File Inventory');
  lines.push('');
  lines.push('| File | Type | Size | SHA-256 |');
  lines.push('| --- | --- | --- | --- |');
  for (const f of r.files.slice(0, 300)) lines.push(`| ${mdCode(f.rel)} | ${mdText(f.label)} | ${f.size} | ${mdCode(f.sha256 ?? '')} |`);
  if (r.files.length > 300) lines.push(`| … ${r.files.length - 300} more | | | |`);
  lines.push('');
  if (r.rea.runs.length) {
    lines.push('## REA Evidence');
    lines.push('');
    for (const run of r.rea.runs) {
      lines.push(`- ${run.ok ? 'OK' : 'FAILED'} ${mdCode(run.command)} (${run.durationMs} ms)${run.error ? `: ${mdText(run.error)}` : ''}`);
    }
    lines.push('');
  }
  if (r.archive.warnings.length || r.errors.length) {
    lines.push('## Warnings & Errors');
    lines.push('');
    for (const w of [...r.errors, ...r.archive.warnings].slice(0, 100)) lines.push(`- ${mdText(w)}`);
    lines.push('');
  }
  lines.push('---');
  lines.push(`_${mdText(r.disclaimer)}_  `);
  lines.push(`_Generated by ${r.tool.name} ${r.tool.version} · scan ${r.scanId}_`);
  return lines.join('\n');
}

const LEVEL_COLOR = { Low: '#22c55e', Medium: '#eab308', High: '#f97316', Critical: '#ef4444' };
const SEV_COLOR = { info: '#64748b', low: '#22c55e', medium: '#eab308', high: '#f97316', critical: '#ef4444' };

export function toHtml(r) {
  const color = LEVEL_COLOR[r.verdict.level];
  const groups = groupByCategory(r.findings)
    .map(
      ([cat, list]) => `
    <section>
      <h2>${esc(CATEGORIES[cat] ?? cat)} <span class="muted">(${list.length})</span></h2>
      ${list
        .map(
          (f) => `
        <article class="finding" style="border-left-color:${SEV_COLOR[f.severity]}">
          <div class="row"><span class="sev" style="background:${SEV_COLOR[f.severity]}">${esc(f.severity.toUpperCase())}</span><strong>${esc(f.title)}</strong></div>
          <div class="muted mono">${esc(f.file)} · ${esc(f.ruleId)}${f.mitre ? ` · ATT&amp;CK ${esc(f.mitre)}` : ''}${f.occurrences ? ` · ${f.occurrences}×` : ''}</div>
          <p>${esc(f.description)}</p>
          ${f.evidence?.length ? `<ul class="evidence">${f.evidence.slice(0, 15).map((e) => `<li class="mono">${esc(e)}</li>`).join('')}</ul>` : ''}
        </article>`,
        )
        .join('')}
    </section>`,
    )
    .join('');
  const sevCells = SEVERITIES.map((s) => `<div class="pill" style="border-color:${SEV_COLOR[s]}"><b>${r.counts.bySeverity[s]}</b> ${s}</div>`).join('');
  const inventory = r.files
    .slice(0, 300)
    .map((f) => `<tr><td class="mono">${esc(f.rel)}</td><td>${esc(f.label)}</td><td>${f.size.toLocaleString('en-US')}</td><td class="mono small">${esc(f.sha256 ?? '')}</td></tr>`)
    .join('');
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>${esc(r.tool.name)} Report – ${esc(r.target.name)}</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 32px; background: #0b1018; color: #dbe4f0; font: 14px/1.5 "Segoe UI", system-ui, sans-serif; }
  h1 { margin: 0 0 4px; font-size: 24px; } h2 { font-size: 17px; margin: 28px 0 10px; border-bottom: 1px solid #1f2a3a; padding-bottom: 6px; }
  .muted { color: #8494a9; } .mono { font-family: Consolas, "Cascadia Mono", monospace; word-break: break-all; } .small { font-size: 11px; }
  .verdict { display: flex; gap: 24px; align-items: center; padding: 20px; border: 1px solid #1f2a3a; border-radius: 12px; background: #101826; margin: 20px 0; }
  .score { width: 110px; height: 110px; border-radius: 50%; display: grid; place-items: center; font-size: 30px; font-weight: 700; border: 8px solid ${color}; color: ${color}; flex: none; }
  .level { font-size: 22px; font-weight: 700; color: ${color}; letter-spacing: .08em; }
  .pills { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 10px; } .pill { border: 1px solid; border-radius: 999px; padding: 2px 10px; font-size: 12px; text-transform: capitalize; }
  table { width: 100%; border-collapse: collapse; } td, th { text-align: left; padding: 6px 8px; border-bottom: 1px solid #1a2433; vertical-align: top; }
  .finding { background: #101826; border: 1px solid #1f2a3a; border-left: 4px solid; border-radius: 8px; padding: 12px 14px; margin: 10px 0; page-break-inside: avoid; }
  .row { display: flex; gap: 10px; align-items: center; } .sev { color: #0b1018; font-weight: 700; font-size: 11px; padding: 1px 8px; border-radius: 4px; }
  .finding p { margin: 6px 0; } .evidence { margin: 6px 0 0; padding-left: 18px; font-size: 12px; color: #b7c4d6; }
  footer { margin-top: 32px; font-size: 12px; color: #8494a9; }
  @media print { body { padding: 16px; } .finding, .verdict { background: #0f1622; } }
</style></head>
<body>
  <h1>${esc(r.tool.name)} Threat Report</h1>
  <div class="muted">Reverse Engineering &amp; Automated Privacy Shield · ${esc(r.startedAt)}</div>
  <div class="verdict">
    <div class="score">${r.verdict.score}</div>
    <div>
      <div class="level">${esc(r.verdict.level.toUpperCase())} RISK</div>
      <div>${esc(r.verdict.summary)}</div>
      <div class="pills">${sevCells}</div>
    </div>
  </div>
  <h2>Target</h2>
  <table>
    <tr><th>File</th><td class="mono">${esc(r.target.name)}</td></tr>
    <tr><th>Type</th><td>${esc(r.target.label)}</td></tr>
    <tr><th>Size</th><td>${r.target.size.toLocaleString('en-US')} bytes</td></tr>
    <tr><th>MD5</th><td class="mono">${esc(r.target.md5)}</td></tr>
    <tr><th>SHA-1</th><td class="mono">${esc(r.target.sha1)}</td></tr>
    <tr><th>SHA-256</th><td class="mono">${esc(r.target.sha256)}</td></tr>
    <tr><th>Files analyzed</th><td>${r.files.length}</td></tr>
    <tr><th>REA integration</th><td>${r.rea.available ? 'Active' : 'Unavailable'} – ${esc(r.rea.source)}</td></tr>
    ${r.yara ? `<tr><th>YARA</th><td>${esc(yaraLine(r.yara))}</td></tr>` : ''}
  </table>
  ${groups || '<p>No findings.</p>'}
  <h2>File Inventory</h2>
  <table><tr><th>File</th><th>Type</th><th>Size</th><th>SHA-256</th></tr>${inventory}</table>
  <footer>${esc(r.disclaimer)}<br>Generated by ${esc(r.tool.name)} ${esc(r.tool.version)} · scan ${esc(r.scanId)}</footer>
</body></html>`;
}

/** One-line YARA summary for the report header tables. */
function yaraLine(y) {
  if (!y.enabled || !y.ruleCount) return `${y.engine}: ${y.note ?? 'no rules used'}`;
  return `${y.engine}: ${y.ruleCount} rules, ${y.matches} match(es) in ${y.matchedFiles} of ${y.scannedFiles} file(s)`;
}
