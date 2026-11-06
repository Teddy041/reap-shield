import { useState } from 'react';
import ThreatGauge, { LEVEL_COLOR } from './ThreatGauge.jsx';
import FindingsAccordion, { SeverityBadge } from './FindingsAccordion.jsx';
import { api } from '../api.js';

const SEVS = ['critical', 'high', 'medium', 'low', 'info'];

function CopyField({ label, value }) {
  const [copied, setCopied] = useState(false);
  if (!value) return null;
  return (
    <div className="flex items-center gap-3 py-1.5">
      <span className="w-16 shrink-0 text-xs uppercase tracking-wider text-dim">{label}</span>
      <code className="min-w-0 flex-1 truncate font-mono text-xs text-ink/90" title={value}>
        {value}
      </code>
      <button
        onClick={async () => {
          await navigator.clipboard.writeText(value);
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        }}
        className="rounded border border-edge px-2 py-0.5 text-[10px] text-dim hover:border-neon hover:text-neon"
      >
        {copied ? 'COPIED' : 'COPY'}
      </button>
    </div>
  );
}

function Tabs({ tabs, active, onChange }) {
  return (
    <div className="flex gap-1 border-b border-edge" role="tablist">
      {tabs.map(([id, label, count]) => (
        <button
          key={id}
          role="tab"
          aria-selected={active === id}
          onClick={() => onChange(id)}
          className={`-mb-px border-b-2 px-4 py-2 text-sm ${active === id ? 'border-neon text-neon' : 'border-transparent text-dim hover:text-ink'}`}
        >
          {label}
          {count !== undefined && <span className="ml-2 rounded bg-panel-2 px-1.5 font-mono text-xs">{count}</span>}
        </button>
      ))}
    </div>
  );
}

function FileTable({ files }) {
  return (
    <div className="overflow-auto rounded-xl border border-edge">
      <table className="w-full text-left text-sm">
        <thead className="bg-panel-2 text-xs uppercase tracking-wider text-dim">
          <tr>
            <th className="px-3 py-2">File</th>
            <th className="px-3 py-2">Type</th>
            <th className="px-3 py-2 text-right">Size</th>
            <th className="px-3 py-2">SHA-256</th>
          </tr>
        </thead>
        <tbody>
          {files.slice(0, 1000).map((f) => (
            <tr key={f.rel} className="border-t border-edge hover:bg-panel-2/60">
              <td className="max-w-[420px] truncate px-3 py-1.5 font-mono text-xs" title={f.rel}>
                <span style={{ paddingLeft: `${f.depth * 12}px` }}>{f.rel.split('!/').pop()}</span>
              </td>
              <td className="px-3 py-1.5 text-xs text-dim">
                {f.label}
                {f.pe?.packers?.length ? <span className="ml-2 text-sev-high">[{f.pe.packers.join(', ')}]</span> : null}
                {f.signature ? <span className={`ml-2 ${f.signature.status === 'Valid' ? 'text-sev-low' : 'text-sev-medium'}`}>[{f.signature.status}]</span> : null}
              </td>
              <td className="px-3 py-1.5 text-right font-mono text-xs text-dim">{f.size.toLocaleString('en-US')}</td>
              <td className="max-w-[260px] truncate px-3 py-1.5 font-mono text-[11px] text-dim" title={f.sha256}>
                {f.sha256}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function PePanel({ files }) {
  const pes = files.filter((f) => f.pe);
  if (pes.length === 0) return <div className="rounded-lg border border-edge bg-panel p-8 text-center text-dim">No PE images in this target.</div>;
  return (
    <div className="space-y-4">
      {pes.map((f) => (
        <div key={f.rel} className="rounded-xl border border-edge bg-panel p-4">
          <div className="font-mono text-sm">{f.rel}</div>
          <div className="mt-2 grid grid-cols-2 gap-x-6 gap-y-1 text-xs text-dim md:grid-cols-4">
            <span>Arch: <b className="text-ink">{f.pe.architecture}</b></span>
            <span>Subsystem: <b className="text-ink">{f.pe.subsystem}</b></span>
            <span>Type: <b className="text-ink">{f.pe.isDotNet ? '.NET ' : ''}{f.pe.isDll ? 'DLL' : f.pe.isDriver ? 'Driver' : 'EXE'}</b></span>
            <span>Compiled: <b className="text-ink">{f.pe.compiled?.slice(0, 10) ?? 'n/a'}</b></span>
            <span>Imports: <b className="text-ink">{f.pe.importedDlls} DLLs / {f.pe.importedFunctions} fns</b></span>
            <span>Entry section: <b className="text-ink">{f.pe.entryPointSection ?? 'n/a'}</b></span>
            <span>ASLR / DEP / CFG: <b className="text-ink">{['aslr', 'dep', 'cfg'].map((k) => (f.pe.mitigations[k] ? 'on' : 'off')).join(' / ')}</b></span>
            <span>Signature: <b className="text-ink">{f.signature?.status ?? (f.pe.certificatePresent ? 'present (unverified)' : 'none')}</b></span>
          </div>
          {f.rea && (
            <div className="mt-3 rounded-lg border border-neon/30 bg-void px-3 py-2 text-xs">
              <div className="mb-1 font-semibold text-neon">REA evidence{f.reaImportsMerged ? ' · imports merged' : ''}</div>
              {f.rea.certificates?.subjects?.length > 0 && (
                <div className="text-dim">
                  Certificate chain: <span className="text-ink">{f.rea.certificates.subjects.join(' → ')}</span>
                </div>
              )}
              {f.rea.hardening && (
                <div className="text-dim">
                  Hardening:{' '}
                  {Object.entries(f.rea.hardening).map(([k, v]) => (
                    <span key={k} className={`mr-3 inline-block break-all font-mono ${v === 'enabled' ? 'text-sev-low' : v === 'disabled' ? 'text-sev-medium' : 'text-dim'}`}>
                      {k}={v}
                    </span>
                  ))}
                </div>
              )}
              {f.rea.entropy && (
                <div className="text-dim">
                  Byte entropy: <span className="text-ink">{f.rea.entropy.fileEntropy}</span> · high-entropy runs: <span className="text-ink">{f.rea.entropy.highRuns}</span>
                </div>
              )}
            </div>
          )}
          <table className="mt-3 w-full text-xs">
            <thead className="text-dim">
              <tr>
                <th className="py-1 text-left">Section</th>
                <th className="text-left">Flags</th>
                <th className="text-right">Raw size</th>
                <th className="w-1/2 pl-4 text-left">Entropy</th>
              </tr>
            </thead>
            <tbody>
              {f.pe.sections.map((s, i) => (
                <tr key={i} className="border-t border-edge">
                  <td className="py-1 font-mono">{s.name || '<unnamed>'}</td>
                  <td className={`font-mono ${s.flags.includes('W') && s.flags.includes('X') ? 'text-sev-high' : ''}`}>{s.flags}</td>
                  <td className="text-right font-mono text-dim">{s.rawSize.toLocaleString('en-US')}</td>
                  <td className="pl-4">
                    <div className="flex items-center gap-2">
                      <div className="h-1.5 flex-1 overflow-hidden rounded bg-panel-2">
                        <div className="h-full rounded" style={{ width: `${(s.entropy / 8) * 100}%`, background: s.entropy > 7.2 ? 'var(--color-sev-high)' : 'var(--color-neon)' }} />
                      </div>
                      <span className="w-10 text-right font-mono">{s.entropy.toFixed(2)}</span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}
    </div>
  );
}

function ReaPanel({ rea }) {
  return (
    <div className="space-y-3">
      <div className={`rounded-lg border px-4 py-3 text-sm ${rea.available ? 'border-neon/40 text-neon' : 'border-sev-medium/40 text-sev-medium'}`}>
        REA integration {rea.available ? 'active' : 'unavailable'}: <span className="text-dim">{rea.source}</span>
      </div>
      {rea.runs.length === 0 && <div className="text-sm text-dim">No REA commands were run for this target.</div>}
      {rea.runs.map((r, i) => (
        <details key={i} className="rounded-lg border border-edge bg-panel">
          <summary className="flex cursor-pointer items-center gap-3 px-4 py-2 text-sm">
            <span className={r.ok ? 'text-sev-low' : 'text-sev-critical'}>{r.ok ? '●' : '✕'}</span>
            <code className="flex-1 truncate font-mono text-xs">{r.command}</code>
            <span className="font-mono text-xs text-dim">{r.durationMs} ms</span>
          </summary>
          <pre className="max-h-96 overflow-auto border-t border-edge p-3 font-mono text-[11px] text-dim">{r.ok ? r.evidence : r.error}</pre>
        </details>
      ))}
    </div>
  );
}

export default function ReportView({ report, onReset }) {
  const [tab, setTab] = useState('findings');
  const [exportMsg, setExportMsg] = useState('');
  const { verdict, target, counts } = report;
  const color = LEVEL_COLOR[verdict.level];

  const [trashed, setTrashed] = useState(false);
  const isFolder = target.kind === 'directory';
  const doTrash = async () => {
    try {
      const res = await api.trashTarget(report.scanId);
      if (res?.trashed) {
        setTrashed(true);
        setExportMsg(`Moved to the Recycle Bin: ${res.path}`);
      }
    } catch (e) {
      setExportMsg(String(e.message ?? e).replace(/^Error invoking remote method '[^']+': (Error: )?/, ''));
    }
  };

  const doExport = async (fmt) => {
    try {
      const out = await api.exportReport(report.scanId, fmt);
      if (out) setExportMsg(`Saved: ${out}`);
    } catch (e) {
      setExportMsg(`Export failed: ${e.message}`);
    }
  };

  const warnings = [...report.errors, ...report.archive.warnings];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <button onClick={onReset} className="flex items-center gap-2 rounded-lg border border-edge px-3 py-2 text-sm text-dim hover:border-neon hover:text-neon">
          <span aria-hidden="true">←</span> Back
        </button>
        <button
          onClick={doTrash}
          disabled={trashed}
          title="Moves the scanned item to the Windows Recycle Bin (recoverable)"
          className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-sm ${
            trashed ? 'cursor-not-allowed border-edge text-dim' : 'border-sev-critical/60 text-sev-critical hover:bg-sev-critical/10'
          }`}
        >
          <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
            <path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13M10 11v6M14 11v6" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          {trashed ? 'Moved to Recycle Bin' : `Delete ${isFolder ? 'folder' : 'file'}`}
        </button>
      </div>
      {report.coverage && !report.coverage.complete && (
        <div className="rounded-lg border border-sev-medium/50 bg-sev-medium/10 px-4 py-3 text-sm text-sev-medium" role="status">
          <b>Partial coverage:</b> {report.coverage.partialFiles.length} large file(s) were only partly examined
          {report.coverage.partialFiles[0] && (
            <>
              {' '}(e.g. <span className="font-mono">{report.coverage.partialFiles[0].rel.split('!/').pop()}</span>: {report.coverage.partialFiles[0].percent}% examined)
            </>
          )}
          . Indicators stored later in those files were not searched, so this verdict is weaker evidence. See the <i>Scan Coverage &amp; Limits</i> finding for details.
        </div>
      )}
      {trashed && (
        <div className="rounded-lg border border-sev-low/50 bg-sev-low/10 px-4 py-2 text-sm text-sev-low" role="status">
          The {isFolder ? 'folder' : 'file'} was moved to the Recycle Bin. You can restore it from there if needed.
        </div>
      )}
      {/* Verdict header */}
      <div className="grid gap-6 rounded-2xl border border-edge bg-panel p-6 lg:grid-cols-[320px_1fr]" style={{ boxShadow: `0 0 0 1px ${color}33, 0 0 48px -16px ${color}` }}>
        <ThreatGauge score={verdict.score} level={verdict.level} />
        <div className="min-w-0">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="text-xs uppercase tracking-widest text-dim">Target</div>
              <div className="truncate font-mono text-xl" title={target.path}>
                {target.name}
              </div>
              <div className="text-sm text-dim">
                {target.label} · {target.size.toLocaleString('en-US')} bytes · entropy {target.entropy?.toFixed?.(2) ?? 'n/a'} · {report.files.length} file(s)
                {verdict.electronApp ? ' · Electron app' : ''}
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              <button onClick={() => doExport('pdf')} className="rounded-lg bg-neon px-3 py-2 text-sm font-semibold text-void hover:brightness-110">Export PDF</button>
              <button onClick={() => doExport('md')} className="rounded-lg border border-neon/60 px-3 py-2 text-sm text-neon hover:bg-neon/10">Markdown</button>
              <button onClick={() => doExport('json')} className="rounded-lg border border-edge px-3 py-2 text-sm text-dim hover:text-ink">JSON</button>
              <button onClick={onReset} className="rounded-lg border border-edge px-3 py-2 text-sm text-dim hover:text-ink">New scan</button>
            </div>
          </div>
          <p className="mt-4 rounded-lg border-l-4 bg-panel-2 px-4 py-3 text-sm" style={{ borderColor: color }}>
            {verdict.summary}
          </p>
          <div className="mt-4 grid grid-cols-5 gap-2">
            {SEVS.map((s) => (
              <div key={s} className="rounded-lg border border-edge bg-panel-2 px-3 py-2 text-center">
                <div className="font-mono text-2xl font-bold">{counts.bySeverity[s]}</div>
                <SeverityBadge severity={s} />
              </div>
            ))}
          </div>
          <div className="mt-4 rounded-lg border border-edge bg-void px-4 py-2">
            <CopyField label="SHA-256" value={target.sha256} />
            <CopyField label="SHA-1" value={target.sha1} />
            <CopyField label="MD5" value={target.md5} />
          </div>
          {exportMsg && <div className="mt-3 truncate text-xs text-neon">{exportMsg}</div>}
        </div>
      </div>

      <Tabs
        active={tab}
        onChange={setTab}
        tabs={[
          ['findings', 'Findings', counts.total],
          ['files', 'Files', report.files.length],
          ['pe', 'PE Inspection', report.files.filter((f) => f.pe).length],
          ['rea', 'REA Evidence', report.rea.runs.length],
          ['log', 'Warnings', warnings.length],
        ]}
      />

      {tab === 'findings' && <FindingsAccordion findings={report.findings} categories={report.categories} />}
      {tab === 'files' && <FileTable files={report.files} />}
      {tab === 'pe' && <PePanel files={report.files} />}
      {tab === 'rea' && <ReaPanel rea={report.rea} />}
      {tab === 'log' && (
        <div className="rounded-xl border border-edge bg-void p-4 font-mono text-xs text-dim">
          {warnings.length === 0 ? 'No warnings.' : warnings.map((w, i) => <div key={i} className="py-0.5">{w}</div>)}
        </div>
      )}

      <div className="text-center text-xs text-dim">{report.disclaimer}</div>
    </div>
  );
}
