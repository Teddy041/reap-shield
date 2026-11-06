import { useEffect, useRef, useState } from 'react';
import { api } from './api.js';
import DropZone from './components/DropZone.jsx';
import ScanProgress from './components/ScanProgress.jsx';
import ReportView from './components/ReportView.jsx';

function Toggle({ label, hint, checked, onChange, disabled }) {
  return (
    <label className={`flex items-start gap-3 ${disabled ? 'opacity-40' : 'cursor-pointer'}`}>
      <input type="checkbox" className="peer sr-only" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      <span className="mt-0.5 h-5 w-9 shrink-0 rounded-full bg-panel-2 ring-1 ring-edge transition peer-checked:bg-neon/30 peer-checked:ring-neon peer-focus-visible:ring-2 relative after:absolute after:left-0.5 after:top-0.5 after:h-4 after:w-4 after:rounded-full after:bg-dim after:transition peer-checked:after:translate-x-4 peer-checked:after:bg-neon" />
      <span>
        <span className="block text-sm">{label}</span>
        <span className="block text-xs text-dim">{hint}</span>
      </span>
    </label>
  );
}

export default function App() {
  const [info, setInfo] = useState(null);
  const [phase, setPhase] = useState('idle'); // idle | scanning | done | error
  const [file, setFile] = useState('');
  const [progress, setProgress] = useState({ stage: 'init', message: '', percent: 0 });
  const [log, setLog] = useState([]);
  const [report, setReport] = useState(null);
  const [error, setError] = useState('');
  const [options, setOptions] = useState({ useRea: true, deep: false, verifySignature: true });
  const cancelled = useRef(false);

  useEffect(() => {
    api.info().then(setInfo).catch(() => {});
    return api.onProgress((e) => {
      setProgress(e);
      setLog((l) => [...l.slice(-400), { ...e, time: new Date().toLocaleTimeString('en-GB') }]);
    });
  }, []);

  const start = async (filePath) => {
    cancelled.current = false;
    setFile(filePath);
    setReport(null);
    setError('');
    setLog([]);
    setProgress({ stage: 'init', message: 'Starting', percent: 0 });
    setPhase('scanning');
    try {
      const r = await api.startScan(filePath, options);
      setReport(r);
      setPhase('done');
    } catch (e) {
      if (cancelled.current) {
        setPhase('idle');
        return;
      }
      setError(String(e.message ?? e).replace(/^Error invoking remote method '[^']+': (Error: )?/, ''));
      setPhase('error');
    }
  };

  // Screenshot capture mode: the main process asks the UI to scan a sample file.
  const startRef = useRef(start);
  startRef.current = start;
  useEffect(() => api.onAutoScan?.((p) => startRef.current(p)), []);

  const cancel = async () => {
    cancelled.current = true;
    await api.cancelScan();
    setPhase('idle');
  };

  const reset = () => {
    setPhase('idle');
    setReport(null);
  };

  const reaOk = info?.rea?.available;

  return (
    <div className="cyber-grid min-h-full">
      <header className="sticky top-0 z-10 border-b border-edge bg-void/85 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center gap-4 px-6 py-3">
          <svg viewBox="0 0 64 64" className="h-9 w-9 text-neon" fill="none" stroke="currentColor" strokeWidth="3">
            <path d="M32 4 L54 12 V30 C54 44 44 54 32 60 C20 54 10 44 10 30 V12 Z" strokeLinejoin="round" />
            <path d="M22 32 L29 39 L43 25" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <div>
            <div className="text-lg font-bold tracking-wide">
              REAP<span className="text-neon">-Shield</span>
            </div>
            <div className="text-[11px] uppercase tracking-[0.2em] text-dim">Reverse Engineering &amp; Automated Privacy Shield</div>
          </div>
          <div className="ml-auto flex items-center gap-3 text-xs">
            {api.demo && <span className="rounded-full border border-sev-medium/50 px-3 py-1 text-sev-medium">DEMO MODE</span>}
            <span
              className={`flex items-center gap-2 rounded-full border px-3 py-1 ${reaOk ? 'border-neon/50 text-neon' : 'border-edge text-dim'}`}
              title={info?.rea?.source ?? ''}
            >
              <span className={`h-2 w-2 rounded-full ${reaOk ? 'bg-neon shadow-[0_0_8px_var(--color-neon)]' : 'bg-dim'}`} />
              REA {reaOk ? 'CONNECTED' : 'OFFLINE'}
            </span>
            <span className="font-mono text-dim">v{info?.version ?? '…'}</span>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-6 py-8">
        {(phase === 'idle' || phase === 'error') && (
          <div className="mx-auto max-w-3xl space-y-6">
            <div className="text-center">
              <h1 className="text-3xl font-bold">Inspect before you execute.</h1>
              <p className="mt-2 text-dim">
                Static reverse engineering of executables, archives and Electron apps: hashes, signatures, imports, strings, C2 indicators and IPC security.
              </p>
            </div>
            <DropZone onFile={start} />
            {phase === 'error' && (
              <div className="rounded-xl border border-sev-critical/50 bg-sev-critical/10 px-4 py-3 text-sm text-sev-critical" role="alert">
                <b>Scan failed:</b> {error}
              </div>
            )}
            <div className="grid gap-4 rounded-xl border border-edge bg-panel p-5 sm:grid-cols-3">
              <Toggle
                label="REA analysis"
                hint={reaOk ? 'PE imports, certificates, hardening, entropy' : 'REA not found: built-in analyzers only'}
                checked={options.useRea && !!reaOk}
                disabled={!reaOk}
                onChange={(v) => setOptions((o) => ({ ...o, useRea: v }))}
              />
              <Toggle
                label="Deep Electron analysis"
                hint="REA JavaScript application reconstruction (slow)"
                checked={options.deep}
                disabled={!reaOk}
                onChange={(v) => setOptions((o) => ({ ...o, deep: v }))}
              />
              <Toggle
                label="Verify signatures"
                hint={info?.platform === 'win32' ? 'Windows Authenticode check' : 'Available on Windows only'}
                checked={options.verifySignature}
                disabled={info?.platform !== 'win32'}
                onChange={(v) => setOptions((o) => ({ ...o, verifySignature: v }))}
              />
            </div>
            <div className="grid gap-3 text-xs text-dim sm:grid-cols-3">
              {[
                ['Isolated sandbox', 'Archives unpack into temp/sandbox with zip-slip, symlink and bomb protection; deleted after each scan.'],
                ['Never executed', 'Files are only read as bytes. No binary, script or installer is ever run.'],
                ['CI/CD ready', 'reap-shield scan file.rar --format json --fail-on high'],
              ].map(([t, d]) => (
                <div key={t} className="rounded-lg border border-edge bg-panel/70 p-3">
                  <div className="mb-1 text-sm text-ink">{t}</div>
                  {d}
                </div>
              ))}
            </div>
          </div>
        )}

        {phase === 'scanning' && (
          <div className="mx-auto max-w-3xl">
            <ScanProgress fileName={file.split(/[\\/]/).pop()} progress={progress} log={log} onCancel={cancel} />
          </div>
        )}

        {phase === 'done' && report && <ReportView report={report} onReset={reset} />}
      </main>
    </div>
  );
}
