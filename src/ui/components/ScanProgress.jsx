import { useEffect, useRef } from 'react';

const STAGES = [
  ['init', 'Validate'],
  ['extract', 'Extract'],
  ['inventory', 'Hash'],
  ['analyze', 'Analyze'],
  ['rea', 'REA'],
  ['yara', 'YARA'],
  ['score', 'Score'],
];

export default function ScanProgress({ fileName, progress, log, onCancel }) {
  const logRef = useRef(null);
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [log]);
  const currentIdx = STAGES.findIndex(([s]) => s === progress.stage);

  return (
    <div className="scanline rounded-2xl border border-edge bg-panel p-6 glow">
      <div className="flex items-center justify-between gap-4">
        <div className="min-w-0">
          <div className="text-xs uppercase tracking-widest text-neon">Scanning</div>
          <div className="truncate font-mono text-lg" title={fileName}>
            {fileName}
          </div>
        </div>
        <button onClick={onCancel} className="rounded-lg border border-edge px-4 py-2 text-sm text-dim hover:border-sev-critical hover:text-sev-critical">
          Cancel
        </button>
      </div>

      <div className="mt-6 h-2 overflow-hidden rounded-full bg-panel-2" role="progressbar" aria-valuenow={progress.percent} aria-valuemin={0} aria-valuemax={100}>
        <div className="h-full rounded-full bg-gradient-to-r from-neon to-neon-2 transition-all duration-300" style={{ width: `${progress.percent}%` }} />
      </div>
      <div className="mt-2 flex justify-between text-xs text-dim">
        <span className="truncate pr-4">{progress.message}</span>
        <span className="font-mono">{progress.percent}%</span>
      </div>

      <ol className="mt-6 grid grid-cols-6 gap-2">
        {STAGES.map(([id, label], i) => {
          const state = i < currentIdx ? 'done' : i === currentIdx ? 'active' : 'todo';
          return (
            <li
              key={id}
              className={`rounded-lg border px-2 py-2 text-center text-xs ${
                state === 'done' ? 'border-neon/40 text-neon' : state === 'active' ? 'border-neon bg-neon/10 text-ink' : 'border-edge text-dim'
              }`}
            >
              {state === 'done' ? '✓ ' : ''}
              {label}
            </li>
          );
        })}
      </ol>

      <div ref={logRef} className="mt-6 h-44 overflow-auto rounded-lg border border-edge bg-void p-3 font-mono text-xs leading-relaxed">
        {log.map((l, i) => (
          <div key={i} className="text-dim">
            <span className="text-neon/70">{l.time}</span> <span className="text-neon-2/80">[{l.stage}]</span> {l.message}
          </div>
        ))}
      </div>
    </div>
  );
}
