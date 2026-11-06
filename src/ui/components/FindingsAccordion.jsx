import { useMemo, useState } from 'react';

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_CLASS = {
  critical: 'bg-sev-critical text-void',
  high: 'bg-sev-high text-void',
  medium: 'bg-sev-medium text-void',
  low: 'bg-sev-low text-void',
  info: 'bg-sev-info text-ink',
};
const SEV_BORDER = {
  critical: 'border-l-sev-critical',
  high: 'border-l-sev-high',
  medium: 'border-l-sev-medium',
  low: 'border-l-sev-low',
  info: 'border-l-sev-info',
};
const ICONS = {
  network: '◎',
  imports: '⧉',
  fileops: '▤',
  persistence: '↻',
  execution: '▶',
  obfuscation: '▒',
  credentials: '⚿',
  evasion: '◌',
  electron: '⚛',
  integrity: '✓',
  archive: '▣',
};

export function SeverityBadge({ severity }) {
  return <span className={`inline-block min-w-[68px] rounded px-1.5 py-0.5 text-center text-[10px] font-bold tracking-wider ${SEV_CLASS[severity]}`}>{severity.toUpperCase()}</span>;
}

function FindingCard({ f }) {
  const [open, setOpen] = useState(f.severity === 'critical');
  return (
    <div className={`rounded-lg border border-edge border-l-4 ${SEV_BORDER[f.severity]} bg-panel-2`}>
      <button onClick={() => setOpen(!open)} className="flex w-full items-start gap-3 px-4 py-3 text-left" aria-expanded={open}>
        <SeverityBadge severity={f.severity} />
        <div className="min-w-0 flex-1">
          <div className="font-medium">{f.title}</div>
          <div className="truncate font-mono text-xs text-dim" title={f.file}>
            {f.file}
          </div>
        </div>
        {f.occurrences > 1 && <span className="rounded bg-void px-2 py-0.5 font-mono text-xs text-dim">{f.occurrences}×</span>}
        <span className={`text-dim transition-transform ${open ? 'rotate-90' : ''}`}>›</span>
      </button>
      {open && (
        <div className="border-t border-edge px-4 py-3 text-sm">
          <p className="text-ink/90">{f.description}</p>
          <div className="mt-2 flex flex-wrap gap-2 text-xs text-dim">
            <span className="rounded bg-void px-2 py-0.5 font-mono">{f.ruleId}</span>
            {f.mitre && <span className="rounded bg-void px-2 py-0.5 font-mono text-neon">ATT&amp;CK {f.mitre}</span>}
            <span className="rounded bg-void px-2 py-0.5">source: {f.source}</span>
          </div>
          {f.evidence?.length > 0 && (
            <ul className="mt-3 max-h-56 space-y-1 overflow-auto rounded-md border border-edge bg-void p-2 font-mono text-xs">
              {f.evidence.map((e, i) => (
                <li key={i} className="break-all text-neon-2/90">
                  {e}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}

export default function FindingsAccordion({ findings, categories }) {
  const [minSev, setMinSev] = useState('low');
  const [query, setQuery] = useState('');
  const [openCats, setOpenCats] = useState(() => new Set());

  const filtered = useMemo(() => {
    const cut = SEV_ORDER.indexOf(minSev);
    const q = query.trim().toLowerCase();
    return findings.filter(
      (f) =>
        SEV_ORDER.indexOf(f.severity) <= cut &&
        (!q || `${f.title} ${f.file} ${f.ruleId} ${(f.evidence ?? []).join(' ')}`.toLowerCase().includes(q)),
    );
  }, [findings, minSev, query]);

  const groups = useMemo(() => {
    const g = new Map();
    for (const f of filtered) {
      if (!g.has(f.category)) g.set(f.category, []);
      g.get(f.category).push(f);
    }
    return [...g.entries()].sort((a, b) => SEV_ORDER.indexOf(a[1][0].severity) - SEV_ORDER.indexOf(b[1][0].severity));
  }, [filtered]);

  const toggle = (cat) =>
    setOpenCats((prev) => {
      const next = new Set(prev);
      next.has(cat) ? next.delete(cat) : next.add(cat);
      return next;
    });
  const isOpen = (cat, list) => openCats.has(cat) !== (list[0].severity === 'critical' || list[0].severity === 'high');

  return (
    <div>
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Filter findings, files, indicators…"
          className="min-w-[220px] flex-1 rounded-lg border border-edge bg-panel-2 px-3 py-2 text-sm outline-none placeholder:text-dim focus:border-neon"
        />
        <div className="flex overflow-hidden rounded-lg border border-edge text-xs" role="group" aria-label="Minimum severity">
          {['critical', 'high', 'medium', 'low', 'info'].map((s) => (
            <button key={s} onClick={() => setMinSev(s)} className={`px-3 py-2 capitalize ${minSev === s ? 'bg-neon/15 text-neon' : 'text-dim hover:text-ink'}`}>
              {s === 'info' ? 'all' : `${s}+`}
            </button>
          ))}
        </div>
      </div>

      {groups.length === 0 && <div className="rounded-lg border border-edge bg-panel p-8 text-center text-dim">No findings at this severity.</div>}

      <div className="space-y-3">
        {groups.map(([cat, list]) => {
          const open = isOpen(cat, list);
          const top = list[0].severity;
          return (
            <section key={cat} className="overflow-hidden rounded-xl border border-edge bg-panel">
              <button onClick={() => toggle(cat)} className="flex w-full items-center gap-3 px-4 py-3 text-left hover:bg-panel-2" aria-expanded={open}>
                <span className="w-6 text-center text-lg text-neon">{ICONS[cat] ?? '•'}</span>
                <span className="flex-1 font-semibold">{categories[cat] ?? cat}</span>
                <SeverityBadge severity={top} />
                <span className="w-10 text-right font-mono text-sm text-dim">{list.length}</span>
                <span className={`text-dim transition-transform ${open ? 'rotate-90' : ''}`}>›</span>
              </button>
              {open && (
                <div className="space-y-2 border-t border-edge p-3">
                  {list.map((f) => (
                    <FindingCard key={f.id} f={f} />
                  ))}
                </div>
              )}
            </section>
          );
        })}
      </div>
    </div>
  );
}
