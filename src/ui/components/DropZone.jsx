import { useState } from 'react';
import { api } from '../api.js';

const FORMATS = ['.exe', '.dll', '.msi', '.zip', '.rar', '.7z', '.tar.xz', '.iso', '.cab', '.asar', '.lnk', '.pdf', '.docm', '.js', '.py', '.hta'];

export default function DropZone({ onFile, disabled }) {
  const [over, setOver] = useState(false);

  const onDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setOver(false);
    if (disabled) return;
    const file = e.dataTransfer.files?.[0];
    if (!file) return;
    const p = api.pathForFile(file);
    if (p) onFile(p);
  };

  const browse = async () => {
    if (disabled) return;
    const p = await api.pickFile();
    if (p) onFile(p);
  };

  return (
    <div
      onDragOver={(e) => {
        e.preventDefault();
        if (!disabled) setOver(true);
      }}
      onDragLeave={() => setOver(false)}
      onDrop={onDrop}
      onClick={browse}
      onKeyDown={(e) => {
        // Only keys pressed on the drop zone itself: Enter on the inner "Scan a folder" button
        // bubbles up here and would otherwise open the file dialog on top of the folder dialog.
        if (e.target !== e.currentTarget) return;
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          browse();
        }
      }}
      role="button"
      tabIndex={0}
      aria-label="Drop a file here or press Enter to browse"
      className={`group relative flex flex-col items-center justify-center rounded-2xl border-2 border-dashed px-8 py-16 text-center transition-all outline-none focus-visible:ring-2 focus-visible:ring-neon ${
        disabled ? 'cursor-not-allowed opacity-50 border-edge' : 'cursor-pointer'
      } ${over ? 'border-neon bg-neon/5 glow scale-[1.01]' : 'border-edge hover:border-neon/60 bg-panel/60'}`}
    >
      <svg viewBox="0 0 64 64" className={`h-20 w-20 transition-colors ${over ? 'text-neon' : 'text-dim group-hover:text-neon'}`} fill="none" stroke="currentColor" strokeWidth="2.5">
        <path d="M32 4 L54 12 V30 C54 44 44 54 32 60 C20 54 10 44 10 30 V12 Z" strokeLinejoin="round" />
        <path d="M32 22 V42 M23 31 L32 22 L41 31" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      <div className="mt-5 text-lg font-semibold">Drop a suspicious file or folder to inspect</div>
      <div className="mt-1 text-sm text-dim">or click to browse. Nothing is executed: analysis is 100% static.</div>
      <button
        type="button"
        disabled={disabled}
        onClick={async (e) => {
          e.stopPropagation();
          if (disabled) return;
          const p = await api.pickFolder();
          if (p) onFile(p);
        }}
        className="mt-4 rounded-lg border border-neon/50 px-4 py-1.5 text-sm text-neon hover:bg-neon/10"
      >
        Scan a folder…
      </button>
      <div className="mt-5 flex flex-wrap justify-center gap-2">
        {FORMATS.map((f) => (
          <span key={f} className="rounded-md border border-edge bg-panel-2 px-2 py-0.5 font-mono text-xs text-dim">
            {f}
          </span>
        ))}
      </div>
    </div>
  );
}
