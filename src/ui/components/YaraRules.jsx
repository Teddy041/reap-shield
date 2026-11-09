import { useEffect, useState } from 'react';
import { api } from '../api.js';

const cleanError = (e) => String(e?.message ?? e).replace(/^Error invoking remote method '[^']+': (Error: )?/, '');

/** Installed YARA rules: status, YARA Forge download / update and the custom rules folder. */
export default function YaraRules({ status, onStatus }) {
  const [pkg, setPkg] = useState(status?.forge?.package ?? 'core');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  useEffect(() => api.onYaraProgress?.((m) => setMessage(m)), []);
  useEffect(() => {
    if (status?.forge?.package) setPkg(status.forge.package);
  }, [status?.forge?.package]);

  const download = async () => {
    setBusy(true);
    setError('');
    setMessage('Starting download');
    try {
      const info = await api.yaraUpdate(pkg);
      setMessage(`Installed YARA Forge "${info.package}" (${info.created}): ${info.rules.toLocaleString('en-US')} rules.`);
      onStatus(await api.yaraStatus());
    } catch (e) {
      setMessage('');
      setError(cleanError(e));
    } finally {
      setBusy(false);
    }
  };

  const openCustom = async () => {
    setError('');
    try {
      await api.yaraOpenCustom();
      onStatus(await api.yaraStatus());
    } catch (e) {
      setError(cleanError(e));
    }
  };

  const forge = status?.forge;
  return (
    <div className="rounded-xl border border-edge bg-panel p-5">
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-sm">YARA rules</span>
        <span className="text-xs text-dim">{status ? `${status.engine.name} ${status.engine.version}` : 'YARA-X'}</span>
        <span className={`ml-auto text-xs ${forge || status?.customRules ? 'text-neon' : 'text-sev-medium'}`} role="status">
          {forge
            ? `YARA Forge "${forge.package}" · ${forge.rules.toLocaleString('en-US')} rules · ${forge.created}`
            : 'YARA Forge rules not downloaded'}
          {status?.customRules ? ` · ${status.customRules} custom` : ''}
        </span>
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <select
          aria-label="YARA Forge package"
          value={pkg}
          disabled={busy}
          onChange={(e) => setPkg(e.target.value)}
          className="rounded-lg border border-edge bg-panel-2 px-3 py-1.5 text-sm outline-none focus:border-neon"
        >
          {(status?.packages ?? ['core', 'extended', 'full']).map((p) => (
            <option key={p} value={p}>
              {p}
              {p === 'core' ? ' (recommended, fewest false positives)' : p === 'extended' ? ' (more rules)' : ' (all rules, noisiest)'}
            </option>
          ))}
        </select>
        <button
          onClick={download}
          disabled={busy}
          className="rounded-lg border border-neon/60 px-3 py-1.5 text-sm text-neon transition hover:bg-neon/10 disabled:opacity-50"
        >
          {busy ? 'Downloading…' : forge ? 'Update rules' : 'Download rules'}
        </button>
        <button onClick={openCustom} className="rounded-lg border border-edge px-3 py-1.5 text-sm text-dim transition hover:border-neon hover:text-neon">
          Open custom rules folder
        </button>
      </div>
      {message && <p className="mt-2 text-xs text-neon">{message}</p>}
      {error && (
        <p className="mt-2 text-xs text-sev-critical" role="alert">
          {error}
        </p>
      )}
      <details className="mt-2 text-xs text-dim">
        <summary className="cursor-pointer text-neon hover:underline">About the rules</summary>
        <p className="mt-2">
          Rules are matched with YARA-X against every extracted file; nothing is executed. The rules are downloaded from YARA Forge (github.com/YARAHQ/yara-forge) only when you click the
          button. Put your own <code>.yar</code> files in the custom rules folder; they are used by every scan.
        </p>
        {status?.note && <p className="mt-2">{status.note}</p>}
      </details>
    </div>
  );
}
