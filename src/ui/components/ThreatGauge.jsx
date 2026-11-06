const BANDS = [
  { level: 'Low', from: 0, to: 20, color: 'var(--color-sev-low)' },
  { level: 'Medium', from: 20, to: 45, color: 'var(--color-sev-medium)' },
  { level: 'High', from: 45, to: 70, color: 'var(--color-sev-high)' },
  { level: 'Critical', from: 70, to: 100, color: 'var(--color-sev-critical)' },
];

export const LEVEL_COLOR = Object.fromEntries(BANDS.map((b) => [b.level, b.color]));

const CX = 150;
const CY = 150;
const R = 112;

/** Point on the gauge arc for a score 0..100 (180° → 0°). */
function point(score, radius = R) {
  const angle = Math.PI * (1 - score / 100);
  return [CX + radius * Math.cos(angle), CY - radius * Math.sin(angle)];
}

function arc(from, to, radius = R) {
  const [x1, y1] = point(from, radius);
  const [x2, y2] = point(to, radius);
  return `M ${x1} ${y1} A ${radius} ${radius} 0 0 1 ${x2} ${y2}`;
}

/** Semicircular threat severity gauge (Low / Medium / High / Critical). */
export default function ThreatGauge({ score, level }) {
  const color = LEVEL_COLOR[level] ?? 'var(--color-neon)';
  const [nx, ny] = point(score, R - 26);
  return (
    <div className="flex flex-col items-center" role="img" aria-label={`Threat level ${level}, score ${score} of 100`}>
      <svg viewBox="0 0 300 180" className="w-full max-w-[320px]">
        <defs>
          <filter id="gauge-glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="4" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        <path d={arc(0, 100)} stroke="#132033" strokeWidth="22" fill="none" strokeLinecap="round" />
        {BANDS.map((b) => (
          <path
            key={b.level}
            d={arc(b.from + 0.6, b.to - 0.6)}
            stroke={b.color}
            strokeOpacity={b.level === level ? 1 : 0.28}
            strokeWidth={b.level === level ? 22 : 16}
            fill="none"
            filter={b.level === level ? 'url(#gauge-glow)' : undefined}
          />
        ))}
        {[0, 20, 45, 70, 100].map((t) => {
          const [x, y] = point(t, R + 22);
          return (
            <text key={t} x={x} y={y} fill="#5d6f87" fontSize="10" textAnchor="middle" dominantBaseline="middle">
              {t}
            </text>
          );
        })}
        <line x1={CX} y1={CY} x2={nx} y2={ny} stroke={color} strokeWidth="4" strokeLinecap="round" filter="url(#gauge-glow)" />
        <circle cx={CX} cy={CY} r="9" fill="#0d1420" stroke={color} strokeWidth="3" />
        <text x={CX} y={CY - 38} fill={color} fontSize="40" fontWeight="700" textAnchor="middle" fontFamily="var(--font-mono)">
          {score}
        </text>
      </svg>
      <div className="-mt-3 text-xl font-bold tracking-[0.25em]" style={{ color }}>
        {level.toUpperCase()}
      </div>
      <div className="text-xs text-dim mt-1">THREAT SEVERITY</div>
    </div>
  );
}
