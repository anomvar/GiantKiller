const ZONES = [
  { from: 0, to: 30, color: "#34d399" },
  { from: 30, to: 70, color: "#fbbf24" },
  { from: 70, to: 100, color: "#f87171" },
];

function polar(cx, cy, r, angleDeg) {
  const rad = ((angleDeg - 90) * Math.PI) / 180;
  return [cx + r * Math.cos(rad), cy + r * Math.sin(rad)];
}

function arcPath(cx, cy, r, from, to) {
  const [x1, y1] = polar(cx, cy, r, from);
  const [x2, y2] = polar(cx, cy, r, to);
  const large = to - from > 180 ? 1 : 0;
  return `M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}`;
}

export default function RiskMeter({ score, breakdown, verdict }) {
  const clamped = Math.max(0, Math.min(100, score || 0));
  const size = 200;
  const cx = size / 2;
  const cy = size / 2;
  const r = 84;

  const scoreColor = clamped >= 70 ? "#f87171" : clamped >= 30 ? "#fbbf24" : "#34d399";

  return (
    <div className="flex flex-col items-center gap-3">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        {ZONES.map((z) => (
          <path
            key={z.from}
            d={arcPath(cx, cy, r, -60 + (z.from * 240) / 100, -60 + (z.to * 240) / 100)}
            fill="none"
            stroke={z.color}
            strokeOpacity={0.25}
            strokeWidth={14}
            strokeLinecap="round"
          />
        ))}
        <path
          d={arcPath(cx, cy, r, -60, -60 + (clamped * 240) / 100)}
          fill="none"
          stroke={scoreColor}
          strokeWidth={14}
          strokeLinecap="round"
          style={{ filter: `drop-shadow(0 0 8px ${scoreColor})` }}
        />
        <text x={cx} y={cy - 8} textAnchor="middle" fontSize="34" fontWeight="700" fill="#f8fafc" fontFamily="JetBrains Mono, monospace">
          {clamped}
        </text>
        <text x={cx} y={cy + 16} textAnchor="middle" fontSize="11" fill={scoreColor} fontFamily="JetBrains Mono, monospace">
          / 100
        </text>
      </svg>

      <div
        className={`px-4 py-1 rounded-full text-sm font-bold tracking-widest border ${
          verdict === "MALICIOUS"
            ? "text-red-300 border-red-500/60 bg-red-500/10"
            : verdict === "SUSPICIOUS"
              ? "text-amber-300 border-amber-500/60 bg-amber-500/10"
              : "text-emerald-300 border-emerald-500/60 bg-emerald-500/10"
        }`}
      >
        {verdict || "PENDING"}
      </div>

      {breakdown && (
        <div className="w-full space-y-1.5 text-xs">
          {[
            ["Static", breakdown.static],
            ["Dynamic", breakdown.dynamic],
            ["Heuristic", breakdown.heuristic],
            ["Power Rules", breakdown.power_rules],
          ].map(([label, val]) => (
            <div key={label} className="flex items-center gap-2">
              <span className="w-20 text-slate-400 font-mono">{label}</span>
              <div className="flex-1 h-1.5 rounded bg-slate-800 overflow-hidden">
                <div
                  className="h-full rounded bg-gradient-to-r from-cyan-500 to-emerald-400"
                  style={{ width: `${val || 0}%` }}
                />
              </div>
              <span className="w-8 text-right text-slate-300 font-mono">{val || 0}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
