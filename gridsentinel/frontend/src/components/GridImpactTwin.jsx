import { useEffect, useMemo, useRef, useState } from "react";

const NODE_POS = {
  SCADA_HMI: [90, 210],
  Relay_1: [250, 210],
  Transformer_T3: [410, 210],
  Bus_3: [570, 210],
  Load_A: [770, 80],
  Load_B: [770, 340],
};

const PULSE_PATH_POINTS = [
  [90, 210], // SCADA
  [250, 210], // Relay
  [410, 210], // Transformer
  [570, 210], // Bus
  [770, 80], // Load A
  [570, 210], // back to bus
  [770, 340], // Load B
];

const NODE_ARRIVAL_INDEX = { SCADA_HMI: 0, Relay_1: 1, Transformer_T3: 2, Bus_3: 3, Load_A: 4, Load_B: 6 };

const ICON = {
  control: "🖥️",
  relay: "⚡",
  transformer: "🔌",
  bus: "▰",
  load: "🏙️",
};

function buildSegments() {
  const segs = [];
  for (let i = 0; i < PULSE_PATH_POINTS.length - 1; i++) {
    const [x1, y1] = PULSE_PATH_POINTS[i];
    const [x2, y2] = PULSE_PATH_POINTS[i + 1];
    segs.push({ x1, y1, x2, y2, len: Math.hypot(x2 - x1, y2 - y1) });
  }
  const total = segs.reduce((a, s) => a + s.len, 0);
  let cum = 0;
  const cumAt = segs.map((s) => {
    cum += s.len;
    return cum;
  });
  return { segs, total, cumAt };
}

export default function GridImpactTwin({ impact }) {
  const [progress, setProgress] = useState(0);
  const [playing, setPlaying] = useState(false);
  const raf = useRef(null);

  const nodes = impact?.topology?.nodes || [];
  const edges = impact?.topology?.edges || [];
  const attackPath = impact?.attack_path || [];
  const compromised = impact?.compromised_nodes || [];
  const effect = impact?.cascading_effect || "";
  const loadLoss = impact?.load_loss_mw || 0;
  const districts = impact?.affected_districts || 0;
  const severity = impact?.severity || "";
  const restoration = impact?.restoration_hours || 0;
  const phases = impact?.attack_phases || [];

  const { segs, total, cumAt } = useMemo(buildSegments, []);

  const arrivals = useMemo(() => {
    const a = {};
    for (const [id, idx] of Object.entries(NODE_ARRIVAL_INDEX)) {
      a[id] = idx === 0 ? 0 : cumAt[idx - 1] / total;
    }
    return a;
  }, [total, cumAt]);

  useEffect(() => {
    if (!playing) return;
    const start = performance.now();
    const DURATION = 9000;
    const tick = (now) => {
      const t = ((now - start) % DURATION) / DURATION;
      setProgress(t);
      raf.current = requestAnimationFrame(tick);
    };
    raf.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf.current);
  }, [playing]);

  const pulsePos = useMemo(() => {
    const dist = progress * total;
    for (let i = 0; i < segs.length; i++) {
      const s = segs[i];
      const startCum = i === 0 ? 0 : cumAt[i - 1];
      if (dist <= cumAt[i]) {
        const local = (dist - startCum) / s.len;
        return {
          x: s.x1 + (s.x2 - s.x1) * local,
          y: s.y1 + (s.y2 - s.y1) * local,
          seg: i,
        };
      }
    }
    const last = segs[segs.length - 1];
    return { x: last.x2, y: last.y2, seg: segs.length - 1 };
  }, [progress, total, segs, cumAt]);

  const infectedSet = useMemo(() => {
    const set = new Set();
    for (const id of attackPath) if (progress >= (arrivals[id] ?? 0)) set.add(id);
    for (const id of ["Load_A", "Load_B"]) if (progress >= (arrivals[id] ?? 1)) set.add(id);
    return set;
  }, [progress, attackPath, arrivals]);

  const loadALost = progress >= (arrivals.Load_A ?? 1);
  const loadBLost = progress >= (arrivals.Load_B ?? 1);
  const lostMW = loadALost && loadBLost ? loadLoss : loadALost ? Math.round(loadLoss * 0.44) : 0;
  const lostDistricts = loadALost && loadBLost ? districts : loadALost ? 1 : 0;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h3 className="text-cyan-300 font-semibold flex items-center gap-2">⚡ Grid Impact Twin — 220kV Substation</h3>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setPlaying((p) => !p)}
            className="px-3 py-1.5 rounded-lg text-xs font-mono border border-cyan-500/50 text-cyan-300 hover:bg-cyan-500/10"
          >
            {playing ? "⏸ Pause" : "▶ Replay Attack"}
          </button>
          <input
            type="range"
            min="0"
            max="1000"
            value={Math.round(progress * 1000)}
            onChange={(e) => {
              setPlaying(false);
              setProgress(e.target.value / 1000);
            }}
            className="w-40 accent-cyan-400"
          />
          <span className="text-[11px] font-mono text-slate-400 w-10">{Math.round(progress * 100)}%</span>
        </div>
      </div>

      <div
        className={`rounded-xl border p-3 text-center text-sm font-mono tracking-wide ${
          severity.startsWith("CRITICAL")
            ? "border-red-500/60 bg-red-500/10 text-red-300"
            : severity.startsWith("HIGH")
              ? "border-amber-500/60 bg-amber-500/10 text-amber-300"
              : "border-slate-600 bg-slate-800/40 text-slate-300"
        }`}
      >
        {severity || "NO IMPACT"}
      </div>

      <div className="rounded-xl border border-slate-700/60 bg-[#0d1526] overflow-hidden">
        <svg viewBox="0 0 860 430" className="w-full h-auto">
          <defs>
            <pattern id="twin-grid" width="20" height="20" patternUnits="userSpaceOnUse">
              <path d="M 20 0 L 0 0 0 20" fill="none" stroke="#1b2440" strokeWidth="0.5" />
            </pattern>
          </defs>
          <rect width="860" height="430" fill="url(#twin-grid)" />

          {edges.map((e, i) => {
            const [x1, y1] = NODE_POS[e.from];
            const [x2, y2] = NODE_POS[e.to];
            const hot = infectedSet.has(e.from) && infectedSet.has(e.to);
            return (
              <line
                key={i}
                x1={x1}
                y1={y1}
                x2={x2}
                y2={y2}
                stroke={hot ? "#f87171" : "#334368"}
                strokeWidth={hot ? 2.5 : 1.5}
                strokeOpacity={hot ? 0.9 : 0.6}
                style={hot ? { filter: "drop-shadow(0 0 4px #f87171)" } : undefined}
              />
            );
          })}

          {attackPath.length > 1 && (
            <>
              <path
                d={PULSE_PATH_POINTS.map((p, i) => `${i === 0 ? "M" : "L"} ${p[0]} ${p[1]}`).join(" ")}
                fill="none"
                stroke="transparent"
                id="pulse-path"
              />
              <circle
                cx={pulsePos.x}
                cy={pulsePos.y}
                r={9}
                fill="#f87171"
                style={{ filter: "drop-shadow(0 0 10px #f87171)", opacity: playing || progress > 0 ? 1 : 0 }}
              />
            </>
          )}

          {nodes.map((n) => {
            const [x, y] = NODE_POS[n.id];
            const infected = infectedSet.has(n.id);
            const isLoad = n.type === "load";
            return (
              <g key={n.id} transform={`translate(${x},${y})`}>
                <circle
                  r={isLoad ? 22 : 18}
                  fill={infected ? "#7f1d1d" : "#0d1526"}
                  stroke={infected ? "#f87171" : "#334368"}
                  strokeWidth={2}
                  style={infected ? { filter: "drop-shadow(0 0 10px #f87171)" } : undefined}
                />
                <text y={5} textAnchor="middle" fontSize={isLoad ? 16 : 13}>
                  {ICON[n.type] || "•"}
                </text>
                <text y={40} textAnchor="middle" fontSize="11" fill={infected ? "#fca5a5" : "#94a3b8"} fontFamily="JetBrains Mono, monospace">
                  {n.label}
                </text>
                {infected && (
                  <text y={-30} textAnchor="middle" fontSize="10" fill="#f87171" fontWeight="bold" fontFamily="JetBrains Mono, monospace">
                    {isLoad ? "⚡ POWER LOST" : "COMPROMISED"}
                  </text>
                )}
              </g>
            );
          })}
        </svg>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          ["Load Lost", `${lostMW} MW`, "text-red-300"],
          ["Districts", lostDistricts, "text-amber-300"],
          ["Restoration", `${restoration} h`, "text-cyan-300"],
          ["Path Depth", attackPath.length, "text-emerald-300"],
        ].map(([label, val, color]) => (
          <div key={label} className="rounded-xl border border-slate-700/60 bg-slate-900/50 p-3 text-center">
            <div className={`text-2xl font-mono font-bold ${color}`}>{val}</div>
            <div className="text-[11px] text-slate-400 font-mono uppercase tracking-wider">{label}</div>
          </div>
        ))}
      </div>

      {effect && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/5 p-3 text-sm text-slate-200 font-mono">
          <span className="text-red-300">▸ Cascade:</span> {effect}
        </div>
      )}

      {phases.length > 0 && (
        <div className="rounded-xl border border-slate-700/60 bg-slate-900/50 p-3">
          <div className="text-xs text-slate-400 font-mono mb-2 tracking-widest">// ATTACK SEQUENCE</div>
          <ol className="space-y-1.5">
            {phases.map((p) => (
              <li key={p.phase} className="text-xs font-mono text-slate-300">
                <span className="text-cyan-400">{p.phase}</span> — {p.detail}
              </li>
            ))}
          </ol>
        </div>
      )}
    </div>
  );
}
