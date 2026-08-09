const CATEGORY_META = {
  file: { icon: "📄", color: "text-cyan-300" },
  network: { icon: "🌐", color: "text-red-300" },
  dns: { icon: "🔍", color: "text-amber-300" },
  registry: { icon: "🗝️", color: "text-purple-300" },
  process: { icon: "⚙️", color: "text-emerald-300" },
  api: { icon: "🧬", color: "text-pink-300" },
  evasion: { icon: "🛡️", color: "text-slate-400" },
};

export default function SandboxComparison({ dynamic }) {
  const behaviors = dynamic?.behaviors || [];
  const standard = dynamic?.standard_behaviors || [];
  const tricks = dynamic?.tricks_used || [];

  const standardSummary =
    !dynamic?.activated
      ? "Sample ran quietly — no network, no file drops, no persistence."
      : "Sample aborted early after detecting the analysis environment.";

  const categories = new Set(behaviors.map((b) => b.category));
  const caughtByDiff = standard.length > 0 && dynamic?.activated;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-cyan-300 font-semibold flex items-center gap-2">🕵️ Deceptive Sandbox — Behavior Comparison</h3>
        <span
          className={`text-xs font-mono px-2 py-1 rounded border ${
            dynamic?.activated
              ? "border-red-500/50 text-red-300 bg-red-500/10"
              : "border-slate-600 text-slate-400 bg-slate-800/50"
          }`}
        >
          SAMPLE {dynamic?.activated ? "ACTIVATED" : "SLEPT"}
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="rounded-xl border border-slate-700/60 bg-slate-900/50 p-4 opacity-70">
          <div className="text-slate-400 font-mono text-xs mb-3 tracking-widest">// STANDARD SANDBOX</div>
          <div className="text-sm text-slate-400 mb-3 italic">“{standardSummary}”</div>
          <ul className="space-y-2">
            {standard.map((b, i) => (
              <li key={i} className="text-xs font-mono text-slate-500 flex gap-2">
                <span>{CATEGORY_META[b.category]?.icon || "·"}</span>
                <span>{b.description}</span>
              </li>
            ))}
            {standard.length === 0 && <li className="text-xs text-slate-600">No observable events</li>}
          </ul>
          <div className="mt-4 border-t border-slate-800 pt-3 text-[11px] text-slate-500 font-mono">
            <span className="text-amber-400/80">▲ MISSED:</span> anti-VM stub silenced the sample before it could act.
          </div>
        </div>

        <div
          className={`rounded-xl border p-4 bg-slate-900/60 ${
            dynamic?.activated ? "border-red-500/40 shadow-[0_0_30px_-10px_rgba(248,113,113,0.5)]" : "border-slate-700/60"
          }`}
        >
          <div className="text-red-300 font-mono text-xs mb-3 tracking-widest">// GRIDSENTINEL DECEPTIVE SANDBOX</div>
          <ul className="space-y-2">
            {behaviors.map((b, i) => (
              <li
                key={i}
                className={`text-xs font-mono rounded px-2 py-1.5 flex gap-2 ${
                  caughtByDiff ? "diff-added bg-emerald-500/5" : ""
                } ${b.suspicious ? "text-slate-200" : "text-slate-400"}`}
              >
                <span className={CATEGORY_META[b.category]?.color}>{CATEGORY_META[b.category]?.icon || "·"}</span>
                <div>
                  <div>{b.description}</div>
                  {b.detail && <div className="text-[10px] text-slate-500">{b.detail}</div>}
                </div>
              </li>
            ))}
            {behaviors.length === 0 && <li className="text-xs text-slate-500">No suspicious behavior captured</li>}
          </ul>
        </div>
      </div>

      {tricks.length > 0 && (
        <div className="rounded-xl border border-cyan-500/30 bg-cyan-500/5 p-4">
          <div className="text-xs font-mono text-cyan-300 mb-2 tracking-widest">// TRICKS USED TO DECEIVE THE SAMPLE</div>
          <div className="flex flex-wrap gap-2">
            {tricks.map((t) => (
              <span
                key={t}
                className="px-2.5 py-1 rounded-full text-[11px] font-mono bg-slate-800 border border-cyan-500/40 text-cyan-200"
              >
                🎭 {t}
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="text-[11px] font-mono text-slate-500">
        Captured categories:{" "}
        {[...categories].map((c) => (
          <span key={c} className="text-slate-300">
            {c}
            {c !== [...categories][categories.size - 1] ? ", " : ""}
          </span>
        ))}
      </div>
    </div>
  );
}
