import { useEffect, useState } from "react";

function LiveClock() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  const pad = (n) => String(n).padStart(2, "0");
  return (
    <div className="font-mono text-cyan-300/90 holo-glow-cyan tracking-widest text-sm tabular-nums">
      {pad(now.getHours())}:{pad(now.getMinutes())}:{pad(now.getSeconds())}
      <span className="ml-2 text-[10px] text-cyan-500/60 hidden md:inline">
        {now.toLocaleDateString(undefined, { month: "short", day: "2-digit", year: "numeric" })}
      </span>
    </div>
  );
}

export default function HolographicHeader({ status = "idle", engines = [], glitchKey = "" }) {
  const [glitch, setGlitch] = useState(false);

  useEffect(() => {
    if (!glitchKey) return;
    setGlitch(true);
    const t = setTimeout(() => setGlitch(false), 320);
    return () => clearTimeout(t);
  }, [glitchKey]);

  const engineColor = (stage) => {
    const idx = engines.findIndex((e) => e === stage);
    if (idx === -1) return "#1e293b";
    return "#00ff88";
  };

  return (
    <header className="relative z-40 holo-glass border-x-0 border-t-0 rounded-none">
      <div className="max-w-[1600px] mx-auto px-4 md:px-6 py-3 flex items-center justify-between gap-4">
        {/* Logo */}
        <div className="flex items-center gap-4">
          <div className="relative w-11 h-11">
            <div className="hex-ring" />
            <div className="hex-ring reverse" />
            <div className="hex-logo absolute inset-0 grid place-items-center bg-gradient-to-br from-[#00f0ff]/25 to-[#00f0ff]/5 border border-[#00f0ff]/40">
              <span className="font-display font-black text-[#00f0ff] holo-glow-cyan text-lg leading-none">
                GS
              </span>
            </div>
          </div>
          <div>
            <h1
              data-text="GRIDSENTINEL"
              className={`font-display font-black tracking-[0.28em] text-lg md:text-xl text-[#00f0ff] holo-glow-cyan ${
                glitch ? "glitch glitch-flash" : "glitch"
              }`}
            >
              GRIDSENTINEL
            </h1>
            <p className="font-tech tracking-[0.34em] text-[10px] text-cyan-500/70 mt-0.5">
              POWER-SECTOR THREAT COMMAND CENTER · SIH1388
            </p>
          </div>
        </div>

        {/* Engine status dots */}
        <div className="hidden lg:flex items-center gap-3">
          {["AUTOPSY", "SANDBOX", "HEURISTIC", "IMPACT"].map((name, i) => {
            const on = engines.length > i;
            return (
              <div key={name} className="flex flex-col items-center gap-1 px-2">
                <span
                  className={`w-2 h-2 rounded-full ${
                    on ? "bg-[#00ff88]" : "bg-slate-700"
                  }`}
                  style={{ boxShadow: on ? "0 0 8px #00ff88, 0 0 16px rgba(0,255,136,0.4)" : "none" }}
                />
                <span className={`font-mono text-[9px] tracking-widest ${on ? "text-emerald-300" : "text-slate-600"}`}>
                  {name}
                </span>
              </div>
            );
          })}
        </div>

        {/* System status + clock */}
        <div className="flex items-center gap-4">
          <div className="hidden md:flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[#00ff88] animate-pulse" style={{ boxShadow: "0 0 10px #00ff88" }} />
            <span className="font-mono text-[10px] tracking-widest text-emerald-300">SYSTEM ONLINE</span>
          </div>
          <LiveClock />
        </div>
      </div>
      {status === "scanning" && (
        <div className="h-[2px] w-full bg-[#00f0ff]/10">
          <div className="h-full bg-gradient-to-r from-[#00f0ff] via-[#00ff88] to-[#ff6b35] animate-pulse" style={{ width: "100%" }} />
        </div>
      )}
    </header>
  );
}
