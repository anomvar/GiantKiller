import { useCallback, useEffect, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import HolographicHeader from "./components/HolographicHeader";
import ParticleBackground from "./components/ParticleBackground";
import HolographicGrid from "./components/HolographicGrid";
import ScanlineOverlay from "./components/ScanlineOverlay";
import UploadZone from "./components/UploadZone";
import EngineStatusPanel from "./components/EngineStatusPanel";
import RiskMeter from "./components/RiskMeter";
import AutopsyVisualizer from "./components/AutopsyVisualizer";
import SandboxComparison from "./components/SandboxComparison";
import GridImpactTwin from "./components/GridImpactTwin";
import ProsecutorReport from "./components/ProsecutorReport";
import TerminalText from "./components/TerminalText";
import { getReport } from "./api";
import { useWebGLSupport } from "./hooks/useHologramGlow";

const MODES = [
  { key: "autopsy", label: "AUTOPSY", icon: "🧬", needs: (r) => r?.static && Object.keys(r.static).length > 0 },
  { key: "deception", label: "DECEPTION", icon: "🎭", needs: (r) => r?.dynamic && Object.keys(r.dynamic).length > 0 },
  { key: "holodeck", label: "HOLODECK", icon: "⚡", needs: (r) => r?.status === "complete" && r?.grid_impact },
  { key: "narrator", label: "NARRATOR", icon: "👨‍⚖️", needs: (r) => r?.status === "complete" && r?.prosecutor_report },
];

function buildStreamLines(report) {
  const lines = [];
  if (!report) return ["> COMMAND CENTER READY", "> AWAITING TARGET ACQUISITION"];
  lines.push(`> TARGET: ${report.filename || "?"}`);
  if (report.sha256) lines.push(`> SHA256: ${report.sha256.slice(0, 18)}…`);
  const status = report.status;
  if (status === "processing" || status === "static") lines.push("> STATIC ENGINE: RUNNING…");
  if (status === "sandbox") lines.push("> SANDBOX ENGINE: RUNNING…");
  if (report.dynamic?.activated) lines.push("> SANDBOX: PAYLOAD ACTIVATED — BEHAVIOR CAPTURED");
  if (report.dynamic && !report.dynamic.activated) lines.push("> SANDBOX: SAMPLE DORMANT");
  if (status === "heuristic") lines.push("> ML ENGINE: SCORING…");
  if (report.heuristic?.risk_percentile != null) lines.push(`> ML RISK PERCENTILE: ${report.heuristic.risk_percentile}`);
  (report.power_rules?.triggered_rules || []).forEach((r) =>
    lines.push(`> RULE ${r.id} [${r.severity}]: ${r.name}`)
  );
  if (report.grid_impact?.severity) lines.push(`> GRID IMPACT: ${report.grid_impact.severity}`);
  if (report.status === "complete") {
    lines.push(`> VERDICT: ${report.verdict} (${report.risk_score}/100)`);
    lines.push("> ANALYSIS COMPLETE — REPORT GENERATED");
  }
  if (report.status === "error") lines.push(`> ERROR: ${report.error}`);
  return lines;
}

function FlatFallback({ report, mode }) {
  const s = report?.static || {};
  const d = report?.dynamic || {};
  const base = "rounded-lg border border-cyan-500/20 bg-[#070d18]/90 p-3 font-mono text-[11px] text-slate-300";
  if (mode === "autopsy")
    return (
      <div className="space-y-2">
        <div className={base}>
          <div className="text-cyan-300 mb-1">// SECTIONS</div>
          {(s.sections || []).map((x) => (
            <div key={x.name} className="flex justify-between">
              <span>{x.name}</span>
              <span className={x.high_entropy ? "text-[#ff6b35]" : "text-emerald-300"}>{x.entropy}</span>
            </div>
          ))}
        </div>
        <div className={base}>
          <div className="text-cyan-300 mb-1">// IMPORTS</div>
          {(s.imports || []).map((x) => (
            <div key={x.dll} className={x.suspicious.length ? "text-[#ff6b35]" : ""}>{x.dll}</div>
          ))}
        </div>
        <div className={base}>
          <div className="text-cyan-300 mb-1">// YARA</div>
          {(s.yara_matches || []).map((m) => (
            <div key={m.rule} className="text-[#ff6b35]">{m.rule}</div>
          ))}
          <div className="text-slate-500 mt-1">// STRING URLS</div>
          {(s.strings?.urls || []).slice(0, 4).map((u) => <div key={u} className="text-slate-400 break-all">{u}</div>)}
        </div>
      </div>
    );
  if (mode === "deception")
    return (
      <div className={`${base} space-y-1`}>
        <div className="text-cyan-300 mb-1">// BEHAVIORS CAPTURED</div>
        {(d.behaviors || []).map((b, i) => (
          <div key={i} className="flex gap-2"><span className="text-[#ff6b35]">•</span>{b.description}</div>
        ))}
      </div>
    );
  if (mode === "holodeck") {
    const g = report?.grid_impact || {};
    return (
      <div className={`${base} space-y-2`}>
        <div className="text-[#ff6b35] font-bold">{g.severity}</div>
        <div>LOAD LOST: {g.load_loss_mw} MW</div>
        <div>DISTRICTS: {g.affected_districts}</div>
        <div>PATH: {(g.attack_path || []).join(" → ")}</div>
        <div className="text-cyan-300 mt-1">// ATTACK SEQUENCE</div>
        {(g.attack_phases || []).map((p) => (
          <div key={p.phase}>{p.phase} — {p.detail}</div>
        ))}
      </div>
    );
  }
  return (
    <div className={`${base} whitespace-pre-wrap max-h-[420px] overflow-auto`}>
      {report?.prosecutor_report || "AWAITING REPORT…"}
    </div>
  );
}

function WebglGate({ fallback, children }) {
  const supported = useWebGLSupport();
  if (supported === false) return fallback;
  if (supported === null) return <div className="h-[420px]" />;
  return children;
}

export default function App() {
  const [phase, setPhase] = useState("acquisition");
  const [scanId, setScanId] = useState(null);
  const [filename, setFilename] = useState(null);
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);
  const [polling, setPolling] = useState(false);
  const [mode, setMode] = useState("autopsy");
  const [autoAdvance, setAutoAdvance] = useState(true);
  const [pulse, setPulse] = useState(0);
  const [glitchKey, setGlitchKey] = useState("");
  const timerRef = useRef(null);

  /* screen-wide pulse on keyword flash */
  useEffect(() => {
    const handler = () => setPulse((p) => p + 1);
    window.addEventListener("gridsentinel:pulse", handler);
    return () => window.removeEventListener("gridsentinel:pulse", handler);
  }, []);

  /* glitch header on verdict/status change */
  useEffect(() => {
    if (report?.verdict) setGlitchKey(report.verdict);
    else if (report?.status === "complete") setGlitchKey("COMPLETE");
  }, [report?.verdict, report?.status]);

  const handleScanCreated = useCallback((id, name) => {
    setScanId(id);
    setFilename(name);
    setReport(null);
    setError(null);
    setPolling(true);
    setAutoAdvance(true);
    setMode("autopsy");
    setPhase("analysis");
    setGlitchKey("ACQUIRED");
  }, []);

  const reset = useCallback(() => {
    setPolling(false);
    setScanId(null);
    setFilename(null);
    setReport(null);
    setError(null);
    setMode("autopsy");
    setAutoAdvance(true);
    setPhase("acquisition");
  }, []);

  useEffect(() => {
    if (!polling || !scanId) return;
    let cancelled = false;
    const tick = async () => {
      try {
        const r = await getReport(scanId);
        if (cancelled) return;
        setReport(r);
        if (r.status === "complete" || r.status === "error") {
          setPolling(false);
          if (r.error) setError(r.error);
          return;
        }
      } catch (e) {
        if (cancelled) return;
        setError(String(e.message || e));
      }
      timerRef.current = setTimeout(tick, 1200);
    };
    timerRef.current = setTimeout(tick, 400);
    return () => {
      cancelled = true;
      clearTimeout(timerRef.current);
    };
  }, [polling, scanId]);

  /* auto-advance stage as data arrives */
  useEffect(() => {
    if (!autoAdvance || !report) return;
    if (report.dynamic && Object.keys(report.dynamic).length && mode === "autopsy") setMode("deception");
    else if (report.status === "complete" && report.grid_impact && mode === "deception") setMode("holodeck");
    else if (report.status === "complete" && report.prosecutor_report && mode === "holodeck") setMode("narrator");
  }, [report, mode, autoAdvance]);

  const streamLines = buildStreamLines(report);
  const enginesLit = report
    ? report.status === "complete"
      ? ["static", "sandbox", "heuristic", "grid_impact"]
      : ["static", "sandbox", "heuristic", "grid_impact"].slice(0, ["static", "sandbox", "heuristic", "grid_impact"].indexOf(report.status) + 1)
    : [];

  return (
    <div className="relative min-h-screen overflow-hidden">
      <ParticleBackground />
      <HolographicGrid />
      <ScanlineOverlay />
      {pulse > 0 && <div key={pulse} className="screen-pulse" />}

      <HolographicHeader status={polling ? "scanning" : "idle"} engines={enginesLit} glitchKey={glitchKey} />

      <main className="relative z-10 max-w-[1600px] mx-auto px-4 md:px-6 py-5">
        <AnimatePresence mode="wait">
          {phase === "acquisition" ? (
            <motion.div
              key="acquisition"
              initial={{ opacity: 0, rotateX: 12, scale: 0.96, y: 24 }}
              animate={{ opacity: 1, rotateX: 0, scale: 1, y: 0 }}
              exit={{ opacity: 0, rotateX: -8, scale: 0.97, y: -16 }}
              transition={{ type: "spring", stiffness: 100, damping: 20 }}
              className="max-w-3xl mx-auto pt-8"
              style={{ perspective: 1000 }}
            >
              <div className="text-center mb-8">
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.2 }}
                  className="inline-block font-mono text-[11px] tracking-[0.3em] text-cyan-400 border border-cyan-500/40 rounded-full px-4 py-1 mb-5 holo-glow-cyan"
                >
                  DETECTION OF MALWARE / TROJAN IN POWER SECTOR SOFTWARE
                </motion.div>
                <motion.h2
                  data-text="WELCOME BACK, OPERATOR"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.3 }}
                  className="glitch font-display font-black text-3xl md:text-4xl text-[#00f0ff] holo-glow-cyan tracking-[0.2em]"
                >
                  WELCOME BACK, OPERATOR
                </motion.h2>
                <motion.p
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.5 }}
                  className="font-tech text-slate-400 mt-3 text-sm tracking-wide max-w-xl mx-auto"
                >
                  Feed me a suspicious binary. I will dissect it layer by layer, trick it into
                  confessing in the deception chamber, and show you the blackout it would cause.
                </motion.p>
              </div>
              <WebglGate fallback={<div className="holo-glass rounded-2xl p-8 text-center font-mono text-sm text-slate-400">HOLOGRAM PROJECTOR OFFLINE — WEBGL UNAVAILABLE</div>}>
                <UploadZone onScanCreated={handleScanCreated} />
              </WebglGate>
            </motion.div>
          ) : (
            <motion.div
              key="analysis"
              initial={{ opacity: 0, rotateX: 10, scale: 0.98 }}
              animate={{ opacity: 1, rotateX: 0, scale: 1 }}
              exit={{ opacity: 0, rotateX: -6, scale: 0.98 }}
              transition={{ type: "spring", stiffness: 100, damping: 20 }}
              style={{ perspective: 1200 }}
            >
              {/* status strip */}
              <div className="flex flex-wrap items-center gap-3 mb-4">
                <span className="font-mono text-[11px] text-slate-500">scan://<span className="text-cyan-300">{scanId?.slice(0, 8)}</span></span>
                <span className="font-mono text-[11px] text-slate-500">|</span>
                <span className="font-mono text-[11px] text-slate-300 max-w-[240px] truncate">{filename}</span>
                <span className="font-mono text-[11px] text-slate-500">|</span>
                <span className="font-mono text-[11px] text-cyan-300 uppercase tracking-widest">{report?.status || "…"}</span>
                {error && <span className="font-mono text-[11px] text-[#ff6b35]">⚠ {error}</span>}
                <button onClick={reset} className="ml-auto font-mono text-[11px] text-slate-400 hover:text-cyan-300 border border-slate-700 hover:border-cyan-500/50 rounded px-3 py-1">
                  ⟲ NEW TARGET
                </button>
              </div>

              {/* mode tabs */}
              <div className="flex gap-2 mb-4 overflow-x-auto">
                {MODES.map((m) => {
                  const on = mode === m.key;
                  const available = m.needs(report);
                  return (
                    <button
                      key={m.key}
                      disabled={!available}
                      onClick={() => {
                        setMode(m.key);
                        setAutoAdvance(false);
                      }}
                      className={`px-3 py-1.5 rounded-md font-display text-[11px] tracking-[0.2em] border transition-all whitespace-nowrap ${
                        on
                          ? "border-[#00f0ff] text-[#00f0ff] bg-[#00f0ff]/10 holo-glow-cyan"
                          : available
                            ? "border-slate-700 text-slate-400 hover:border-cyan-500/40"
                            : "border-slate-800 text-slate-700 cursor-not-allowed"
                      }`}
                    >
                      {m.icon} {m.label}
                    </button>
                  );
                })}
              </div>

              {/* 3-column layout */}
              <div className="grid grid-cols-1 lg:grid-cols-[260px_1fr_300px] gap-4">
                {/* left */}
                <div className="space-y-4">
                  <EngineStatusPanel status={report?.status} dynamic={report?.dynamic} power={report?.power_rules} verdict={report?.verdict} />
                  <WebglGate fallback={<div className="holo-glass rounded-xl p-4 font-mono text-[11px] text-slate-400">GAUGE OFFLINE — NO WEBGL</div>}>
                    <RiskMeter score={report?.risk_score} breakdown={report?.risk_breakdown} verdict={report?.verdict} />
                  </WebglGate>
                </div>

                {/* center stage */}
                <div className="holo-glass holo-corners rounded-xl p-3 min-h-[540px]">
                  <AnimatePresence mode="wait">
                    <motion.div
                      key={mode}
                      initial={{ opacity: 0, scale: 0.94, rotateY: -4 }}
                      animate={{ opacity: 1, scale: 1, rotateY: 0 }}
                      exit={{ opacity: 0, scale: 0.96, rotateY: 4 }}
                      transition={{ type: "spring", stiffness: 110, damping: 18 }}
                      className="h-full"
                    >
                      {mode === "autopsy" && (
                        <WebglGate fallback={<FlatFallback report={report} mode="autopsy" />}>
                          <AutopsyVisualizer staticData={report?.static} />
                        </WebglGate>
                      )}
                      {mode === "deception" && (
                        <WebglGate fallback={<FlatFallback report={report} mode="deception" />}>
                          <SandboxComparison dynamic={report?.dynamic} />
                        </WebglGate>
                      )}
                      {mode === "holodeck" && (
                        <WebglGate fallback={<FlatFallback report={report} mode="holodeck" />}>
                          <GridImpactTwin impact={report?.grid_impact} />
                        </WebglGate>
                      )}
                      {mode === "narrator" && (
                        <WebglGate fallback={<FlatFallback report={report} mode="narrator" />}>
                          <ProsecutorReport text={report?.prosecutor_report} verdict={report?.verdict} />
                        </WebglGate>
                      )}
                    </motion.div>
                  </AnimatePresence>
                </div>

                {/* right stream */}
                <div className="space-y-4">
                  <div className="holo-glass holo-corners rounded-xl p-3">
                    <h3 className="font-display text-xs tracking-[0.3em] text-cyan-300 holo-glow-cyan mb-2">
                      DATA STREAM
                    </h3>
                    <div className="terminal rounded-lg px-3 py-2 h-[320px] overflow-hidden">
                      <TerminalText key={scanId + report?.status} lines={streamLines} speed={12} />
                    </div>
                  </div>

                  <div className="holo-glass rounded-xl p-3">
                    <h3 className="font-display text-xs tracking-[0.3em] text-cyan-300 holo-glow-cyan mb-2">
                      TARGET PROFILE
                    </h3>
                    <div className="space-y-1.5 font-mono text-[11px]">
                      <Row k="FORMAT" v={report?.static?.file_type || "—"} />
                      <Row k="SIZE" v={report?.static?.basic_info?.size_human || "—"} />
                      <Row k="SIGNED" v={report?.static?.basic_info?.is_signed ? "YES" : "NO"} c={report?.static?.basic_info?.is_signed ? "#00ff88" : "#ff6b35"} />
                      <Row k="VENDOR" v={report?.static?.basic_info?.claimed_vendor || "—"} />
                      <Row k="ARCH" v={report?.static?.basic_info?.architecture || "—"} />
                      <Row k="PACKER" v={report?.static?.packer_name || "NONE"} c={report?.static?.packer_detected ? "#ff6b35" : "#00ff88"} />
                      <Row k="MODBUS" v={report?.static?.has_modbus_strings ? "DETECTED" : "NONE"} c={report?.static?.has_modbus_strings ? "#ff6b35" : "#64748b"} />
                    </div>
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </main>

      <footer className="relative z-10 border-t border-cyan-500/10 py-3 text-center font-mono text-[10px] tracking-[0.3em] text-slate-600">
        GRIDSENTINEL v2.5 · PROJECT JARVIS · AIR-GAPPED · NO EXTERNAL API CALLS
      </footer>
    </div>
  );
}

function Row({ k, v, c = "#e2e8f0" }) {
  return (
    <div className="flex justify-between gap-2">
      <span className="text-slate-500">{k}</span>
      <span className="text-right break-all" style={{ color: c }}>{v}</span>
    </div>
  );
}
