import { useCallback, useEffect, useRef, useState } from "react";
import UploadZone from "./components/UploadZone";
import RiskMeter from "./components/RiskMeter";
import AutopsyVisualizer from "./components/AutopsyVisualizer";
import SandboxComparison from "./components/SandboxComparison";
import GridImpactTwin from "./components/GridImpactTwin";
import ProsecutorReport from "./components/ProsecutorReport";
import { getReport } from "./api";

const STAGES = ["static", "sandbox", "heuristic", "grid_impact"];
const STAGE_LABEL = {
  static: "Software Autopsy",
  sandbox: "Deceptive Sandbox",
  heuristic: "ML Anomaly Scan",
  grid_impact: "Grid Impact Twin",
};

function StatusBar({ status, error }) {
  const activeIndex = STAGES.indexOf(status);
  return (
    <div className="w-full">
      <div className="flex items-center gap-2 mb-2">
        {STAGES.map((s, i) => {
          const done = activeIndex > i || status === "complete";
          const active = activeIndex === i;
          return (
            <div key={s} className="flex-1">
              <div
                className={`h-1.5 rounded-full transition-all ${
                  done ? "bg-emerald-400" : active ? "bg-cyan-400 animate-pulseGlow" : "bg-slate-700"
                }`}
              />
              <div className={`text-[10px] font-mono mt-1 ${done ? "text-emerald-300" : active ? "text-cyan-300" : "text-slate-600"}`}>
                {done ? "✓ " : active ? "▶ " : ""}
                {STAGE_LABEL[s]}
              </div>
            </div>
          );
        })}
      </div>
      {error && (
        <div className="text-red-400 text-xs font-mono bg-red-500/10 border border-red-500/40 rounded-lg p-2">
          Scan failed: {error}
        </div>
      )}
    </div>
  );
}

function InfoCard({ label, value, tone = "slate" }) {
  const color =
    tone === "red" ? "text-red-300" : tone === "amber" ? "text-amber-300" : tone === "green" ? "text-emerald-300" : "text-cyan-300";
  return (
    <div className="rounded-lg border border-slate-700/60 bg-slate-900/50 p-3">
      <div className="text-[10px] uppercase tracking-wider text-slate-500 font-mono">{label}</div>
      <div className={`text-sm font-mono ${color} break-all mt-0.5`}>{value}</div>
    </div>
  );
}

function StaticSection({ report }) {
  const static_ = report?.static || {};
  const basic = static_.basic_info || {};
  const rules = report?.power_rules?.triggered_rules || [];

  return (
    <section className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <InfoCard label="Format" value={`${static_.file_type || "?"}`} />
        <InfoCard label="Size" value={basic.size_human || "?"} />
        <InfoCard
          label="Signed"
          value={basic.is_signed ? "YES" : "NO"}
          tone={basic.is_signed ? "green" : "red"}
        />
        <InfoCard
          label="SHA-256"
          value={(basic.sha256 || "").slice(0, 16) + "…"}
        />
        <InfoCard label="Vendor Claim" value={basic.claimed_vendor || "?"} />
        <InfoCard label="Architecture" value={basic.architecture || "?"} />
        <InfoCard
          label="Sections"
          value={(static_.sections || []).length}
          tone={static_.summary?.num_high_entropy_sections ? "amber" : "slate"}
        />
        <InfoCard
          label="YARA Hits"
          value={(static_.yara_matches || []).length}
          tone={(static_.yara_matches || []).length ? "red" : "slate"}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2">
          <h3 className="text-cyan-300 font-semibold mb-2">🧬 Software Autopsy — PE Structure</h3>
          <AutopsyVisualizer data={static_._graph} />
        </div>
        <div className="space-y-4">
          <div className="rounded-xl border border-slate-700/60 bg-slate-900/50 p-4">
            <div className="text-xs text-slate-400 font-mono mb-2 tracking-widest">// FLAGS</div>
            {Object.entries(static_.flags || {}).map(([k, v]) => (
              <div key={k} className="flex items-center justify-between text-xs font-mono py-1">
                <span className="text-slate-400">{k}</span>
                <span className={v ? "text-red-300" : "text-slate-600"}>{v ? "⚠ present" : "—"}</span>
              </div>
            ))}
          </div>
          <div className="rounded-xl border border-slate-700/60 bg-slate-900/50 p-4">
            <div className="text-xs text-slate-400 font-mono mb-2 tracking-widest">// SECTIONS / ENTROPY</div>
            {(static_.sections || []).slice(0, 8).map((s) => (
              <div key={s.name} className="flex items-center justify-between text-xs font-mono py-1">
                <span className="text-slate-300">{s.name}</span>
                <span className={s.high_entropy ? "text-red-300" : "text-slate-500"}>{s.entropy.toFixed(2)}</span>
              </div>
            ))}
          </div>
          <div className="rounded-xl border border-slate-700/60 bg-slate-900/50 p-4">
            <div className="text-xs text-slate-400 font-mono mb-2 tracking-widest">// YARA MATCHES</div>
            {(static_.yara_matches || []).map((m) => (
              <div key={m.rule} className="text-xs font-mono py-1 text-red-300">• {m.rule}</div>
            ))}
            {!(static_.yara_matches || []).length && <div className="text-xs text-slate-600">none</div>}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {Object.entries(static_.strings || {}).filter(([, v]) => v?.length).map(([k, v]) => (
          <div key={k} className="rounded-xl border border-slate-700/60 bg-slate-900/50 p-3">
            <div className="text-[11px] text-slate-400 font-mono mb-1 uppercase tracking-wider">Strings · {k} ({v.length})</div>
            <div className="text-xs font-mono text-red-200/80 break-all space-y-0.5">
              {(v || []).slice(0, 6).map((s, i) => (
                <div key={i} className="truncate">» {s}</div>
              ))}
            </div>
          </div>
        ))}
      </div>

      {rules.length > 0 && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/5 p-4">
          <div className="text-xs text-red-300 font-mono mb-2 tracking-widest">// POWER-SECTOR RULES FIRED</div>
          {rules.map((r) => (
            <div key={r.id} className="flex items-start gap-3 py-1.5">
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                  r.severity === "CRITICAL"
                    ? "bg-red-500/20 text-red-300"
                    : r.severity === "HIGH"
                      ? "bg-amber-500/20 text-amber-300"
                      : "bg-slate-700 text-slate-300"
                }`}
              >
                {r.id} · {r.severity}
              </span>
              <div className="text-xs">
                <div className="text-slate-200 font-mono">{r.name}</div>
                <div className="text-slate-500">{r.detail}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

export default function App() {
  const [view, setView] = useState("upload");
  const [scanId, setScanId] = useState(null);
  const [filename, setFilename] = useState(null);
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);
  const [polling, setPolling] = useState(false);
  const timerRef = useRef(null);

  const handleScanCreated = useCallback((id, name) => {
    setScanId(id);
    setFilename(name);
    setReport(null);
    setError(null);
    setPolling(true);
    setView("dashboard");
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
    timerRef.current = setTimeout(tick, 500);
    return () => {
      cancelled = true;
      clearTimeout(timerRef.current);
    };
  }, [polling, scanId]);

  return (
    <div className="min-h-screen text-slate-200">
      <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-5 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 to-emerald-500 grid place-items-center text-slate-950 font-bold glow-cyan">
              GS
            </div>
            <div>
              <h1 className="text-lg font-bold tracking-wide text-slate-100">
                GridSentinel
                <span className="text-cyan-400">_</span>
              </h1>
              <p className="text-[10px] text-slate-500 font-mono tracking-widest">
                POWER SECTOR SOFTWARE SECURITY SCANNER · SIH1388
              </p>
            </div>
          </div>
          {view === "dashboard" && (
            <div className="flex items-center gap-3 text-[11px] font-mono">
              <span className="text-slate-500">scan://</span>
              <span className="text-cyan-300">{scanId?.slice(0, 8)}</span>
              <span className="text-slate-600">|</span>
              <span className="text-slate-300 max-w-[160px] truncate">{filename}</span>
            </div>
          )}
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-5 py-8">
        {view === "upload" && (
          <>
            <div className="text-center mb-10">
              <div className="inline-block text-[11px] font-mono text-cyan-400 border border-cyan-500/40 rounded-full px-3 py-1 mb-4">
                DETECTION OF MALWARE / TROJAN IN POWER SECTOR SOFTWARE
              </div>
              <h2 className="text-3xl md:text-4xl font-bold text-slate-100">
                A forensic <span className="text-cyan-400">software autopsy</span> for the grid
              </h2>
              <p className="text-slate-400 mt-3 max-w-2xl mx-auto text-sm">
                GridSentinel dissects every binary like a CT scan, runs it through a sandbox that
                <span className="text-emerald-400"> lies to malware</span>, scores it with a trained
                anomaly model, and animates the blackout it would cause — all air-gapped, all offline.
              </p>
            </div>
            <UploadZone onScanCreated={handleScanCreated} />
          </>
        )}

        {view === "dashboard" && (
          <div className="space-y-8">
            <StatusBar status={report?.status} error={error} />

            {report?.status && (
              <div className="grid grid-cols-1 lg:grid-cols-4 gap-4 items-start">
                <div className="rounded-xl border border-slate-700/60 bg-slate-900/50 p-5 flex justify-center">
                  <RiskMeter
                    score={report.risk_score}
                    breakdown={report.risk_breakdown}
                    verdict={report.verdict}
                  />
                </div>
                <div className="lg:col-span-3 grid grid-cols-2 md:grid-cols-3 gap-3">
                  <InfoCard label="Scan Status" value={report.status} />
                  <InfoCard label="SHA-256" value={(report.sha256 || "").slice(0, 16) + "…"} />
                  <InfoCard label="Verdict" value={report.verdict} tone={report.verdict === "MALICIOUS" ? "red" : report.verdict === "SUSPICIOUS" ? "amber" : "green"} />
                  <InfoCard label="Static Score" value={report.risk_breakdown?.static ?? "—"} />
                  <InfoCard label="Dynamic Score" value={report.risk_breakdown?.dynamic ?? "—"} />
                  <InfoCard label="Heuristic %ile" value={report.risk_breakdown?.heuristic ?? "—"} />
                </div>
              </div>
            )}

            {report?.static && Object.keys(report.static).length > 0 && <StaticSection report={report} />}

            {report?.dynamic && Object.keys(report.dynamic).length > 0 && (
              <section className="pt-2">
                <SandboxComparison dynamic={report.dynamic} />
              </section>
            )}

            {report?.status === "complete" && report?.grid_impact && (
              <section className="pt-2">
                <GridImpactTwin impact={report.grid_impact} />
              </section>
            )}

            {report?.status === "complete" && report?.prosecutor_report && (
              <section className="pt-2">
                <ProsecutorReport text={report.prosecutor_report} verdict={report.verdict} />
              </section>
            )}

            {report?.status === "processing" && (
              <div className="text-center text-sm text-slate-500 font-mono animate-pulseGlow">
                analyzing… engines running sequentially
              </div>
            )}
          </div>
        )}
      </main>

      <footer className="border-t border-slate-800 py-4 text-center text-[10px] font-mono text-slate-600">
        GridSentinel v2.4 · SIH1388 · fully air-gapped · no external API calls
      </footer>
    </div>
  );
}
