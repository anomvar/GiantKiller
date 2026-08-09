import { motion, AnimatePresence } from "framer-motion";
import TerminalText from "./TerminalText";

const ENGINES = [
  { key: "static", name: "STATIC ENGINE", sub: "SOFTWARE AUTOPSY", color: "#00f0ff" },
  { key: "sandbox", name: "SANDBOX ENGINE", sub: "DECEPTIVE CHAMBER", color: "#00ff88" },
  { key: "heuristic", name: "ML ENGINE", sub: "ANOMALY ISOLATION", color: "#ffd166" },
  { key: "grid_impact", name: "IMPACT ENGINE", sub: "GRID HOLODECK", color: "#ff6b35" },
];

const STAGE_ORDER = ["static", "sandbox", "heuristic", "grid_impact"];

function buildStatusLines(status, dynamic, power) {
  const lines = ["> GRIDSENTINEL ANALYSIS PIPELINE INITIALIZED"];
  const idx = status === "complete" ? STAGE_ORDER.length : STAGE_ORDER.indexOf(status);
  for (let i = 0; i < STAGE_ORDER.length; i++) {
    const done = status === "complete" || i < idx;
    lines.push(
      `> ${ENGINES[i].name}: ${done ? "COMPLETE" : i === idx ? "RUNNING..." : "QUEUED"}`
    );
  }
  if (dynamic?.activated) {
    lines.push("> DECEPTION SUCCESSFUL — PAYLOAD ACTIVATED");
  } else if (dynamic && status !== "complete") {
    lines.push("> SAMPLE DORMANT IN STANDARD SANDBOX");
  }
  if (power?.critical) {
    lines.push(`> CRITICAL POWER-SECTOR RULES FIRED (${power.critical})`);
  }
  return lines;
}

export default function EngineStatusPanel({ status = "pending", dynamic, power, verdict }) {
  const stageIndex = status === "complete" ? 4 : Math.max(0, STAGE_ORDER.indexOf(status));
  const lines = buildStatusLines(status, dynamic, power);

  return (
    <div className="holo-glass holo-corners rounded-xl p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="font-display text-xs tracking-[0.3em] text-cyan-300 holo-glow-cyan">
          ENGINE MATRIX
        </h3>
        <AnimatePresence>
          {verdict && (
            <motion.span
              initial={{ scale: 2, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              className={`font-display text-xs font-bold tracking-widest ${
                verdict === "MALICIOUS"
                  ? "text-[#ff6b35] holo-glow-orange"
                  : verdict === "SUSPICIOUS"
                    ? "text-[#ffd166] holo-glow-orange"
                    : "text-[#00ff88] holo-glow-green"
              }`}
            >
              {verdict}
            </motion.span>
          )}
        </AnimatePresence>
      </div>

      <div className="relative flex items-center justify-between px-2 py-2">
        {/* connecting beam */}
        <div className="absolute left-5 right-5 top-1/2 h-[2px] bg-[#00f0ff]/10" />
        {ENGINES.map((eng, i) => {
          const lit = status === "complete" ? 2 : i < stageIndex ? 2 : i === stageIndex ? 1 : 0;
          return (
            <motion.div
              key={eng.key}
              className="relative z-10 flex flex-col items-center gap-1.5"
              animate={lit === 2 ? { scale: 1 } : lit === 1 ? { scale: [1, 1.15, 1] } : { scale: 0.92 }}
              transition={lit === 1 ? { repeat: Infinity, duration: 0.9 } : { duration: 0.3 }}
            >
              <div
                className="w-8 h-8 rounded-full grid place-items-center border"
                style={{
                  borderColor: lit ? eng.color : "#1e293b",
                  background: lit === 2 ? `${eng.color}22` : "#0a0f1c",
                  boxShadow: lit ? `0 0 14px ${eng.color}80, inset 0 0 8px ${eng.color}40` : "none",
                }}
              >
                <span
                  className="font-display font-bold text-[11px]"
                  style={{ color: lit ? eng.color : "#475569" }}
                >
                  {String(i + 1).padStart(2, "0")}
                </span>
              </div>
              <span
                className={`font-mono text-[8px] tracking-widest text-center ${
                  lit ? "text-slate-300" : "text-slate-600"
                }`}
              >
                {eng.name}
              </span>
            </motion.div>
          );
        })}
      </div>

      <div className="terminal rounded-lg px-3 py-2 mt-3 h-[104px] overflow-hidden">
        <TerminalText key={status} lines={lines} speed={10} />
      </div>
    </div>
  );
}
