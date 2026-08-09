import { useEffect, useMemo, useRef, useState } from "react";

const KEYWORDS = {
  MALICIOUS: "text-red-400",
  SUSPICIOUS: "text-amber-300",
  CLEAN: "text-emerald-300",
  CRITICAL: "text-red-400",
  HIGH: "text-amber-300",
  MEDIUM: "text-amber-300",
  Modbus: "text-red-300",
  SCADA: "text-cyan-300",
  C2: "text-red-300",
  beacon: "text-red-300",
  injection: "text-pink-300",
  trojan: "text-red-300",
  quarantine: "text-red-300",
  VERDICT: "text-cyan-300",
  RECOMMENDATION: "text-cyan-300",
  "GRID IMPACT": "text-cyan-300",
};

const KEYWORD_RE = new RegExp(
  `\\b(${Object.keys(KEYWORDS).join("|")})\\b`,
  "i"
);

function tokenize(text) {
  const tokens = [];
  const parts = text.split(KEYWORD_RE);
  for (const part of parts) {
    if (!part) continue;
    const kw = Object.keys(KEYWORDS).find((k) => k.toLowerCase() === part.toLowerCase());
    tokens.push({ text: part, highlight: kw ? KEYWORDS[kw] : null });
  }
  return tokens;
}

export default function ProsecutorReport({ text, verdict }) {
  const tokens = useMemo(() => tokenize(text || ""), [text]);
  const [visible, setVisible] = useState(0);
  const [done, setDone] = useState(false);
  const timer = useRef(null);

  useEffect(() => {
    setVisible(0);
    setDone(false);
    if (timer.current) clearInterval(timer.current);
    timer.current = setInterval(() => {
      setVisible((v) => {
        if (v >= tokens.length) {
          clearInterval(timer.current);
          setDone(true);
          return v;
        }
        return v + 2;
      });
    }, 8);
    return () => clearInterval(timer.current);
  }, [tokens.length]);

  const banner =
    verdict === "MALICIOUS"
      ? { text: "⚠ VERDICT: MALICIOUS", cls: "border-red-500 bg-red-500/15 text-red-300" }
      : verdict === "SUSPICIOUS"
        ? { text: "△ VERDICT: SUSPICIOUS", cls: "border-amber-500 bg-amber-500/15 text-amber-300" }
        : { text: "✓ VERDICT: CLEAN", cls: "border-emerald-500 bg-emerald-500/15 text-emerald-300" };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-cyan-300 font-semibold">👨‍⚖️ Prosecutor AI — Forensic Narrative</h3>
        {!done && (
          <button
            onClick={() => {
              clearInterval(timer.current);
              setVisible(tokens.length);
              setDone(true);
            }}
            className="text-xs font-mono text-slate-500 hover:text-cyan-300"
          >
            [skip typewriter]
          </button>
        )}
      </div>

      <div className="rounded-xl border border-slate-700/60 bg-[#0a101c] p-5 font-mono text-[13px] leading-7 text-slate-300 min-h-[240px] max-h-[520px] overflow-y-auto">
        {tokens.slice(0, visible).map((t, i) =>
          t.highlight ? (
            <span key={i} className={`font-bold ${t.highlight}`}>
              {t.text}
            </span>
          ) : (
            <span key={i}>{t.text}</span>
          )
        )}
        {!done && <span className="typewriter-caret" />}
      </div>

      <div className={`rounded-xl border-2 p-4 text-center text-lg font-bold tracking-widest ${banner.cls}`}>
        {banner.text}
      </div>
    </div>
  );
}
