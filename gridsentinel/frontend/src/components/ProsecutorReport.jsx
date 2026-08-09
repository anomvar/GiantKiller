import { useEffect, useMemo, useRef } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import { OrbitControls, Html, Text, Float } from "@react-three/drei";
import { EffectComposer, Bloom, Vignette } from "@react-three/postprocessing";
import gsap from "gsap";
import { useTypewriter } from "../hooks/useTypewriter";

const CYAN = "#00f0ff";
const ORANGE = "#ff6b35";
const RED = "#ff2d55";
const GREEN = "#00ff88";
const AMBER = "#ffd166";

const KEYWORDS = {
  MALICIOUS: "#ff2d55",
  SUSPICIOUS: "#ffd166",
  CLEAN: "#00ff88",
  CRITICAL: "#ff2d55",
  HIGH: "#ff6b35",
  MEDIUM: "#ffd166",
  Modbus: "#ff6b35",
  SCADA: "#00f0ff",
  C2: "#ff6b35",
  beacon: "#ff6b35",
  injection: "#ff6b35",
  trojan: "#ff2d55",
  quarantine: "#ff6b35",
  VERDICT: "#00f0ff",
  RECOMMENDATION: "#00f0ff",
  "GRID IMPACT": "#00f0ff",
};

const KEYWORD_RE = new RegExp(`\\b(${Object.keys(KEYWORDS).join("|")})\\b`, "i");

const SECTION_ICONS = {
  STATIC: "🛡",
  DYNAMIC: "🌐",
  HEURISTIC: "🧠",
  POWER: "⚡",
  GRID: "🏭",
  VERDICT: "⚖",
  RECOMMENDATION: "🚫",
};

let lastPulse = 0;

function KeywordSpan({ text }) {
  useEffect(() => {
    const now = Date.now();
    if (now - lastPulse > 600) {
      lastPulse = now;
      window.dispatchEvent(new CustomEvent("gridsentinel:pulse"));
    }
  }, []);
  return (
    <span className="font-bold keyword-flash" style={{ color: KEYWORDS[text] || ORANGE, textShadow: `0 0 10px ${KEYWORDS[text] || ORANGE}` }}>
      {text}
    </span>
  );
}

function tokenizeLine(line) {
  const parts = line.split(KEYWORD_RE);
  return parts.filter(Boolean).map((part) => {
    const kw = Object.keys(KEYWORDS).find((k) => k.toLowerCase() === part.toLowerCase());
    return kw ? { text: part, keyword: true } : { text: part, keyword: false };
  });
}

function sectionIcon(line) {
  const upper = line.toUpperCase();
  for (const key of Object.keys(SECTION_ICONS)) {
    if (upper.startsWith(key)) return SECTION_ICONS[key];
  }
  return null;
}

/* ------------------------------ DOM tape -------------------------------- */

function Holotape({ text, verdict }) {
  const { revealed, done } = useTypewriter(text || "", 10, 600);
  const lines = useMemo(() => (revealed || "").split("\n"), [revealed]);
  const stampColor = verdict === "MALICIOUS" ? RED : verdict === "SUSPICIOUS" ? AMBER : GREEN;

  return (
    <div
      className="terminal rounded-lg"
      style={{ width: 600, background: "rgba(3,7,16,0.9)", overflow: "hidden" }}
    >
      <div className="flex items-center justify-between px-3 py-1.5 border-b border-cyan-500/20">
        <span className="font-mono text-[10px] tracking-[0.3em] text-cyan-300">// AI NARRATOR · FORENSIC TRANSCRIPT</span>
        <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" style={{ boxShadow: "0 0 8px #00f0ff" }} />
      </div>
      <div className="px-4 py-3 font-mono text-[11px] leading-6 text-slate-300" style={{ maxHeight: 320, overflow: "auto" }}>
        {lines.map((line, i) => {
          const icon = sectionIcon(line);
          const tokens = tokenizeLine(line);
          return (
            <div key={i} className="whitespace-pre-wrap">
              {icon && <span className="mr-1">{icon} </span>}
              {tokens.map((t, j) =>
                t.keyword ? <KeywordSpan key={j} text={t.text} /> : <span key={j}>{t.text}</span>
              )}
            </div>
          );
        })}
        {!done && <span className="cursor-blink ml-1" />}
      </div>
      {done && (
        <div className="relative px-4 py-3 border-t border-cyan-500/20 stamp-box">
          <div className={`stamp-ring ${done ? "on" : ""}`} />
          <div
            className="inline-block rounded-lg border-2 px-4 py-1.5 font-display font-black tracking-[0.3em]"
            style={{ color: stampColor, borderColor: stampColor, background: `${stampColor}11`, boxShadow: `0 0 24px ${stampColor}66` }}
          >
            VERDICT: {verdict || "PENDING"}
          </div>
        </div>
      )}
    </div>
  );
}

/* ------------------------------ 3D stamp -------------------------------- */

function Stamp3D({ active, verdict }) {
  const group = useRef();
  const ring = useRef();
  const color = verdict === "MALICIOUS" ? RED : verdict === "SUSPICIOUS" ? AMBER : GREEN;

  useEffect(() => {
    if (active && group.current) {
      gsap.fromTo(group.current.scale, { x: 3.4, y: 3.4, z: 3.4 }, { x: 1, y: 1, z: 1, duration: 0.5, ease: "power2.out" });
    }
  }, [active]);

  useFrame((state) => {
    if (ring.current) {
      const k = (state.clock.elapsedTime * 0.7) % 1;
      ring.current.scale.setScalar(0.2 + k * 4.5);
      ring.current.material.opacity = 1 - k;
    }
  });

  if (!active) return null;
  return (
    <group position={[0, 1.3, 1.4]}>
      <group ref={group}>
        <Text fontSize={0.42} color={color} anchorX="center" strokeWidth={0.03} strokeColor="#000000">
          VERDICT: {verdict}
        </Text>
      </group>
      <mesh ref={ring}>
        <ringGeometry args={[0.45, 0.56, 48]} />
        <meshBasicMaterial color={ORANGE} transparent side={2} toneMapped={false} />
      </mesh>
    </group>
  );
}

/* ------------------------------ glyphs --------------------------------- */

function Glyph({ position, color, kind }) {
  return (
    <Float speed={2.4} rotationIntensity={1.4} floatIntensity={1.2}>
      <mesh position={position}>
        {kind === "shield" ? (
          <icosahedronGeometry args={[0.22, 0]} />
        ) : kind === "globe" ? (
          <sphereGeometry args={[0.2, 12, 12]} />
        ) : (
          <octahedronGeometry args={[0.2, 0]} />
        )}
        <meshStandardMaterial color={color} emissive={color} emissiveIntensity={0.9} wireframe={kind === "globe"} toneMapped={false} />
      </mesh>
    </Float>
  );
}

/* ------------------------------ scene ---------------------------------- */

function NarratorScene({ text, verdict, done }) {
  return (
    <group rotation={[-0.12, 0, 0]}>
      {/* holographic document plane */}
      <mesh position={[0, 0, -0.04]}>
        <planeGeometry args={[7.6, 5.6]} />
        <meshBasicMaterial color={CYAN} transparent opacity={0.05} />
      </mesh>
      <mesh position={[0, 0, -0.03]}>
        <planeGeometry args={[7.6, 5.6]} />
        <meshBasicMaterial color={CYAN} wireframe transparent opacity={0.12} toneMapped={false} />
      </mesh>
      <Html transform position={[0, 0, 0]} scale={0.85} style={{ pointerEvents: "none" }}>
        <Holotape text={text} verdict={verdict} />
      </Html>
      <Stamp3D active={done} verdict={verdict} />
      <Glyph position={[-4.4, 1.6, 0.6]} color={GREEN} kind="shield" />
      <Glyph position={[4.3, 1.8, 0.5]} color={CYAN} kind="globe" />
      <Glyph position={[-4.2, -1.6, 0.4]} color={ORANGE} kind="bolt" />
    </group>
  );
}

/* ------------------------------ wrapper -------------------------------- */

export default function ProsecutorReport({ text, verdict }) {
  const { done } = useTypewriter(text || "", 10, 600);
  return (
    <div className="relative h-[470px] rounded-xl overflow-hidden">
      <Canvas dpr={[1, 1.5]} camera={{ position: [0, 1.1, 8.4], fov: 48 }}>
        <color attach="background" args={["#04060c"]} />
        <fog attach="fog" args={["#04060c", 12, 26]} />
        <ambientLight intensity={0.3} />
        <pointLight position={[0, 5, 6]} intensity={30} color={CYAN} />
        <pointLight position={[0, -2, -3]} intensity={10} color={GREEN} />
        <NarratorScene text={text} verdict={verdict} done={done} />
        <OrbitControls enablePan={false} minDistance={4} maxDistance={16} enableDamping dampingFactor={0.08} />
        <EffectComposer>
          <Bloom intensity={1.0} luminanceThreshold={0.2} mipmapBlur />
          <Vignette eskil={false} offset={0.12} darkness={0.85} />
        </EffectComposer>
      </Canvas>
    </div>
  );
}
