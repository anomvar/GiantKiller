import { useMemo, useRef } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import { Text, Sparkles, Float } from "@react-three/drei";
import { EffectComposer, Bloom } from "@react-three/postprocessing";

const ZONES = {
  low: { from: 0, to: 30, color: "#00f0ff" },
  mid: { from: 30, to: 70, color: "#ffd166" },
  high: { from: 70, to: 100, color: "#ff6b35" },
};

function zoneFor(score) {
  if (score >= 70) return ZONES.high;
  if (score >= 30) return ZONES.mid;
  return ZONES.low;
}

function ArcRing({
  radius = 1.4,
  tube = 0.035,
  fraction = 1,
  color = "#00f0ff",
  opacity = 0.9,
  intensity = 0.9,
  spin = 0,
  startAngle = 0,
  position = [0, 0, 0],
  track = false,
}) {
  const ref = useRef();
  useFrame((_, delta) => {
    if (ref.current && spin) ref.current.rotation.z += delta * spin;
  });
  return (
    <group position={position}>
      {track && (
        <mesh>
          <torusGeometry args={[radius, tube, 12, 128]} />
          <meshStandardMaterial color="#00f0ff" transparent opacity={0.08} toneMapped={false} />
        </mesh>
      )}
      <mesh ref={ref} rotation={[0, 0, startAngle]}>
        <torusGeometry args={[radius, tube, 12, 96, Math.max(0.0001, Math.PI * 2 * fraction)]} />
        <meshStandardMaterial
          color={color}
          emissive={color}
          emissiveIntensity={intensity}
          transparent
          opacity={opacity}
          toneMapped={false}
        />
      </mesh>
    </group>
  );
}

function Satellite({ label, value, position, color }) {
  return (
    <group position={position}>
      <ArcRing radius={0.42} tube={0.02} fraction={Math.max(0.03, value / 100)} color={color} intensity={0.8} startAngle={-Math.PI / 2} />
      <Text position={[0, 0, 0]} fontSize={0.22} color={color} anchorX="center" anchorY="middle">
        {value}
      </Text>
      <Text position={[0, -0.5, 0]} fontSize={0.12} color="#64748b" anchorX="center">
        {label.toUpperCase()}
      </Text>
    </group>
  );
}

function Gauge({ score, breakdown }) {
  const zone = zoneFor(score || 0);
  const spinSpeed = useMemo(() => {
    if (score >= 70) return 1.4;
    if (score >= 30) return 0.7;
    return 0.25;
  }, [score]);
  const satellites = [
    { label: "Static", value: breakdown?.static ?? 0, pos: [3.1, 1.5, 0], color: "#00f0ff" },
    { label: "Dynamic", value: breakdown?.dynamic ?? 0, pos: [-3.1, 1.5, 0], color: "#00ff88" },
    { label: "Heuristic", value: breakdown?.heuristic ?? 0, pos: [3.1, -1.5, 0], color: "#ffd166" },
    { label: "Power", value: breakdown?.power_rules ?? 0, pos: [-3.1, -1.5, 0], color: "#ff6b35" },
  ];

  return (
    <group>
      <Float speed={2} rotationIntensity={0.2} floatIntensity={0.6}>
        <ArcRing fraction={1} color={zone.color} opacity={0.15} intensity={0.35} track spin={spinSpeed * 0.4} />
        <ArcRing fraction={(score || 0) / 100} color={zone.color} spin={spinSpeed} startAngle={-Math.PI / 2} intensity={1.4} />
        {score >= 70 && <Sparkles count={26} scale={4.2} size={4} speed={1.4} color="#ff6b35" opacity={0.8} />}
      </Float>

      <Text position={[0, 0.15, 0]} fontSize={0.9} fontWeight="900" color={zone.color} anchorX="center" anchorY="middle">
        {score ?? 0}
      </Text>
      <Text position={[0, -0.55, 0]} fontSize={0.18} color="#94a3b8" anchorX="center">
        RISK / 100
      </Text>

      {satellites.map((s) => (
        <Satellite key={s.label} {...s} />
      ))}
    </group>
  );
}

export default function RiskMeter({ score, breakdown, verdict }) {
  const zone = zoneFor(score || 0);
  return (
    <div className="holo-glass holo-corners rounded-xl p-3">
      <div className="flex items-center justify-between px-1 mb-1">
        <h3 className="font-display text-xs tracking-[0.3em] text-cyan-300 holo-glow-cyan">
          THREAT GAUGE
        </h3>
        <span
          className="font-mono text-[10px] tracking-widest"
          style={{ color: zone.color, textShadow: `0 0 8px ${zone.color}` }}
        >
          {verdict || "PENDING"}
        </span>
      </div>
      <div className="w-full h-[330px]">
        <Canvas dpr={[1, 1.5]} camera={{ position: [0, 0, 7.5], fov: 45 }}>
          <color attach="background" args={["#05070d"]} />
          <ambientLight intensity={0.4} />
          <pointLight position={[0, 4, 6]} intensity={30} color={zone.color} />
          <pointLight position={[-6, -2, 2]} intensity={8} color="#00f0ff" />
          <Gauge score={score} breakdown={breakdown} />
          <EffectComposer>
            <Bloom intensity={0.9} luminanceThreshold={0.25} mipmapBlur />
          </EffectComposer>
        </Canvas>
      </div>
      <div className="flex justify-between px-1 font-mono text-[9px] text-slate-500">
        <span>SAFE 0</span>
        <span>ALERT 30</span>
        <span>CRITICAL 70</span>
        <span>100</span>
      </div>
    </div>
  );
}
