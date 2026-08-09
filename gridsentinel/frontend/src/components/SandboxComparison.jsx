import { useEffect, useMemo, useRef, useState } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import { OrbitControls, Float, Html, Text, Edges, Line, Sparkles } from "@react-three/drei";
import { EffectComposer, Bloom } from "@react-three/postprocessing";
import * as THREE from "three";

const CYAN = "#00f0ff";
const ORANGE = "#ff6b35";
const RED = "#ff2d55";
const GREEN = "#00ff88";
const SLATE = "#475569";

const WALL_POINTS = [
  [2.1, 0.7, 1.0],
  [-2.1, -0.9, -1.1],
  [1.6, 2.05, -0.5],
  [-1.6, 1.7, 1.3],
  [0.9, -2.05, 0.8],
  [0.1, 0.3, -2.2],
  [2.0, -1.1, -1.2],
];

/* ------------------------------ tendrils ------------------------------- */

function Tendril({ target, index }) {
  const pulse = useRef();
  const ring = useRef();
  const fromV = useMemo(() => new THREE.Vector3(0, 0, 0), []);
  const toV = useMemo(() => new THREE.Vector3(...target), [target]);
  const period = 3.2 + (index % 3) * 0.7;

  useFrame((state) => {
    const t = state.clock.elapsedTime;
    const phase = (t / period + index * 0.13) % 1;
    if (pulse.current) {
      pulse.current.position.lerpVectors(fromV, toV, phase);
    }
    if (ring.current) {
      const k = (phase + 0.9) % 1;
      if (k < 0.18) {
        ring.current.scale.setScalar(0.15 + (k / 0.18) * 0.8);
        ring.current.material.opacity = 1 - k / 0.18;
        ring.current.position.set(...target);
      } else {
        ring.current.material.opacity = 0;
      }
    }
  });

  return (
    <group>
      <Line points={[from, target]} color={RED} lineWidth={0.8} transparent opacity={0.45} />
      <mesh ref={pulse}>
        <sphereGeometry args={[0.06, 8, 8]} />
        <meshBasicMaterial color={RED} toneMapped={false} />
      </mesh>
      <mesh ref={ring}>
        <ringGeometry args={[0.2, 0.34, 32]} />
        <meshBasicMaterial color={ORANGE} transparent opacity={0} side={2} toneMapped={false} />
      </mesh>
    </group>
  );
}

/* ------------------------------ chamber -------------------------------- */

function Chamber({ side, activated, isRight }) {
  const orb = useRef();
  const color = isRight ? (activated ? CYAN : SLATE) : SLATE;
  const orbColor = isRight ? (activated ? ORANGE : RED) : RED;

  useFrame((state) => {
    if (orb.current) {
      const t = state.clock.elapsedTime;
      const pulse = isRight && activated ? 1 + Math.sin(t * 5) * 0.06 : 1;
      orb.current.scale.setScalar(pulse);
    }
  });

  return (
    <Float speed={1.6} rotationIntensity={0.15} floatIntensity={0.8}>
      <group position={[side, 0, 0]}>
        {/* chamber shell */}
        <mesh>
          <boxGeometry args={[3.4, 3.4, 3.4]} />
          <meshStandardMaterial
            color="#04070d"
            transparent
            opacity={0.55}
            emissive={isRight && activated ? CYAN : "#1a2438"}
            emissiveIntensity={isRight && activated ? 0.25 : 0.05}
          />
        </mesh>
        <Edges color={isRight && activated ? CYAN : SLATE} scale={1.002} />
        {isRight && activated && (
          <mesh>
            <boxGeometry args={[3.46, 3.46, 3.46]} />
            <meshBasicMaterial color={CYAN} wireframe transparent opacity={0.06} toneMapped={false} />
          </mesh>
        )}

        {/* orb */}
        <mesh ref={orb}>
          <sphereGeometry args={[0.62, 32, 32]} />
          <meshStandardMaterial
            color={orbColor}
            emissive={orbColor}
            emissiveIntensity={isRight && activated ? 2.2 : 0.6}
            toneMapped={false}
          />
        </mesh>

        {isRight && activated ? (
          <>
            {WALL_POINTS.map((p, i) => (
              <Tendril key={i} target={p} index={i} />
            ))}
            <Sparkles count={24} scale={3.4} size={3} speed={1.1} color={ORANGE} />
          </>
        ) : (
          <Sparkles count={8} scale={2.4} size={2} speed={0.2} color={SLATE} />
        )}

        <Text position={[0, -2.3, 0]} fontSize={0.2} color={isRight && activated ? CYAN : "#64748b"} anchorX="center">
          {isRight
            ? activated
              ? "VM MASKED — PAYLOAD ACTIVATED"
              : "SAMPLE DORMANT"
            : "VM DETECTED — PAYLOAD DORMANT"}
        </Text>
      </group>
    </Float>
  );
}

/* ------------------------------ behavior spiral ------------------------ */

function BehaviorSpiral({ behaviors }) {
  const refs = useRef([]);
  const items = behaviors || [];
  useFrame((state) => {
    const t = state.clock.elapsedTime * 0.22;
    items.forEach((_, i) => {
      const g = refs.current[i];
      if (!g) return;
      const ang = t + (i / Math.max(1, items.length)) * Math.PI * 2;
      const rad = 4.4 + Math.sin(t * 0.7 + i) * 0.9;
      g.position.set(Math.cos(ang) * rad, Math.sin(t + i * 0.9) * 1.1, Math.sin(ang) * rad);
    });
  });
  return (
    <group>
      {items.map((b, i) => (
        <group key={i} ref={(el) => (refs.current[i] = el)}>
          <Html center distanceFactor={16} style={{ pointerEvents: "none" }}>
            <div
              className="rounded-md px-2.5 py-1 font-mono text-[10px] whitespace-nowrap"
              style={{
                background: "rgba(6,10,20,0.9)",
                border: `1px solid ${b.suspicious ? ORANGE : CYAN}66`,
                color: b.suspicious ? "#ffd0b8" : "#c8f5ff",
                boxShadow: `0 0 12px ${b.suspicious ? ORANGE : CYAN}44`,
              }}
            >
              {b.description}
            </div>
          </Html>
        </group>
      ))}
    </group>
  );
}

/* ------------------------------ tunnel --------------------------------- */

function DataTunnel({ active }) {
  const stream = useRef([]);
  const n = 10;
  useFrame((state) => {
    const t = state.clock.elapsedTime;
    for (let i = 0; i < n; i++) {
      const m = stream.current[i];
      if (!m) continue;
      const phase = ((t * 0.35 + i / n) % 1);
      m.position.set(-3.4 + phase * 6.8, Math.sin(i * 2.1) * 0.5, Math.cos(i * 2.1) * 0.5);
      m.material.opacity = active ? 0.9 : 0.15;
    }
  });
  return (
    <group rotation={[0, 0, Math.PI / 2]}>
      <mesh>
        <cylinderGeometry args={[0.9, 0.9, 6.8, 24, 1, true]} />
        <meshBasicMaterial color={active ? CYAN : SLATE} transparent opacity={0.05} side={2} toneMapped={false} />
      </mesh>
      <mesh>
        <cylinderGeometry args={[1.0, 1.0, 6.8, 24, 1, true]} />
        <meshBasicMaterial color={active ? CYAN : SLATE} wireframe transparent opacity={0.08} toneMapped={false} />
      </mesh>
      {Array.from({ length: n }).map((_, i) => (
        <mesh key={i} ref={(el) => (stream.current[i] = el)}>
          <sphereGeometry args={[0.05, 6, 6]} />
          <meshBasicMaterial color={active ? GREEN : SLATE} toneMapped={false} />
        </mesh>
      ))}
    </group>
  );
}

/* ------------------------------ wrapper -------------------------------- */

export default function SandboxComparison({ dynamic }) {
  const activated = Boolean(dynamic?.activated);
  const behaviors = dynamic?.behaviors || [];
  const tricks = dynamic?.tricks_used || [];

  return (
    <div className="space-y-3">
      <div className="relative h-[380px] rounded-xl overflow-hidden">
        <Canvas dpr={[1, 1.5]} camera={{ position: [-2.2, 3.2, 10.5], fov: 50 }}>
          <color attach="background" args={["#04060c"]} />
          <fog attach="fog" args={["#04060c", 12, 28]} />
          <ambientLight intensity={0.3} />
          <pointLight position={[0, 6, 6]} intensity={30} color={CYAN} />
          <pointLight position={[-8, -2, -4]} intensity={12} color="#64748b" />
          <Chamber side={-4} activated={false} isRight={false} />
          <Chamber side={4} activated={activated} isRight />
          <DataTunnel active={activated} />
          <BehaviorSpiral behaviors={behaviors} />
          <OrbitControls enablePan={false} minDistance={5} maxDistance={20} enableDamping dampingFactor={0.08} />
          <EffectComposer>
            <Bloom intensity={1.1} luminanceThreshold={0.22} mipmapBlur />
          </EffectComposer>
        </Canvas>

        {/* chamber labels */}
        <div className="absolute top-3 left-4 font-mono text-[10px] tracking-widest text-slate-500">
          // STANDARD SANDBOX — OBSERVATION
        </div>
        <div className="absolute top-3 right-4 font-mono text-[10px] tracking-widest text-cyan-300 holo-glow-cyan">
          // GRIDSENTINEL DECEPTIVE CHAMBER
        </div>
        <div
          className={`absolute bottom-3 left-1/2 -translate-x-1/2 rounded-full px-4 py-1 font-mono text-[10px] tracking-widest border ${
            activated
              ? "border-[#ff6b35]/60 text-[#ff6b35] bg-[#ff6b35]/10 holo-glow-orange"
              : "border-slate-600 text-slate-400 bg-slate-800/40"
          }`}
        >
          {activated ? "▲ PAYLOAD ACTIVATED — BEHAVIORS CAPTURED" : "SAMPLE DORMANT"}
        </div>
      </div>

      {tricks.length > 0 && (
        <div className="holo-glass rounded-xl p-3">
          <div className="font-mono text-[10px] tracking-widest text-cyan-300 mb-2">// ANTI-ANTI-VM TRICKS DEPLOYED</div>
          <div className="flex flex-wrap gap-1.5">
            {tricks.map((t) => (
              <span key={t} className="px-2 py-0.5 rounded-full text-[10px] font-mono border border-cyan-500/40 text-cyan-200 bg-slate-900/60">
                🎭 {t}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
