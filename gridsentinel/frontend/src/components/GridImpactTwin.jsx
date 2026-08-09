import { useEffect, useMemo, useRef, useState } from "react";
import { Canvas, useFrame, useThree } from "@react-three/fiber";
import { OrbitControls, Text, Html, Line, MeshReflectorMaterial, Sparkles } from "@react-three/drei";
import { EffectComposer, Bloom, Vignette } from "@react-three/postprocessing";
import * as THREE from "three";

const CYAN = "#00f0ff";
const ORANGE = "#ff6b35";
const RED = "#ff2d55";
const GREEN = "#00ff88";

/* ------------------------------ path math ------------------------------ */

const NODE3D = {
  SCADA_HMI: [-4.2, 0, -2.5],
  Relay_1: [-1.3, 0, -2.5],
  Transformer_T3: [1.5, 0, -2.5],
  Bus_3: [4.0, 0, -2.5],
  Load_A: [6.4, 0, 0.2],
  Load_B: [6.4, 0, -5.2],
};

const PULSE_POINTS = [
  NODE3D.SCADA_HMI,
  NODE3D.Relay_1,
  NODE3D.Transformer_T3,
  NODE3D.Bus_3,
  NODE3D.Load_A,
  NODE3D.Bus_3,
  NODE3D.Load_B,
];

function computePath() {
  const segs = [];
  for (let i = 0; i < PULSE_POINTS.length - 1; i++) {
    const [x1, y1, z1] = PULSE_POINTS[i];
    const [x2, y2, z2] = PULSE_POINTS[i + 1];
    segs.push({ a: [x1, y1, z1], b: [x2, y2, z2], len: Math.hypot(x2 - x1, y2 - y1, z2 - z1) });
  }
  const total = segs.reduce((s, x) => s + x.len, 0);
  let cum = 0;
  const cumAt = segs.map((s) => {
    cum += s.len;
    return cum;
  });
  const arrivalIdx = { SCADA_HMI: 0, Relay_1: 1, Transformer_T3: 2, Bus_3: 3, Load_A: 4, Load_B: 6 };
  const arrivals = {};
  for (const [id, idx] of Object.entries(arrivalIdx)) {
    arrivals[id] = idx === 0 ? 0 : cumAt[idx - 1] / total;
  }
  return { segs, total, cumAt, arrivals };
}

const { segs, total, cumAt, arrivals } = computePath();

function pulsePosition(progress) {
  const dist = Math.max(0, Math.min(1, progress)) * total;
  for (let i = 0; i < segs.length; i++) {
    const startCum = i === 0 ? 0 : cumAt[i - 1];
    if (dist <= cumAt[i]) {
      const k = (dist - startCum) / segs[i].len;
      return {
        x: segs[i].a[0] + (segs[i].b[0] - segs[i].a[0]) * k,
        y: segs[i].a[1] + (segs[i].b[1] - segs[i].a[1]) * k,
        z: segs[i].a[2] + (segs[i].b[2] - segs[i].a[2]) * k,
      };
    }
  }
  const last = segs[segs.length - 1];
  return { x: last.b[0], y: last.b[1], z: last.b[2] };
}

/* ------------------------------ node meshes ---------------------------- */

function ScadaNode({ infected }) {
  const c = infected ? RED : CYAN;
  return (
    <group>
      <mesh position={[0, 0.45, 0]}>
        <boxGeometry args={[0.9, 0.9, 0.7]} />
        <meshStandardMaterial color="#0a2440" emissive={c} emissiveIntensity={infected ? 1.4 : 0.25} />
      </mesh>
      <mesh position={[0, 0.45, 0.36]}>
        <planeGeometry args={[0.72, 0.5]} />
        <meshBasicMaterial color={c} toneMapped={false} />
      </mesh>
      <Text position={[0, 1.15, 0]} fontSize={0.18} color={c} anchorX="center">SCADA HMI</Text>
    </group>
  );
}

function RelayNode({ infected }) {
  const antenna = useRef();
  const c = infected ? RED : GREEN;
  useFrame((_, dt) => {
    if (antenna.current) antenna.current.rotation.y += dt * (infected ? 6 : 1.4);
  });
  return (
    <group>
      <mesh position={[0, 0.7, 0]}>
        <cylinderGeometry args={[0.28, 0.34, 1.4, 8]} />
        <meshStandardMaterial color="#0a2440" emissive={c} emissiveIntensity={infected ? 1.3 : 0.18} />
      </mesh>
      <group ref={antenna} position={[0, 1.5, 0]}>
        <mesh>
          <boxGeometry args={[0.06, 0.6, 0.06]} />
          <meshStandardMaterial color={c} emissive={c} emissiveIntensity={infected ? 2 : 0.5} toneMapped={false} />
        </mesh>
        <mesh position={[0, 0.35, 0]}>
          <sphereGeometry args={[0.08, 8, 8]} />
          <meshBasicMaterial color={c} toneMapped={false} />
        </mesh>
      </group>
      <Text position={[0, 2.05, 0]} fontSize={0.16} color={c} anchorX="center">220kV RELAY</Text>
      {infected && <Sparkles count={16} scale={1.6} size={3.5} speed={1.6} color={ORANGE} />}
    </group>
  );
}

function TransformerNode({ infected }) {
  const c = infected ? RED : CYAN;
  return (
    <group>
      <mesh position={[0, 0.55, 0]}>
        <cylinderGeometry args={[0.5, 0.62, 1.1, 12]} />
        <meshStandardMaterial color="#0a2440" emissive={c} emissiveIntensity={infected ? 1.3 : 0.2} />
      </mesh>
      {[-0.3, 0, 0.3].map((y) => (
        <mesh key={y} position={[0, y, 0]} rotation={[0, 0, Math.PI / 2]}>
          <torusGeometry args={[0.62, 0.03, 8, 24]} />
          <meshStandardMaterial color={c} emissive={c} emissiveIntensity={infected ? 2 : 0.45} toneMapped={false} />
        </mesh>
      ))}
      <Text position={[0, 1.15, 0]} fontSize={0.16} color={c} anchorX="center">400/220kV TX</Text>
    </group>
  );
}

function BusNode({ infected }) {
  const c = infected ? RED : CYAN;
  return (
    <group>
      <mesh position={[0, 0.22, 0]} rotation={[0, 0, Math.PI / 2]}>
        <boxGeometry args={[0.3, 2.6, 0.3]} />
        <meshStandardMaterial color="#0a2440" emissive={c} emissiveIntensity={infected ? 1.4 : 0.35} />
      </mesh>
      <Text position={[0, 0.9, 0]} fontSize={0.16} color={c} anchorX="center">BUS 3</Text>
    </group>
  );
}

function CityNode({ id, infected, lost }) {
  const c = lost ? RED : GREEN;
  const buildings = [
    [0, 0, 0, 0.5, 0.8],
    [0.8, 0, 0.2, 0.4, 0.55],
    [-0.75, 0, -0.2, 0.45, 0.7],
    [0.3, 0, 0.7, 0.35, 0.5],
    [-0.3, 0, -0.8, 0.4, 0.6],
  ];
  return (
    <group>
      {buildings.map(([x, y, z, w, h], i) => (
        <mesh key={i} position={[x, h / 2, z]}>
          <boxGeometry args={[w, h, w]} />
          <meshStandardMaterial
            color="#0a2440"
            emissive={lost ? "#241014" : c}
            emissiveIntensity={lost ? 0.06 : 0.8}
          />
        </mesh>
      ))}
      <Html position={[0, 1.7, 0]} center distanceFactor={10} style={{ pointerEvents: "none" }}>
        <div
          className={`font-mono text-[10px] tracking-widest px-2 py-0.5 rounded border text-center`}
          style={{
            color: lost ? RED : c,
            borderColor: lost ? RED : c,
            background: "rgba(4,7,13,0.75)",
            boxShadow: `0 0 12px ${lost ? RED : c}55`,
            whiteSpace: "nowrap",
          }}
        >
          {id === "Load_A" ? "CITY A · 150MW" : "CITY B · 190MW"} {lost && "· ⚡ POWER LOST"}
        </div>
      </Html>
    </group>
  );
}

/* ------------------------------ pulse + warnings ----------------------- */

function InfectionPulse({ progressRef, active }) {
  const ref = useRef();
  useFrame(() => {
    const p = pulsePosition(progressRef.current);
    if (ref.current) ref.current.position.set(p.x, 0.55, p.z);
  });
  if (!active) return null;
  return (
    <mesh ref={ref}>
      <sphereGeometry args={[0.14, 16, 16]} />
      <meshBasicMaterial color={RED} toneMapped={false} />
    </mesh>
  );
}

function WarningHologram({ active, loadLoss, districts }) {
  const ring = useRef();
  useFrame((state) => {
    if (ring.current) {
      const k = (state.clock.elapsedTime * 0.6) % 1;
      ring.current.scale.setScalar(0.5 + k * 5);
      ring.current.material.opacity = 1 - k;
    }
  });
  if (!active) return null;
  return (
    <group>
      <mesh ref={ring}>
        <ringGeometry args={[0.8, 1.0, 48]} />
        <meshBasicMaterial color={RED} transparent opacity={1} side={2} toneMapped={false} />
      </mesh>
      <Text position={[0, 3.2, -1.5]} fontSize={0.55} color={RED} anchorX="center" strokeWidth={0.02} strokeColor="#000000">
        ⚠ CRITICAL — {loadLoss}MW LOAD LOST
      </Text>
      <Text position={[0, 2.5, -1.5]} fontSize={0.28} color={ORANGE} anchorX="center">
        {districts} DISTRICTS AFFECTED · EST. RESTORATION 4H
      </Text>
    </group>
  );
}

function ShakeCam({ active }) {
  const { camera } = useThree();
  const base = useMemo(() => ({ x: 3.4, y: 5.4, z: 10.5 }), []);
  useFrame((state) => {
    if (!active) return;
    const t = state.clock.elapsedTime;
    camera.position.x = base.x + Math.sin(t * 55) * 0.14;
    camera.position.y = base.y + Math.sin(t * 47 + 1) * 0.1;
    camera.position.z = base.z + Math.sin(t * 61 + 2) * 0.12;
  });
  return null;
}

function PanRig({ playing, progressRef }) {
  const { camera } = useThree();
  useFrame(() => {
    if (!playing) return;
    const p = pulsePosition(progressRef.current);
    const tx = THREE.MathUtils.lerp(camera.position.x, p.x * 0.35, 0.02);
    camera.position.x = tx;
  });
  return null;
}

/* ------------------------------ scene ---------------------------------- */

function GridScene({ progressRef, playingRef, onProgressChange, impact, speedRef }) {
  const [infectedSet, setInfectedSet] = useState(new Set());
  const [warning, setWarning] = useState(false);
  const sparkFired = useRef(false);
  const infectedRef = useRef(new Set());
  const warnRef = useRef(false);

  const loadLoss = impact?.load_loss_mw || 0;
  const districts = impact?.affected_districts || 0;
  const pathNodes = impact?.attack_path || ["SCADA_HMI", "Relay_1", "Transformer_T3", "Bus_3"];

  useFrame((_, delta) => {
    if (playingRef.current) {
      const speed = speedRef?.current || 1;
      progressRef.current = (progressRef.current + delta * 0.12 * speed) % 1;
      onProgressChange(progressRef.current);
    }
    const p = progressRef.current;
    const infected = new Set();
    for (const id of pathNodes) if (p >= (arrivals[id] ?? 1)) infected.add(id);
    for (const id of ["Load_A", "Load_B"]) if (p >= (arrivals[id] ?? 1)) infected.add(id);
    if (infected.has("Relay_1") && !sparkFired.current) {
      sparkFired.current = true;
      setTimeout(() => (sparkFired.current = false), 2500);
    }
    const changed =
      infected.size !== infectedRef.current.size ||
      [...infected].some((id) => !infectedRef.current.has(id));
    if (changed) {
      infectedRef.current = infected;
      setInfectedSet(infected);
    }
    const warn = p >= 0.985;
    if (warn !== warnRef.current) {
      warnRef.current = warn;
      setWarning(warn);
    }
  });

  return (
    <group>
      {/* reflective floor */}
      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.01, -1]}>
        <planeGeometry args={[22, 22]} />
        <MeshReflectorMaterial
          blur={[240, 90]}
          resolution={512}
          mixBlur={1}
          mixStrength={30}
          roughness={0.9}
          depthScale={1.1}
          minDepthThreshold={0.4}
          maxDepthThreshold={1.3}
          color="#04070d"
          metalness={0.6}
          mirror={0.7}
        />
      </mesh>

      {/* grid wires */}
      <Line points={[NODE3D.SCADA_HMI, NODE3D.Relay_1]} color={infectedSet.has("Relay_1") ? RED : CYAN} lineWidth={1.2} transparent opacity={0.5} />
      <Line points={[NODE3D.Relay_1, NODE3D.Transformer_T3]} color={infectedSet.has("Transformer_T3") ? RED : CYAN} lineWidth={1.2} transparent opacity={0.5} />
      <Line points={[NODE3D.Transformer_T3, NODE3D.Bus_3]} color={infectedSet.has("Bus_3") ? RED : CYAN} lineWidth={1.2} transparent opacity={0.5} />
      <Line points={[NODE3D.Bus_3, NODE3D.Load_A]} color={infectedSet.has("Load_A") ? RED : GREEN} lineWidth={1.2} transparent opacity={0.5} />
      <Line points={[NODE3D.Bus_3, NODE3D.Load_B]} color={infectedSet.has("Load_B") ? RED : GREEN} lineWidth={1.2} transparent opacity={0.5} />

      <group position={NODE3D.SCADA_HMI}>
        <ScadaNode infected={infectedSet.has("SCADA_HMI")} />
      </group>
      <group position={NODE3D.Relay_1}>
        <RelayNode infected={infectedSet.has("Relay_1")} />
      </group>
      <group position={NODE3D.Transformer_T3}>
        <TransformerNode infected={infectedSet.has("Transformer_T3")} />
      </group>
      <group position={NODE3D.Bus_3}>
        <BusNode infected={infectedSet.has("Bus_3")} />
      </group>
      <group position={NODE3D.Load_A}>
        <CityNode id="Load_A" infected={infectedSet.has("Load_A")} lost={infectedSet.has("Load_A")} />
      </group>
      <group position={NODE3D.Load_B}>
        <CityNode id="Load_B" infected={infectedSet.has("Load_B")} lost={infectedSet.has("Load_B")} />
      </group>

      <InfectionPulse progressRef={progressRef} active={pathNodes.length > 1} />
      <PanRig playing={playingRef.current} progressRef={progressRef} />
      <ShakeCam active={warning} />
      <WarningHologram active={warning} loadLoss={loadLoss} districts={districts} />
    </group>
  );
}

/* ------------------------------ wrapper -------------------------------- */

export default function GridImpactTwin({ impact }) {
  const [progress, setProgressState] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const progressRef = useRef(0);
  const playingRef = useRef(false);
  const speedRef = useRef(1);

  const setPlayingBoth = (v) => {
    playingRef.current = v;
    setPlaying(v);
  };
  const onProgressChange = (v) => setProgressState(v);

  const loadALost = progress >= (arrivals.Load_A ?? 1);
  const loadBLost = progress >= (arrivals.Load_B ?? 1);
  const loss = impact?.load_loss_mw || 0;
  const lostMW = loadALost && loadBLost ? loss : loadALost ? Math.round(loss * 0.44) : 0;
  const districts = impact?.affected_districts || 0;
  const lostDistricts = loadALost && loadBLost ? districts : loadALost ? 1 : 0;

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h3 className="font-display text-sm tracking-[0.3em] text-cyan-300 holo-glow-cyan">
          GRID IMPACT — SUBSTATION HOLODECK
        </h3>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setPlayingBoth(!playing)}
            className="px-3 py-1 rounded-md font-mono text-xs border border-cyan-500/50 text-cyan-300 hover:bg-cyan-500/10"
          >
            {playing ? "⏸ HOLD" : "▶ REPLAY ATTACK"}
          </button>
          <select
            value={speed}
            onChange={(e) => {
              const v = parseFloat(e.target.value);
              setSpeed(v);
              speedRef.current = v;
            }}
            className="bg-slate-900 border border-slate-700 text-[11px] font-mono text-slate-300 rounded px-1"
          >
            <option value="0.5">0.5x</option>
            <option value="1">1x</option>
            <option value="2">2x</option>
          </select>
          <input
            type="range"
            min="0"
            max="1000"
            value={Math.round(progress * 1000)}
            onChange={(e) => {
              setPlayingBoth(false);
              progressRef.current = e.target.value / 1000;
              onProgressChange(progressRef.current);
            }}
            className="holo-range w-40"
          />
          <span className="font-mono text-[11px] text-cyan-300 w-10">{Math.round(progress * 100)}%</span>
        </div>
      </div>

      <div className="relative h-[430px] rounded-xl overflow-hidden">
        <Canvas dpr={[1, 1.5]} camera={{ position: [3.4, 5.4, 10.5], fov: 45 }}>
          <color attach="background" args={["#04060c"]} />
          <fog attach="fog" args={["#04060c", 14, 34]} />
          <ambientLight intensity={0.25} />
          <pointLight position={[0, 8, 6]} intensity={40} color={CYAN} />
          <pointLight position={[-6, 2, -4]} intensity={16} color={GREEN} />
          <pointLight position={[6, -1, 6]} intensity={12} color={ORANGE} />
          <GridScene
            progressRef={progressRef}
            playingRef={playingRef}
            onProgressChange={onProgressChange}
            impact={impact}
            speedRef={speedRef}
          />
          <OrbitControls enableDamping dampingFactor={0.08} minDistance={4} maxDistance={24} target={[0, 1.5, -1]} />
          <EffectComposer>
            <Bloom intensity={1.2} luminanceThreshold={0.2} mipmapBlur />
            <Vignette eskil={false} offset={0.1} darkness={0.85} />
          </EffectComposer>
        </Canvas>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          ["LOAD LOST", `${lostMW} MW`, "text-[#ff6b35]"],
          ["DISTRICTS", lostDistricts, "text-[#ffd166]"],
          ["RESTORATION", `${impact?.restoration_hours || 0} h`, "text-cyan-300"],
          ["PATH DEPTH", impact?.attack_path?.length || 0, "text-[#00ff88]"],
        ].map(([label, val, color]) => (
          <div key={label} className="holo-glass rounded-lg p-2.5 text-center">
            <div className={`font-display text-xl font-bold ${color} holo-glow-cyan`}>{val}</div>
            <div className="font-mono text-[9px] tracking-widest text-slate-500">{label}</div>
          </div>
        ))}
      </div>

      {impact?.cascading_effect && (
        <div className="holo-glass holo-glass-threat rounded-lg px-3 py-2 font-mono text-xs text-[#ffb59b]">
          ▸ CASCADE: {impact.cascading_effect}
        </div>
      )}
    </div>
  );
}
