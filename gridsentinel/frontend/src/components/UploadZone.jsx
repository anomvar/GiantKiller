import { useCallback, useEffect, useRef, useState } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import { Text, Sparkles, Edges } from "@react-three/drei";
import { EffectComposer, Bloom } from "@react-three/postprocessing";
import gsap from "gsap";
import TerminalText from "./TerminalText";
import { uploadFile, triggerScan } from "../api";

const ACCEPTED = [".exe", ".dll", ".msi", ".elf", ".zip", ".bin", ".scr", ".cpl"];

const STATUS_LINES = {
  idle: ["> ACQUISITION PAD STANDBY", "> AWAITING TARGET BINARY"],
  drag: ["> TARGET DETECTED IN FIELD", "> AWAITING RELEASE"],
  acquiring: [],
  complete: ["> TARGET ACQUIRED", "> STAGING FOR AUTOPSY"],
};

function HexPlatform({ phase, progress }) {
  const group = useRef();
  const glow = useRef();
  const beam = useRef();

  useFrame((state) => {
    if (!group.current) return;
    const t = state.clock.elapsedTime;
    group.current.rotation.y += phase === "drag" ? 0.02 : 0.006;
    const pulse = 1 + Math.sin(t * (phase === "acquiring" ? 6 : 2)) * 0.04;
    group.current.scale.setScalar(pulse);
    if (glow.current) {
      glow.current.material.opacity =
        phase === "acquiring" ? 0.55 + Math.sin(t * 8) * 0.2 : 0.3 + Math.sin(t * 2.5) * 0.12;
    }
    if (beam.current && phase === "acquiring") {
      beam.current.position.y = Math.sin(t * 1.6) * 1.5;
      beam.current.material.opacity = 0.5 + Math.sin(t * 20) * 0.2;
    }
  });

  return (
    <group>
      {/* platform */}
      <group ref={group}>
        <mesh position={[0, -0.5, 0]}>
          <cylinderGeometry args={[1.8, 1.8, 0.16, 6]} />
          <meshStandardMaterial
            color={phase === "drag" ? "#00f0ff" : "#0a2440"}
            emissive="#00f0ff"
            emissiveIntensity={phase === "drag" ? 1.4 : 0.35}
            transparent
            opacity={0.85}
            toneMapped={false}
          />
        </mesh>
        <Edges color={phase === "drag" ? "#00f0ff" : "#00f0ff"} scale={1.01} />
        {/* glow disc */}
        <mesh ref={glow} position={[0, -0.38, 0]} rotation={[-Math.PI / 2, 0, 0]}>
          <ringGeometry args={[1.2, 1.85, 64]} />
          <meshBasicMaterial color="#00f0ff" transparent opacity={0.3} side={2} depthWrite={false} toneMapped={false} />
        </mesh>
      </group>

      {/* energy torus */}
      {(phase === "drag" || phase === "acquiring") && (
        <mesh rotation={[Math.PI / 2, 0, 0]} position={[0, 0.4, 0]}>
          <torusGeometry args={[2.3, 0.05, 12, 64]} />
          <meshStandardMaterial color="#00f0ff" emissive="#00f0ff" emissiveIntensity={2} transparent opacity={0.9} toneMapped={false} />
        </mesh>
      )}

      {/* scan beam */}
      {phase === "acquiring" && (
        <mesh ref={beam} position={[0, 0, 0]}>
          <boxGeometry args={[2.6, 0.06, 2.6]} />
          <meshBasicMaterial color="#00f0ff" transparent opacity={0.7} toneMapped={false} />
        </mesh>
      )}

      {phase !== "complete" && (
        <Sparkles count={phase === "drag" ? 40 : 18} scale={[4, 2, 4]} position={[0, 0.4, 0]} size={3.5} speed={0.5} color="#00f0ff" />
      )}
    </group>
  );
}

function SplitSegments({ filename, onDone }) {
  const group = useRef();
  const wedges = useRef([]);
  const [revealed, setRevealed] = useState(false);

  useFrame((_, delta) => {
    if (group.current) group.current.rotation.y += delta * 0.4;
  });

  useEffect(() => {
    const timers = [];
    timers.push(
      setTimeout(() => {
        for (let i = 0; i < 6; i++) {
          const el = wedges.current[i];
          if (!el) continue;
          const angle = (i / 6) * Math.PI * 2;
          gsap.to(el.position, {
            x: Math.cos(angle) * 3.4,
            z: Math.sin(angle) * 3.4,
            y: -3.5,
            rotationX: (Math.random() - 0.5) * 1.2,
            duration: 0.9,
            delay: i * 0.05,
            ease: "power2.in",
          });
        }
      }, 60)
    );
    timers.push(setTimeout(() => setRevealed(true), 350));
    timers.push(setTimeout(() => onDone?.(), 1100));
    return () => timers.forEach(clearTimeout);
  }, [onDone]);

  return (
    <group ref={group}>
      {Array.from({ length: 6 }).map((_, i) => (
        <mesh key={i} ref={(el) => (wedges.current[i] = el)} position={[0, -0.5, 0]}>
          <cylinderGeometry
            args={[1.8, 1.8, 0.16, 6, 1, true, (i / 6) * Math.PI * 2, Math.PI / 3]}
          />
          <meshStandardMaterial color="#0a2440" emissive="#00f0ff" emissiveIntensity={0.5} side={2} transparent opacity={0.85} toneMapped={false} />
        </mesh>
      ))}
      {revealed && (
        <Text position={[0, 0.2, 0]} fontSize={0.5} color="#00f0ff" anchorX="center" anchorY="middle">
          {filename}
        </Text>
      )}
    </group>
  );
}

function Pad({ phase, progress, filename }) {
  return (
    <>
      {phase !== "complete" ? (
        <HexPlatform phase={phase} progress={progress} />
      ) : (
        <SplitSegments filename={filename} onDone={() => {}} />
      )}
    </>
  );
}

export default function UploadZone({ onScanCreated }) {
  const [phase, setPhase] = useState("idle");
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState(null);
  const [filename, setFilename] = useState("");
  const inputRef = useRef(null);

  const statusLines = useCallback(() => {
    if (phase === "acquiring") return ["> ACQUIRING TARGET...", `> UPLOADING ${progress}%`];
    return STATUS_LINES[phase];
  }, [phase, progress]);

  const validate = (file) => {
    const name = file.name.toLowerCase();
    if (!ACCEPTED.some((e) => name.endsWith(e)))
      throw new Error(`UNSUPPORTED FORMAT. ALLOWED: ${ACCEPTED.join(" ")}`);
    if (file.size > 50 * 1024 * 1024) throw new Error("TARGET EXCEEDS 50MB LIMIT");
  };

  const handleFile = useCallback(
    async (file) => {
      if (!file) return;
      setError(null);
      setPhase("acquiring");
      setProgress(0);
      try {
        validate(file);
        const up = await uploadFile(file, setProgress);
        setFilename(file.name);
        setProgress(100);
        setTimeout(() => setPhase("complete"), 200);
        await triggerScan(up.scan_id);
        setTimeout(() => onScanCreated(up.scan_id, file.name), 1100);
      } catch (e) {
        setError(e.message || "ACQUISITION FAILED");
        setPhase("idle");
      }
    },
    [onScanCreated]
  );

  const onDrop = (e) => {
    e.preventDefault();
    setPhase("idle");
    const file = e.dataTransfer.files?.[0];
    if (file) handleFile(file);
  };

  return (
    <div className="relative">
      <div
        className="relative h-[440px] rounded-2xl overflow-hidden cursor-pointer"
        onClick={() => phase !== "acquiring" && phase !== "complete" && inputRef.current?.click()}
        onDragEnter={() => phase !== "acquiring" && setPhase("drag")}
        onDragLeave={() => phase !== "acquiring" && setPhase("idle")}
        onDragOver={(e) => e.preventDefault()}
        onDrop={onDrop}
      >
        <Canvas dpr={[1, 1.5]} camera={{ position: [0, 2.6, 6.5], fov: 45 }}>
          <color attach="background" args={["#04060c"]} />
          <fog attach="fog" args={["#04060c", 8, 16]} />
          <ambientLight intensity={0.3} />
          <pointLight position={[0, 4, 4]} intensity={20} color="#00f0ff" />
          <pointLight position={[0, -2, -3]} intensity={6} color="#4d7cfe" />
          <Pad phase={phase} progress={progress} filename={filename} />
          <EffectComposer>
            <Bloom intensity={1.2} luminanceThreshold={0.2} mipmapBlur />
          </EffectComposer>
        </Canvas>

        {/* overlay hints */}
        {phase === "idle" && (
          <div className="absolute inset-0 grid place-items-center pointer-events-none">
            <div className="text-center">
              <div className="font-display text-lg tracking-[0.3em] text-cyan-300 holo-glow-cyan">
                DROP THE TARGET
              </div>
              <div className="font-mono text-[11px] text-slate-500 mt-1 tracking-widest">
                PE / ELF BINARY · ≤ 50MB
              </div>
            </div>
          </div>
        )}

        {/* terminal */}
        <div className="absolute bottom-3 left-3 right-3 terminal rounded-lg px-4 py-2 min-h-[74px]">
          <TerminalText key={phase + progress} lines={statusLines()} speed={16} />
        </div>

        {error && (
          <div className="absolute top-3 left-3 right-3 rounded-lg border border-[#ff6b35]/50 bg-[#ff6b35]/10 px-4 py-2 font-mono text-xs text-[#ff6b35]">
            ! {error}
          </div>
        )}

        <input
          ref={inputRef}
          type="file"
          className="hidden"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) handleFile(file);
          }}
        />
      </div>
    </div>
  );
}
