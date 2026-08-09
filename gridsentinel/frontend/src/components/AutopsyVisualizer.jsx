import { useEffect, useMemo, useRef, useState } from "react";
import { Canvas, useFrame, useThree } from "@react-three/fiber";
import { OrbitControls, Edges, Text, Html, Sparkles, MeshDistortMaterial, Line } from "@react-three/drei";
import { EffectComposer, Bloom, Vignette } from "@react-three/postprocessing";
import gsap from "gsap";
import * as THREE from "three";

const CYAN = "#00f0ff";
const ORANGE = "#ff6b35";
const GREEN = "#00ff88";
const AMBER = "#ffd166";

/* ------------------------------ focus rig ------------------------------ */

function CameraFocus({ focus, controlsRef }) {
  const { camera } = useThree();
  useEffect(() => {
    if (!controlsRef.current) return;
    if (focus) {
      controlsRef.current.enabled = false;
      gsap.to(camera.position, {
        x: focus[0] * 1.35,
        y: focus[1] + 1.3,
        z: focus[2] + 4.4,
        duration: 1.3,
        ease: "power3.inOut",
      });
      gsap.to(controlsRef.current.target, {
        x: focus[0],
        y: focus[1],
        z: focus[2],
        duration: 1.3,
        ease: "power3.inOut",
      });
    } else {
      gsap.to(camera.position, { x: 0, y: 1.6, z: 9.5, duration: 1.3, ease: "power3.inOut" });
      gsap.to(controlsRef.current.target, { x: 0, y: 0, z: 0, duration: 1.3, ease: "power3.inOut" });
      const t = setTimeout(() => {
        if (controlsRef.current) controlsRef.current.enabled = true;
      }, 1350);
      return () => clearTimeout(t);
    }
  }, [focus, camera]);
  return null;
}

/* ------------------------------ data streams --------------------------- */

function Stream({ from, to, color }) {
  const p = useRef();
  const a = useMemo(() => new THREE.Vector3(...from), [from]);
  const b = useMemo(() => new THREE.Vector3(...to), [to]);
  useFrame((state) => {
    const t = (state.clock.elapsedTime * 0.35) % 1;
    p.current.position.lerpVectors(a, b, t);
  });
  return (
    <group>
      <Line points={[a.toArray(), b.toArray()]} color={color} lineWidth={0.6} transparent opacity={0.35} />
      <mesh ref={p}>
        <sphereGeometry args={[0.05, 8, 8]} />
        <meshBasicMaterial color={color} toneMapped={false} />
      </mesh>
    </group>
  );
}

/* ------------------------------ layers --------------------------------- */

function LayerBox({ section, index, count, dimmed, selected, onHover, onSelect }) {
  const group = useRef();
  const color = section.high_entropy ? ORANGE : CYAN;
  const z = (index - (count - 1) / 2) * 1.05;

  useEffect(() => {
    const ctx = gsap.timeline();
    ctx.fromTo(
      group.current.position,
      { z: 0, y: -0.4 },
      { z, duration: 1.1, ease: "back.out(1.4)", delay: 0.25 + index * 0.09 }
    );
    ctx.fromTo(
      group.current.scale,
      { x: 0.15, y: 0.15, z: 0.15 },
      { x: 1, y: 1, z: 1, duration: 1.1, ease: "power2.out" },
      0
    );
    return () => ctx.kill();
  }, []);

  useFrame((state) => {
    if (!group.current) return;
    const t = state.clock.elapsedTime;
    group.current.rotation.y += 0.0016;
    group.current.position.x = Math.sin(t * 0.4 + index * 1.3) * 0.22;
    group.current.position.y = Math.sin(t * 0.5 + index * 1.7) * 0.12;
  });

  return (
    <group
      ref={group}
      position={[0, 0, z]}
      onPointerOver={(e) => {
        e.stopPropagation();
        onHover({ label: section.name, details: `entropy ${section.entropy} · raw ${section.raw_size}B · va ${section.virtual_address}`, risk: section.high_entropy ? "threat" : "clean" });
      }}
      onPointerOut={() => onHover(null)}
      onClick={(e) => {
        e.stopPropagation();
        onSelect({ key: `sec:${section.name}`, title: section.name, data: section });
      }}
    >
      <mesh>
        <boxGeometry args={[3.2, 2.2, 0.06]} />
        <meshStandardMaterial
          color={color}
          transparent
          opacity={dimmed ? 0.05 : selected ? 0.3 : 0.16}
          emissive={color}
          emissiveIntensity={dimmed ? 0.04 : selected ? 1.1 : 0.4}
          toneMapped={false}
        />
      </mesh>
      <Edges color={color} scale={1.005} />
      {section.name === ".text" && (
        <Sparkles count={26} scale={[3.2, 2.2, 0.4]} size={2.2} speed={0.35} color={color} />
      )}
      {section.high_entropy && !dimmed && (
        <Sparkles count={14} scale={[3.2, 2.2, 0.4]} size={2.6} speed={0.7} color={ORANGE} />
      )}
      <Text position={[0, -1.35, 0.2]} fontSize={0.2} color={color} anchorX="center">
        {section.name}
      </Text>
    </group>
  );
}

/* ------------------------------ certificate shield ---------------------- */

function CertShield({ signed, misspelled }) {
  const mesh = useRef();
  const color = misspelled ? ORANGE : signed ? GREEN : ORANGE;
  useFrame((_, dt) => {
    if (mesh.current) mesh.current.rotation.y += dt * 0.12;
  });
  return (
    <group>
      <mesh ref={mesh}>
        <dodecahedronGeometry args={[3.7, 0]} />
        <meshBasicMaterial wireframe color={color} transparent opacity={0.2} toneMapped={false} />
      </mesh>
      <Text position={[0, -4.1, 0]} fontSize={0.22} color={color} anchorX="center">
        {misspelled ? "FAKE VENDOR SIGNATURE" : signed ? "AUTHENTICODE SIGNED" : "UNSIGNED — NO CERTIFICATE"}
      </Text>
    </group>
  );
}

/* ------------------------------ core ----------------------------------- */

function Core({ risk }) {
  const shell = useRef();
  const color = risk === "threat" ? ORANGE : CYAN;
  useFrame((state) => {
    if (shell.current) {
      const t = state.clock.elapsedTime;
      const s = 1 + Math.sin(t * 2.2) * 0.12;
      shell.current.scale.setScalar(s);
      shell.current.material.opacity = 0.12 + Math.sin(t * 2.2) * 0.06;
    }
  });
  return (
    <group>
      <mesh>
        <sphereGeometry args={[0.72, 48, 48]} />
        <MeshDistortMaterial color={color} emissive={color} emissiveIntensity={0.55} distort={0.4} speed={2} toneMapped={false} />
      </mesh>
      <mesh ref={shell}>
        <sphereGeometry args={[1.1, 32, 32]} />
        <meshBasicMaterial color={color} wireframe transparent opacity={0.14} toneMapped={false} />
      </mesh>
      <Sparkles count={30} scale={3} size={3} speed={0.4} color={color} />
    </group>
  );
}

/* ------------------------------ imports ring --------------------------- */

function ImportRing({ imports, dimmed }) {
  const ring = useRef();
  const glyphs = useMemo(() => {
    const n = Math.min(imports?.length || 0, 9);
    return Array.from({ length: n }, (_, i) => {
      const imp = imports[i];
      const angle = (i / n) * Math.PI * 2;
      const suspicious = imp.suspicious?.length > 0;
      const isNet = /ws2_32|wininet|urlmon|winhttp/i.test(imp.dll);
      const isReg = /advapi/i.test(imp.dll);
      const color = suspicious || isNet || isReg ? ORANGE : CYAN;
      return { imp, angle, color, pos: [Math.cos(angle) * 2.7, Math.sin(angle) * 1.3, 3.6] };
    });
  }, [imports]);

  useFrame((state) => {
    if (ring.current) ring.current.rotation.z += 0.0008;
  });

  return (
    <group ref={ring}>
      {glyphs.map((g) => (
        <group key={g.imp.dll} position={g.pos}>
          <mesh>
            <icosahedronGeometry args={[0.16, 0]} />
            <meshStandardMaterial color={g.color} emissive={g.color} emissiveIntensity={dimmed ? 0.05 : 0.9} transparent opacity={dimmed ? 0.1 : 1} toneMapped={false} />
          </mesh>
          <Text position={[0, -0.32, 0]} fontSize={0.11} color={g.color} anchorX="center" transparent opacity={dimmed ? 0.15 : 1}>
            {g.imp.dll}
          </Text>
          <Line points={[g.pos, [0, 0, 0.6]]} color={g.color} lineWidth={0.6} transparent opacity={dimmed ? 0.05 : 0.3} />
        </group>
      ))}
    </group>
  );
}

/* ------------------------------ strings -------------------------------- */

function StringField({ strings, dimmed }) {
  const frags = useMemo(() => {
    const flat = [];
    if (strings?.urls?.length) flat.push(...strings.urls.slice(0, 4).map((s) => ({ s, color: ORANGE })));
    if (strings?.ips?.length) flat.push(...strings.ips.slice(0, 3).map((s) => ({ s, color: AMBER })));
    if (strings?.registry_keys?.length) flat.push(...strings.registry_keys.slice(0, 3).map((s) => ({ s, color: ORANGE })));
    return flat.slice(0, 8).map((f, i) => ({
      ...f,
      angle: (i / 8) * Math.PI * 2,
      rad: 3.5 + (i % 3) * 0.55,
    }));
  }, [strings]);

  useFrame((state) => {
    frags.forEach((f, i) => {
      const grp = refs.current[i];
      if (grp) {
        const t = state.clock.elapsedTime * 0.1;
        grp.position.set(Math.cos(f.angle + t + i) * f.rad, Math.sin(i * 1.9) * 1.1, -2.6 + Math.sin(t + i) * 0.6);
      }
    });
  });

  const refs = useRef([]);
  return (
    <group>
      {frags.map((f, i) => (
        <group key={i} ref={(el) => (refs.current[i] = el)}>
          <Text fontSize={0.14} color={f.color} anchorX="center" anchorY="middle" transparent opacity={dimmed ? 0.12 : 0.85}>
            {f.s.length > 26 ? f.s.slice(0, 26) + "…" : f.s}
          </Text>
        </group>
      ))}
    </group>
  );
}

/* ------------------------------ resources ------------------------------ */

function ResourceBurst({ resources, dimmed }) {
  const items = useMemo(
    () =>
      (resources || []).slice(0, 6).map((r, i) => ({
        ...r,
        angle: (i / 6) * Math.PI * 2,
        color: r.high_entropy ? ORANGE : CYAN,
      })),
    [resources]
  );
  useFrame((state) => {
    const t = state.clock.elapsedTime;
    items.forEach((it, i) => {
      const g = refs.current[i];
      if (g) {
        g.position.set(Math.cos(it.angle + t * 0.2) * 2.6, Math.sin(t * 0.7 + i) * 0.6, -2.4);
      }
    });
  });
  const refs = useRef([]);
  return (
    <group>
      {items.map((it, i) => (
        <mesh key={i} ref={(el) => (refs.current[i] = el)}>
          <boxGeometry args={[0.22, 0.22, 0.22]} />
          <meshStandardMaterial color={it.color} emissive={it.color} emissiveIntensity={dimmed ? 0.05 : 0.7} transparent opacity={dimmed ? 0.1 : 1} toneMapped={false} />
        </mesh>
      ))}
    </group>
  );
}

/* ------------------------------ scene ---------------------------------- */

function Scene({ staticData, selected, dimmed, onHover, onSelect }) {
  const sections = (staticData?.sections || []).slice(0, 6);
  const imports = staticData?.imports || [];
  const resources = staticData?.resources || [];
  const strings = staticData?.strings || {};
  const flags = staticData?.flags || {};
  const threat = flags.network_api || flags.injection_api || flags.antidebug_api;
  const layerZ = sections.map((_, i) => (i - (sections.length - 1) / 2) * 1.05);

  return (
    <group>
      <Core risk={threat ? "threat" : "clean"} />
      <CertShield signed={staticData?.basic_info?.is_signed} misspelled={staticData?.basic_info?.cert_misspelled} />
      {sections.map((s, i) => (
        <LayerBox key={s.name + i} section={s} index={i} count={sections.length} dimmed={dimmed} selected={selected?.key === `sec:${s.name}`} onHover={onHover} onSelect={onSelect} />
      ))}
      {layerZ.map((z, i) => (
        <Stream key={`stream-${i}`} from={[0, 0, 0.6]} to={[0, 0, z]} color={sections[i]?.high_entropy ? ORANGE : CYAN} />
      ))}
      <ImportRing imports={imports} dimmed={dimmed} />
      <StringField strings={strings} dimmed={dimmed} />
      <ResourceBurst resources={resources} dimmed={dimmed} />
    </group>
  );
}

/* ------------------------------ wrapper -------------------------------- */

export default function AutopsyVisualizer({ staticData }) {
  const [hover, setHover] = useState(null);
  const [selected, setSelected] = useState(null);
  const controlsRef = useRef();

  const dimmed = Boolean(selected && !hover);

  const selectTarget = selected
    ? selected.key?.startsWith("sec:")
      ? (() => {
          const idx = (staticData?.sections || []).findIndex((s) => `sec:${s.name}` === selected.key);
          return [0, 0, (idx - ((staticData?.sections?.length || 1) - 1) / 2) * 1.05];
        })()
      : [0, 0, 0]
    : null;

  const detailRows = useMemo(() => {
    if (!selected) return [];
    const d = selected.data || {};
    return Object.entries(d)
      .filter(([, v]) => typeof v === "number" || typeof v === "string" || typeof v === "boolean")
      .slice(0, 10);
  }, [selected]);

  return (
    <div className="relative h-full min-h-[520px]">
      <Canvas dpr={[1, 1.6]} camera={{ position: [0, 1.6, 9.5], fov: 50 }}>
        <color attach="background" args={["#04060c"]} />
        <fog attach="fog" args={["#04060c", 12, 26]} />
        <ambientLight intensity={0.25} />
        <pointLight position={[0, 5, 6]} intensity={40} color={CYAN} />
        <pointLight position={[-6, -2, -4]} intensity={15} color={ORANGE} />
        <pointLight position={[0, -4, 4]} intensity={8} color={GREEN} />
        <Scene
          staticData={staticData}
          selected={selected}
          dimmed={dimmed}
          onHover={setHover}
          onSelect={(sel) => setSelected(sel)}
        />
        {hover && (
          <Html position={[hover.risk === "threat" ? 2.2 : -2.2, 1.6, 0]} center distanceFactor={10} style={{ pointerEvents: "none" }}>
            <div
              className="rounded-lg px-3 py-2 font-mono text-[11px]"
              style={{
                background: "rgba(5,10,20,0.92)",
                border: `1px solid ${hover.risk === "threat" ? ORANGE : CYAN}`,
                boxShadow: `0 0 18px ${hover.risk === "threat" ? ORANGE : CYAN}66`,
                color: hover.risk === "threat" ? ORANGE : CYAN,
              }}
            >
              <div className="font-bold tracking-widest">{hover.label}</div>
              <div className="text-slate-400">{hover.details}</div>
            </div>
          </Html>
        )}
        <CameraFocus focus={selectTarget} controlsRef={controlsRef} />
        <OrbitControls ref={controlsRef} enableDamping dampingFactor={0.08} minDistance={4} maxDistance={26} />
        <EffectComposer>
          <Bloom intensity={1.15} luminanceThreshold={0.2} luminanceSmoothing={0.9} mipmapBlur />
          <Vignette eskil={false} offset={0.12} darkness={0.9} />
        </EffectComposer>
      </Canvas>

      {/* isolated detail panel */}
      {selected && (
        <div className="absolute top-4 right-4 w-72 holo-glass holo-corners rounded-xl p-4 slide-in-right">
          <div className="flex items-center justify-between mb-2">
            <h4 className="font-display text-xs tracking-[0.25em] text-cyan-300 holo-glow-cyan">ISOLATED LAYER</h4>
            <button onClick={() => setSelected(null)} className="font-mono text-[10px] text-slate-400 hover:text-[#ff6b35]">
              [EXIT]
            </button>
          </div>
          <div className="font-mono text-sm text-slate-200 mb-2 break-all">{selected.title}</div>
          <div className="space-y-1">
            {detailRows.map(([k, v]) => (
              <div key={k} className="flex justify-between text-[11px] font-mono">
                <span className="text-slate-500">{k}</span>
                <span className="text-cyan-300 text-right break-all max-w-[60%]">{String(v)}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
