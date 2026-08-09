# GridSentinel — Project JARVIS Frontend Setup

The frontend was rebuilt as a cinematic **Iron Man / JARVIS-style holographic
command center** using React Three Fiber, Three.js, drei, post-processing (Bloom),
Framer Motion and GSAP.

## New dependencies

`package.json` now includes:

| Package | Purpose |
|---|---|
| `three` | WebGL scene graph |
| `@react-three/fiber` | React renderer for three.js |
| `@react-three/drei` | 3D helpers (`Float`, `Html`, `Text`, `Edges`, `MeshDistortMaterial`, `MeshReflectorMaterial`, `Sparkles`, `Line`) |
| `@react-three/postprocessing` | `EffectComposer` + `Bloom` + `Vignette` (the hologram look) |
| `framer-motion` | Spring panel entrances + camera-flight transitions |
| `gsap` | Layer peel / stamp slam / focus camera timelines |

The previous `d3` dependency was removed (the autopsy graph is now 3D).

## Install & run

```bash
cd frontend
npm install        # installs the new 3D deps (three is large — expect ~1.4MB bundle)
npm run dev        # dev server → http://localhost:3000 (proxies /api → :8000)
npm run build      # production build → dist/
```

Bundle is code-split (`vite.config.js` manualChunks): `three.*.js`, `ui.*.js`,
`index.*.js` so the app shell loads fast while the 3D engine lazy-loads.

## Run the full stack (Docker)

```bash
docker compose up --build
# frontend → http://localhost:3000 (nginx) · backend → :8000
```

## Fonts

`index.html` loads **Orbitron**, **Rajdhani** and **JetBrains Mono** from Google
Fonts. The app is fully air-gapped-capable: if the machine is offline the font
`<link>` fails silently and the CSS falls back to `system-ui`/`monospace` — no
functionality depends on the network.

## WebGL requirements

The UI needs a GPU / WebGL for the holographic scenes. A `useWebGLSupport()` gate
detects this once and swaps every 3D scene to a **flat 2D fallback** (styled glass
panels with the same data) so the demo never hard-crashes on machines without WebGL.

## Notes for judging machines

- Use Chrome/Edge on a machine with hardware acceleration (WebGL1/2).
- 3-column layout requires ≥1366px width; below that it collapses to single column.
- The 3D canvases auto-resize via the R3F viewport.
