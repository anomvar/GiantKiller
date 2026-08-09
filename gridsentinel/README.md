# GridSentinel — Power Sector Software Security Scanner (SIH1388)

A production-grade, fully air-gapped web platform that detects malware/trojans in
software destined for the power sector. It performs a **forensic software autopsy**
on each binary, runs it through a **deceptive sandbox** that actively lies to
anti-VM/anti-debug code, scores it with a trained **IsolationForest** model, applies
**power-sector rules**, and animates the **grid impact** a deployment would cause.

> ⚠️ **Ethical scope:** This project is a defensive security tool built for the
> Smart India Hackathon (SIH1388). The demo payload in `demo_payload/` is a
> **harmless proof-of-concept** — it writes one text file, reads a registry key,
> and resolves the non-routable local hostname `command-and-control.local`.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│ Browser (1366x768+)                                             │
│   UploadZone · AutopsyVisualizer (D3 force graph)               │
│   SandboxComparison · GridImpactTwin · ProsecutorReport          │
│   RiskMeter                                                     │
└───────────────┬──────────────────────────────────────────────────┘
                │ HTTP /api/v1/*  (nginx proxy)
┌───────────────▼──────────────────────────────────────────────────┐
│ FastAPI backend (port 8000)                                     │
│   POST /upload → scan_id                                        │
│   POST /scan/{id} → async 4-engine pipeline                     │
│   GET  /scan/{id}/status | /report | /autopsy | /grid-impact    │
│   static_engine → sandbox_engine → heuristic_engine → grid_imp  │
│   SQLite (scan_results.db)  ·  ML model (anomaly_model.pkl)     │
└───────────────┬──────────────────────────────────────────────────┘
                │ Docker SDK (or deterministic simulation fallback)
┌───────────────▼──────────────────────────────────────────────────┐
│ Deceptive sandbox container (gridsentinel-sandbox)              │
│   strace syscall capture · LD_PRELOAD vm_spoof.so (fake CPUID,   │
│   hidden VM DMI, spoofed RAM) · inetsim fake C2 responder        │
└──────────────────────────────────────────────────────────────────┘
```

## Quick start

```bash
docker compose up --build
```

- Frontend: http://localhost:3000
- Backend API: http://localhost:8000 (docs at `/docs`)

### Build the demo payload (optional, for a richer demo)

```bash
cd demo_payload && ./build.sh
```

Produces `build/SCADA_PowerGridUpdater_v2.4.exe` (Windows PE, needs
`gcc-mingw-w64-x86-64`) and `build/SCADA_PowerGridUpdater_v2.4.elf` (Linux ELF).
Upload either to the scanner. The ELF also runs on Linux without wine.

## Running without Docker (local dev)

```bash
# backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn app.main:app --port 8000 --app-dir backend

# frontend
cd frontend && npm install && npm run dev   # http://localhost:3000 (proxies /api)
```

Without a reachable Docker socket the sandbox engine transparently falls back to a
deterministic simulation driven by the static evidence, so the full pipeline and demo
still work on any machine.

## Pipeline

| Stage | What it does |
|---|---|
| 1. Software Autopsy | PE/ELF dissection: sections + Shannon entropy, imports with suspicious-API flags, Authenticode cert check (misspelled-vendor heuristic), resources (high-entropy = steganography), strings (URLs/IPs/registry/cmds), 4 YARA rules, UPX packer detection |
| 2. Deceptive Sandbox | Runs the sample in a strace-armed container whose LD_PRELOAD shim fakes CPUID `GenuineIntel`, hides VM DMI/registry artifacts, spoofs 8GB/4-core and returns 0 from `IsDebuggerPresent` — malware that would sleep in a normal sandbox now activates and beacons to the fake inetsim C2 responder |
| 3. Heuristic ML | Pre-trained `IsolationForest` (20 features, contamination 0.1) → `anomaly_score` + `risk_percentile` |
| 4. Power Rules | 7 power-sector rules (PWR001–PWR007): SCADA network exposure, unsigned HES patch, Modbus/TCP refs, fake vendor certs, DMZ beaconing, high-entropy resources, anti-VM stubs |
| 5. Grid Impact Twin | Rule-based narrative animator: maps findings onto a 220kV substation topology and emits a timestamped attack sequence (trip command → 340MW loss across 2 districts) |
| 6. Prosecutor AI | Template NLG (no LLM API, fully offline) producing the forensic narrative + verdict (CLEAN/SUSPICIOUS/MALICIOUS) and confidence |

## API

| Endpoint | Description |
|---|---|
| `POST /api/v1/upload` | Multipart upload (`.exe .dll .msi .elf .zip .bin .scr .cpl`, ≤50MB). Returns `scan_id`. |
| `POST /api/v1/scan/{scan_id}` | Triggers the async pipeline. |
| `GET /api/v1/scan/{scan_id}/status` | Stage: pending → static → sandbox → heuristic → grid_impact → complete/error. |
| `GET /api/v1/scan/{scan_id}/report` | Full JSON report incl. all engine results + prosecutor narrative. |
| `GET /api/v1/scan/{scan_id}/autopsy` | D3 force-graph payload (nodes/links) for the Autopsy visualizer. |
| `GET /api/v1/scan/{scan_id}/grid-impact` | Grid topology + animation sequence. |

## Project layout

```
backend/app/          FastAPI app (routers, engines, utils, ml_model)
backend/sandbox/      Sandbox image: monitor.py (strace→JSON), hook_agent.py,
                      vm_spoof.c (LD_PRELOAD anti-anti-VM shim)
frontend/src/         React 18 + Vite + Tailwind + D3 v7
demo_payload/         Harmless C POC payload + cross-platform build.sh
docker-compose.yml    backend + frontend(nginx) + sandbox
```

## Offline / air-gapped

- No VirusTotal, no OpenAI, no external APIs — everything runs locally.
- The ML model (`anomaly_model.pkl`) is trained at first launch from a hardcoded
  corpus (50 benign / 50 malicious vectors) and cached to disk.
- The fake C2 responder is inetsim bound to localhost; `command-and-control.local`
  is resolved to 127.0.0.1 inside the sandbox only.
