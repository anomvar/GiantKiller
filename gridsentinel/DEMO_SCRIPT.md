# GridSentinel — 5-Minute Judge Demo Script (SIH1388)

**Theme:** *"Not a generic antivirus — a forensic platform that performs a software
autopsy, lies to malware, and shows the blackout it would cause."*

---

## Setup (before judges arrive) — 2 min, do this ahead of time

```bash
cd gridsentinel
docker compose up --build          # one command, full stack on :3000/:8000
cd demo_payload && ./build.sh      # produces the demo binaries
```

Pre-load the browser at `http://localhost:3000`. Have the demo binary selected in a
file manager ready to drag in. **Do not upload anything yet.**

---

## 0:00–0:30 — Hook (Elevator pitch)

> "The power sector runs on the SCADA/ICS software inside substations. One
> trojanized update can trip a 220kV relay and take out two cities. Antivirus
> catches yesterday's malware. GridSentinel does a **forensic software autopsy** —
> a CT scan of the binary — then runs it in a **sandbox that actively lies to it**,
> scores it with ML, and **animates the blackout it would cause**."

Point at the three feature cards on the landing page (① Autopsy, ② Deceptive
Sandbox, ③ Grid Impact Twin).

## 0:30–1:00 — Upload the demo payload

1. Drag `build/SCADA_PowerGridUpdater_v2.4.exe` (or `.elf`) onto the upload zone.
   - **Say:** *"This 'SCADA PowerGridUpdater' claims to be a vendor update for a
     220kV substation. Watch the pipeline."*
2. Upload bar → auto-queues the scan. Call out the stage tracker:
   > "Four engines run sequentially: Software Autopsy → Deceptive Sandbox →
   > ML Anomaly Scan → Grid Impact Twin."

## 1:00–2:00 — Software Autopsy (D3 CT-scan graph)

1. Point at the **force-directed graph**.
   - *"Every node is a piece of the binary: sections with their entropy, imports,
     the certificate, resources, embedded strings."*
   - Red glowing nodes = flagged. Click one node → sidebar shows evidence.
2. Scroll to the **flag panel**:
   - `network_api ✓`, `registry_api ✓`, `antidebug_api ✓` — *"a legitimate update
     doesn't import winsock AND IsDebuggerPresent."*
3. Point at **YARA matches** and **Power-Sector Rules fired**:
   - PWR001 *SCADA Network Exposure* (CRITICAL)
   - PWR003 *Modbus/TCP Reference* (CRITICAL) — *"it speaks the relay's protocol."*

## 2:00–3:00 — Deceptive Sandbox (the money shot)

Split screen:
- **Left (Standard sandbox):** dim, *"sample slept and exited silently."*
- **Right (GridSentinel deceptive):** red border, vivid behaviors —
  persistence marker dropped, `Run` key read, **beacon to
  `command-and-control.local`**, socket + connect captured.

> "Both ran the same binary. The standard sandbox saw nothing — malware checked
> CPUID, saw a hypervisor, and shut itself down. GridSentinel **faked CPUID, hid
> the VM registry artifacts, spoofed 8GB RAM / 4 cores, and returned 0 from
> IsDebuggerPresent**, so the trojan *trusted* the environment and activated.
> That's the 'deceptive sandbox' — we don't just observe malware, we **trick it
> into confessing**."

Point at the 🎭 **Tricks Used** badge list.

## 3:00–4:00 — Grid Impact Twin (the WOW)

1. Hit **▶ Replay Attack**.
2. The red pulse travels: `SCADA_HMI → Relay_1 → Transformer → Bus_3 → Cities`.
   - *"The compromised SCADA workstation issues a **trip command** over Modbus/TCP
     to the 220kV relay."*
   - When the pulse reaches the cities: **"POWER LOST"** tags light up.
3. Read the counters: **Load Lost 340 MW · Districts 2 · Restoration 4 h**.
   - Drag the **timeline scrubber** back and forth to replay it.
4. Show the **Attack Sequence** list (Recon → Pivot → Act).

## 4:00–4:40 — Prosecutor AI + Verdict

Typewriter narrative renders. Read 1–2 lines aloud, e.g.:

> *"I render a verdict of MALICIOUS with 97% confidence."*

Point at the **Risk Meter**: 98/100, breakdown Static/Dynamic/Heuristic/Power Rules.
Red **VERDICT: MALICIOUS** banner.

## 4:40–5:00 — Close

> "Fully **air-gapped** — no VirusTotal, no cloud. The ML model trains locally.
> One `docker compose up --build` runs the whole stack. GridSentinel turns a
> black-box binary into a prosecutor's evidence file — and shows a grid operator
> *exactly* what deploying it would cost."

---

## Judge FAQ — quick answers

| Question | Answer |
|---|---|
| Is it offline? | 100%. No external API calls; fake C2 responder is inetsim on localhost. |
| How is ML trained? | `IsolationForest` over a 20-feature vector; trained at first boot from a 100-sample corpus, cached as `anomaly_model.pkl`. |
| How do you bypass anti-VM? | `vm_spoof.so` LD_PRELOAD shim + env spoofing: CPUID → GenuineIntel, hidden DMI/VM registry, 8GB/4-core, `IsDebuggerPresent`→0. |
| Is the payload real malware? | No — it writes one text marker, reads a key, and resolves a non-routable local hostname. Big comment header in `source.c` says so. |
| What if Docker is missing? | The sandbox engine falls back to a deterministic simulation; full demo still runs. |
| Scaling? | Engines are pluggable modules; sandbox runs per-sample containers; SQLite→Postgres swap is a config change. |

## Expected demo numbers (pre-built payload)

- Verdict: **MALICIOUS**, risk ≈ **84–100/100**
  (ELF via real Docker sandbox ≈ 84; PE via simulation fallback ≈ 100)
- Breakdown: Static 45–95 · Dynamic 100 · Heuristic 100 · Power 100
- YARA: `SuspiciousApiCombo`, `PowerSectorImplantStrings`
- Power rules: PWR001, PWR003, PWR005, PWR007 (2 CRITICAL)
- Grid impact: **CRITICAL — Potential Grid Instability, 340 MW, 2 districts, 4 h**
- Sandbox: ELF runs the **real strace container** (`mode: docker`); on hosts without a
  reachable Docker socket the deterministic simulation drives the same narrative.
