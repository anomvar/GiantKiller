# GridSentinel Demo Payload — SIH1388

> **HARMLESS DEMO PAYLOAD — NO ACTUAL MALICIOUS BEHAVIOR.**
> This is a proof-of-concept binary that mimics the *shape* of a trojanized
> industrial updater so the GridSentinel detection platform can be demonstrated
> end-to-end. It only writes a text marker file, reads a registry key, and
> resolves the **non-routable local hostname** `command-and-control.local`.

## What it mimics

| Real-world trojan technique | What this demo actually does |
|---|---|
| Anti-debug check | Calls `IsDebuggerPresent()` (Windows build) and exits early if true |
| Anti-VM check | Reads CPUID hypervisor bit and exits early if set |
| Persistence drop | Writes one text file to `%APPDATA%\...\PowerConfig\update.log` |
| C2 beaconing | Resolves `command-and-control.local` (local-only) and sends a GET |
| Persistence check | READS `HKLM\...\CurrentVersion\Run` (never writes it) |
| OT protocol targeting | Embeds `modbus/tcp`, `dnp3`, `iec 104` protocol strings |

## Build

```bash
./build.sh
```

Produces (in `build/`):

- `SCADA_PowerGridUpdater_v2.4.exe` — Windows PE (needs `x86_64-w64-mingw32-gcc`; install with `sudo apt install gcc-mingw-w64-x86-64`)
- `SCADA_PowerGridUpdater_v2.4.elf` — Linux ELF (needs plain `gcc`)

## Use in the demo

1. Upload either binary to GridSentinel (`http://localhost:3000`).
2. Watch the 4-engine pipeline run.
3. Note the deceptive sandbox bypasses the anti-VM/anti-debug stubs and captures
   the "beacon" to the fake C2 responder — the exact behavior a standard sandbox
   would miss.

## Why the filename matters

The output name contains `SCADA`, which the power rules engine uses to fire
`PWR001` (SCADA Network Exposure). Do not rename the binaries before the demo.
