#!/usr/bin/env bash
# =============================================================================
#  HARMLESS DEMO PAYLOAD BUILDER FOR SIH1388 — NO ACTUAL MALICIOUS BEHAVIOR.
#  Compiles source.c into:
#    - SCADA_PowerGridUpdater_v2.4.exe  (Windows PE, via x86_64-w64-mingw32-gcc)
#    - SCADA_PowerGridUpdater_v2.4.elf  (Linux ELF, via gcc) — fallback so the
#      demo also runs on a Linux-only machine.
# =============================================================================
set -euo pipefail

cd "$(dirname "$0")"

OUT_EXE="SCADA_PowerGridUpdater_v2.4.exe"
OUT_ELF="SCADA_PowerGridUpdater_v2.4.elf"

echo "==> GridSentinel demo payload builder"
echo ""

mkdir -p build

if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    echo "==> Building Windows PE ($OUT_EXE)"
    x86_64-w64-mingw32-gcc -O2 -o "build/$OUT_EXE" source.c -lws2_32
    echo "    OK -> build/$OUT_EXE"
else
    echo "==> x86_64-w64-mingw32-gcc not found — skipping PE build."
    echo "    Install with:  sudo apt install gcc-mingw-w64-x86-64"
fi

if command -v gcc >/dev/null 2>&1; then
    echo "==> Building Linux ELF ($OUT_ELF)"
    gcc -O2 -o "build/$OUT_ELF" source.c
    chmod +x "build/$OUT_ELF"
    echo "    OK -> build/$OUT_ELF"
else
    echo "==> gcc not found — cannot build ELF."
fi

echo ""
echo "==> Done. Upload build/SCADA_PowerGridUpdater_v2.4.* to GridSentinel."
echo "    For the Windows PE, you need gcc-mingw-w64; the ELF works out of the box."
