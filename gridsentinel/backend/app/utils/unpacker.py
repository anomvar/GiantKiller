import shutil
import subprocess
import tempfile
from pathlib import Path

import pefile


def detect_packer(data: bytes) -> tuple[bool, str | None]:
    if b"UPX!" in data[: min(len(data), 4096)]:
        return True, "UPX"
    try:
        pe = pefile.PE(data=data)
        names = [s.Name.rstrip(b"\x00").decode("ascii", "ignore") for s in pe.sections]
        if ".UPX0" in names or ".UPX1" in names:
            return True, "UPX"
        high_ent = sum(1 for s in pe.sections if s.get_entropy() > 7.6)
        if high_ent >= 3:
            return True, "unknown_packer"
        return False, None
    except Exception:  # noqa: BLE001
        return False, None


def try_unpack(path: str) -> str | None:
    upx_bin = shutil.which("upx")
    if not upx_bin:
        return None
    try:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "sample"
            shutil.copy(path, target)
            result = subprocess.run(
                [upx_bin, "-d", "-o", str(target) + ".unpacked", str(target)],
                capture_output=True,
                timeout=30,
            )
            if result.returncode != 0:
                return None
            out = Path(str(target) + ".unpacked")
            if out.exists() and out.stat().st_size > 0:
                out_path = Path(path).with_suffix(".unpacked")
                shutil.copy(out, out_path)
                return str(out_path)
            return None
    except Exception:  # noqa: BLE001
        return None
