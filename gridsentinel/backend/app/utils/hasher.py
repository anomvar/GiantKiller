import hashlib
import re

try:
    import ssdeep

    HAS_SSDEEP = True
except Exception:  # noqa: BLE001
    HAS_SSDEEP = False


def detect_format(data: bytes) -> str:
    if data[:2] == b"MZ":
        return "PE"
    if data[:4] == b"\x7fELF":
        return "ELF"
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return "ZIP"
    return "UNSUPPORTED"


def md5_of(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _naive_fuzzy(data: bytes, window: int = 512, blocks: int = 8) -> str:
    if len(data) < window:
        h = sha256_of(data)
        return "%d:%s" % (len(data), h[:32])
    step = max(1, (len(data) - window) // blocks)
    digests = []
    for i in range(blocks):
        chunk = data[i * step: i * step + window]
        digests.append(hashlib.sha1(chunk).hexdigest()[:6])
    return "%d:%s" % (len(data), "".join(digests))


def fuzzy_of(data: bytes) -> str:
    if HAS_SSDEEP:
        try:
            return ssdeep.hash(data) or _naive_fuzzy(data)
        except Exception:  # noqa: BLE001
            return _naive_fuzzy(data)
    return _naive_fuzzy(data)


def hash_file(data: bytes) -> dict:
    fmt = detect_format(data)
    return {
        "format": fmt,
        "magic": "UNSUPPORTED" if fmt == "UNSUPPORTED" else fmt,
        "md5": md5_of(data),
        "sha256": sha256_of(data),
        "ssdeep": fuzzy_of(data) if fmt != "UNSUPPORTED" else "",
        "size": len(data),
    }


def looks_like_dga(domain: str) -> bool:
    if not domain or re.match(r"^[\d.:]+$", domain):
        return False
    label = domain.split(".")[0]
    if len(label) < 6:
        return False
    consonants = sum(1 for ch in label if ch.lower() in "bcdfghjklmnpqrstvwxyz")
    return consonants / max(1, len(label)) > 0.55
