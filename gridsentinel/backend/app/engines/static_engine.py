"""Static analysis engine: PE/ELF dissection, entropy, imports, strings, YARA."""

from __future__ import annotations

import math
import re
from pathlib import Path

from ..utils.hasher import hash_file, looks_like_dga
from ..utils.unpacker import detect_packer

try:
    import pefile

    HAS_PEFILE = True
except Exception:  # noqa: BLE001
    HAS_PEFILE = False

try:
    import yara

    HAS_YARA = True
except Exception:  # noqa: BLE001
    HAS_YARA = False

YARA_RULES = r"""
rule UPX_Packed {
    meta:
        description = "Detects UPX packing"
    strings:
        $upx_sig = "UPX!"
        $upx0 = ".UPX0"
        $upx1 = ".UPX1"
        $upx_magic = { 60 EA 07 00 00 00 }
    condition:
        any of them
}

rule SuspiciousApiCombo {
    meta:
        description = "Network plus injection or anti-debug API combination"
    strings:
        $ws2 = "ws2_32.dll" nocase
        $wininet = "wininet.dll" nocase
        $urlmon = "urlmon.dll" nocase
        $valloc = "VirtualAllocEx" nocase
        $remthread = "CreateRemoteThread" nocase
        $wpm = "WriteProcessMemory" nocase
        $ntmap = "NtMapViewOfSection" nocase
        $isdbg = "IsDebuggerPresent" nocase
        $chkdbg = "CheckRemoteDebuggerPresent" nocase
    condition:
        (any of ($ws2, $wininet, $urlmon)) and
        (any of ($valloc, $remthread, $wpm, $ntmap, $isdbg, $chkdbg))
}

rule PowerShellExecution {
    meta:
        description = "PowerShell execution strings"
    strings:
        $ps = "powershell.exe" nocase
        $enc = "-enc" nocase
        $iex = "iex(" nocase
        $dls = "DownloadString" nocase
        $exby = "-executionpolicy" nocase
    condition:
        any of them
}

rule PowerSectorImplantStrings {
    meta:
        description = "Strings referencing OT/SCADA attack primitives"
    strings:
        $modbus = "modbus" nocase
        $iec104 = "iec 104" nocase
        $dnp3 = "dnp3" nocase
        $station = "substation" nocase
        $scada = "scada" nocase
        $breaker = "breaker trip" nocase
    condition:
        2 of them
}
"""

_SUSPICIOUS_DLLS = {
    "ws2_32.dll": "network",
    "wininet.dll": "network",
    "urlmon.dll": "network",
    "winhttp.dll": "network",
    "advapi32.dll": "registry",
    "ntdll.dll": "native",
    "msvfw32.dll": "screen capture",
    "user32.dll": "UI hooking",
}

_SUSPICIOUS_FUNCTIONS = {
    "IsDebuggerPresent": "anti-debug",
    "CheckRemoteDebuggerPresent": "anti-debug",
    "NtQueryInformationProcess": "anti-debug",
    "GetTickCount": "timing evasion",
    "VirtualAllocEx": "process injection",
    "CreateRemoteThread": "process injection",
    "WriteProcessMemory": "process injection",
    "NtWriteVirtualMemory": "process injection",
    "QueueUserAPC": "APC injection",
    "SetWindowsHookEx": "keylogging",
    "GetAsyncKeyState": "keylogging",
    "CreateProcessW": "process spawn",
    "RegOpenKeyExW": "registry access",
    "RegSetValueExW": "registry persistence",
    "ShellExecuteW": "command execution",
}

_URL_RE = re.compile(r"(?i)(https?|ftp)://[^\s\"'<>]+")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_REGISTRY_RE = re.compile(r"(?i)(HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKCC|SOFTWARE\\[^\s\"'<>]+)")
_CMD_RE = re.compile(
    r"(?i)(powershell\s+-enc|cmd\.exe|/c\s+del\s+\\\\|net\s+user|schtasks\s+/create|"
    r"reg\s+add|wscript\.exe|cscript\.exe|rundll32|mimikatz|keylog|psexec)"
)

TRICK_STRINGS = ["vbox", "vmware", "virtualbox", "qemu", "hypervisor", "cpu brand"]


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    ent = 0.0
    length = len(data)
    for c in counts:
        if c:
            p = c / length
            ent -= p * math.log2(p)
    return round(ent, 4)


def extract_strings(data: bytes, min_len: int = 5, limit: int = 4000) -> list[str]:
    out: list[str] = []
    current = bytearray()
    for b in data:
        if 32 <= b <= 126:
            current.append(b)
        else:
            if len(current) >= min_len:
                out.append(bytes(current).decode("ascii", "ignore"))
                if len(out) >= limit:
                    return out
            current.clear()
    if len(current) >= min_len:
        out.append(bytes(current).decode("ascii", "ignore"))
    return out


def extract_unicode_strings(data: bytes, min_len: int = 4, limit: int = 2000) -> list[str]:
    out: list[str] = []
    current = bytearray()
    i = 0
    n = len(data)
    while i + 1 < n:
        if data[i + 1] == 0 and 32 <= data[i] <= 126:
            current.append(data[i])
            i += 2
        else:
            if len(current) >= min_len:
                out.append(bytes(current).decode("ascii", "ignore"))
                if len(out) >= limit:
                    return out
            current.clear()
            i += 1
    if len(current) >= min_len:
        out.append(bytes(current).decode("ascii", "ignore"))
    return out


def classify_strings(all_strings: list[str]) -> dict:
    urls: list[str] = []
    ips: list[str] = []
    registry_keys: list[str] = []
    suspicious_cmds: list[str] = []
    for s in all_strings:
        if _URL_RE.search(s):
            urls.append(s.strip())
        if _IP_RE.search(s) and not re.fullmatch(r"[\d.]+", s):
            ips.append(s.strip())
        if _REGISTRY_RE.search(s):
            registry_keys.append(s.strip())
        if _CMD_RE.search(s):
            suspicious_cmds.append(s.strip())
    return {
        "urls": sorted(set(urls)),
        "ips": sorted(set(ips)),
        "registry_keys": sorted(set(registry_keys)),
        "suspicious_cmds": sorted(set(suspicious_cmds)),
    }


def _parse_cert_blob(raw: bytes) -> dict:
    result = {"is_signed": False, "subject": None, "issuer": None, "validity_days": 0}
    if not raw:
        return result
    if len(raw) < 8 or raw[:2] not in (b"\x02\x01", b"\x02\x00"):
        try:
            magic = int.from_bytes(raw[:2], "little")
        except Exception:  # noqa: BLE001
            return result
        if magic != 0x0002:
            return result
    try:
        cns = re.findall(rb"CN=[^,\x00\r\n]{2,80}", raw)
        orgs = re.findall(rb"O=[^,\x00\r\n]{2,80}", raw)
        result["is_signed"] = True
        subj = (cns[0] if cns else b"").decode("ascii", "ignore")
        issr = (cns[1] if len(cns) > 1 else (orgs[0] if orgs else b"")).decode("ascii", "ignore")
        result["subject"] = subj or None
        result["issuer"] = issr or None
        dates = re.findall(rb"(\d{12})Z", raw)
        if len(dates) >= 2:
            from datetime import datetime

            try:
                nbf = datetime.strptime(dates[0].decode(), "%y%m%d%H%M%S")
                exp = datetime.strptime(dates[-1].decode(), "%y%m%d%H%M%S")
                result["validity_days"] = max(0, (exp - nbf).days)
            except ValueError:
                result["validity_days"] = 0
    except Exception:  # noqa: BLE001
        pass
    return result


def _parse_pe(path: str, hashes: dict) -> dict:
    pe = pefile.PE(path, fast_load=False)
    data = Path(path).read_bytes()

    result: dict = {
        "file_type": "PE32" if pe.FILE_HEADER.Machine in (0x014C,) else "PE32+",
        "basic_info": {},
        "sections": [],
        "imports": [],
        "certificates": {},
        "resources": [],
        "strings": {},
        "yara_matches": [],
        "packer_detected": False,
        "packer_name": None,
        "has_port_502": False,
        "has_modbus_strings": False,
        "suspicious_import_flags": [],
        "flags": {},
        "summary": {},
        "raw_strings_sample": [],
        "score": 0,
    }

    arch = "x86"
    if pe.FILE_HEADER.Machine == 0x8664:
        arch = "AMD64"
    elif pe.FILE_HEADER.Machine == 0xAA64:
        arch = "ARM64"

    compiler = None
    try:
        if hasattr(pe, "RICH_HEADER") and pe.RICH_HEADER:
            vals = [v for v in pe.RICH_HEADER.values if isinstance(v, int) and v > 0]
            if vals:
                compiler = f"Rich header product id 0x{vals[0]:x}"
        if hasattr(pe, "VS_FIXEDFILEINFO") and pe.VS_FIXEDFILEINFO:
            compiler = compiler or "MSVC VersionInfo present"
        if compiler is None:
            for sec in pe.sections:
                n = sec.Name.rstrip(b"\x00")
                if b"mingw" in n or b"__w" in n or b".eh_frame" == n:
                    compiler = "MinGW/GCC toolchain"
                    break
    except Exception:  # noqa: BLE001
        pass

    packed, packer_name = detect_packer(data)
    result["packer_detected"] = packed
    result["packer_name"] = packer_name

    sections = []
    max_entropy = 0.0
    num_high_entropy = 0
    for sec in pe.sections:
        name = sec.Name.rstrip(b"\x00").decode("ascii", "ignore") or "(noname)"
        entropy = round(sec.get_entropy(), 4)
        flags_list = []
        if sec.Characteristics & 0x20000000:
            flags_list.append("executable")
        if sec.Characteristics & 0x80000000:
            flags_list.append("writeable")
        if entropy > 7.0 and sec.SizeOfRawData > 0:
            flags_list.append("high_entropy")
        if entropy > 7.0 and sec.SizeOfRawData > 0:
            num_high_entropy += 1
        max_entropy = max(max_entropy, entropy)
        sections.append(
            {
                "name": name,
                "virtual_address": hex(sec.VirtualAddress),
                "virtual_size": sec.Misc_VirtualSize,
                "raw_size": sec.SizeOfRawData,
                "entropy": entropy,
                "high_entropy": entropy > 7.0 and sec.SizeOfRawData > 0,
                "flags": flags_list,
            }
        )

    imports = []
    suspicious_flags = set()
    has_network = False
    has_registry = False
    has_injection = False
    has_antidebug = False
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("ascii", "ignore").lower()
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    funcs.append(imp.name.decode("ascii", "ignore"))
            funcs = sorted(set(funcs))
            suspicious_funcs = {
                f: v for f, v in _SUSPICIOUS_FUNCTIONS.items() if f.lower() in {x.lower() for x in funcs}
            }
            if dll_name in _SUSPICIOUS_DLLS:
                kind = _SUSPICIOUS_DLLS[dll_name]
                if kind == "network":
                    has_network = True
                    suspicious_flags.add(f"network API via {dll_name}")
                if kind == "registry":
                    has_registry = True
                    suspicious_flags.add(f"registry API via {dll_name}")
            for f, v in suspicious_funcs.items():
                suspicious_flags.add(f"{f} ({v})")
                if v == "anti-debug":
                    has_antidebug = True
                if v == "process injection":
                    has_injection = True
            imports.append(
                {
                    "dll": entry.dll.decode("ascii", "ignore"),
                    "functions": funcs,
                    "suspicious": sorted(set(suspicious_funcs.keys())),
                }
            )

    certificates = {"is_signed": False, "subject": None, "issuer": None, "validity_days": 0, "raw_entries": 0}
    try:
        security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        if security_dir.VirtualAddress and security_dir.Size:
            offset = security_dir.VirtualAddress
            size = min(security_dir.Size, len(data) - offset)
            blob = data[offset: offset + size]
            certificates = _parse_cert_blob(blob)
            certificates["raw_entries"] = 1
    except Exception:  # noqa: BLE001
        pass

    resources = []
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            def walk(entries, depth=0, res_type=None, res_name=None):
                for e in entries:
                    if hasattr(e, "directory") and e.directory is not None and e.directory.entries:
                        walk(e.directory.entries, depth + 1, res_type if depth > 0 else e.id, e.name)
                    elif hasattr(e, "data") and e.data is not None:
                        rva = e.data.struct.OffsetToData
                        rsize = e.data.struct.Size
                        rdata = pe.get_data(rva, min(rsize, 1 << 20))
                        ent = shannon_entropy(rdata)
                        rtype = res_type if res_type is not None else "unknown"
                        try:
                            tname = pefile.RESOURCE_TYPE.get(rtype, f"RT_{rtype}")
                        except Exception:  # noqa: BLE001
                            tname = f"RT_{rtype}"
                        resources.append(
                            {
                                "type": tname,
                                "name": str(res_name.name) if res_name and hasattr(res_name, "name") else f"#{e.id}",
                                "size": rsize,
                                "entropy": ent,
                                "high_entropy": ent > 7.0,
                            }
                        )

            walk(pe.DIRECTORY_ENTRY_RESOURCE.entries)
    except Exception:  # noqa: BLE001
        pass

    num_exported = 0
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        try:
            num_exported = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        except Exception:  # noqa: BLE001
            pass

    debug_info_present = hasattr(pe, "DIRECTORY_ENTRY_DEBUG") and bool(pe.DIRECTORY_ENTRY_DEBUG)

    ascii_strs = extract_strings(data, limit=20000)
    uni_strs = extract_unicode_strings(data, limit=10000)
    all_strings = ascii_strs + uni_strs
    classified = classify_strings(all_strings)

    has_modbus = any("modbus" in s.lower() for s in all_strings)
    has_port_502 = has_modbus and any(re.search(r"(?i)(:502|\b502\b)", s) for s in all_strings[: len(all_strings) // 2])
    if has_modbus:
        has_port_502 = True

    yara_matches = []
    if HAS_YARA:
        try:
            compiled = yara.compile(source=YARA_RULES)
            for m in compiled.match(data=data):
                yara_matches.append(
                    {"rule": m.rule, "description": m.meta.get("description", ""), "tags": list(m.tags)}
                )
        except Exception:  # noqa: BLE001
            yara_matches = []
    if not yara_matches:
        if b"UPX!" in data[:4096]:
            yara_matches.append({"rule": "UPX_Packed", "description": "Detects UPX packing"})
        if (has_network and (has_injection or has_antidebug)) or (has_network and has_antidebug):
            yara_matches.append(
                {"rule": "SuspiciousApiCombo", "description": "Network plus injection or anti-debug API combination"}
            )
        if any(p in s.lower() for s in all_strings for p in ("powershell", "-enc", "iex(")):
            yara_matches.append({"rule": "PowerShellExecution", "description": "PowerShell execution strings"})
        if sum(1 for p in ("modbus", "substation", "scada", "breaker trip") if any(p in s.lower() for s in all_strings)) >= 2:
            yara_matches.append(
                {"rule": "PowerSectorImplantStrings", "description": "Strings referencing OT/SCADA attack primitives"}
            )

    claimed_vendor = None
    try:
        if pe.FileInfo:
            for finfo in pe.FileInfo:
                if finfo.Key == b"StringFileInfo":
                    for st in finfo.StringTable:
                        claimed_vendor = st.entries.get(b"CompanyName", b"").decode("utf-8", "ignore").strip() or None
                        if claimed_vendor:
                            break
        if not claimed_vendor and certificates.get("subject"):
            claimed_vendor = certificates["subject"]
        if not claimed_vendor:
            claimed_vendor = "UNKNOWN (unsigned, no version info)"
    except Exception:  # noqa: BLE001
        claimed_vendor = "UNKNOWN"

    cert_issuer = certificates.get("issuer") or ""
    cert_misspelled = any(
        m in (cert_issuer + (certificates.get("subject") or "")).lower() for m in ["siemenss", "abb ", "schneiderr", "general electricc"]
    )

    resource_entropy_avg = round(sum(r["entropy"] for r in resources) / len(resources), 4) if resources else 0.0

    static_score = 0
    if has_network:
        static_score += 25
    if has_registry:
        static_score += 15
    if has_injection:
        static_score += 25
    if has_antidebug:
        static_score += 15
    if packed:
        static_score += 15
    if not certificates.get("is_signed"):
        static_score += 10
    if cert_misspelled:
        static_score += 30
    if classified["urls"]:
        static_score += 10
    if classified["registry_keys"]:
        static_score += 5
    if has_modbus:
        static_score += 15
    if len(yara_matches) >= 2:
        static_score += 10
    static_score = min(100, static_score)

    result.update(
        {
            "basic_info": {
                "filename": Path(path).name,
                "size": hashes["size"],
                "size_human": _human_size(hashes["size"]),
                "md5": hashes["md5"],
                "sha256": hashes["sha256"],
                "ssdeep": hashes["ssdeep"],
                "architecture": arch,
                "claimed_vendor": claimed_vendor,
                "is_signed": bool(certificates.get("is_signed")),
                "signer_subject": certificates.get("subject"),
                "signer_issuer": cert_issuer or None,
                "cert_validity_days": certificates.get("validity_days", 0),
                "cert_misspelled": cert_misspelled,
                "compiler": compiler,
                "tricks_detected": sorted(set(t for t in TRICK_STRINGS if any(t in s.lower() for s in all_strings))),
            },
            "sections": sections,
            "imports": imports,
            "certificates": certificates,
            "resources": resources,
            "strings": classified,
            "yara_matches": yara_matches,
            "has_port_502": has_port_502,
            "has_modbus_strings": has_modbus,
            "suspicious_import_flags": sorted(suspicious_flags),
            "flags": {
                "network_api": has_network,
                "registry_api": has_registry,
                "injection_api": has_injection,
                "antidebug_api": has_antidebug,
            },
            "summary": {
                "num_sections": len(sections),
                "num_imports": len(imports),
                "max_section_entropy": max_entropy,
                "num_high_entropy_sections": num_high_entropy,
                "resource_entropy_avg": resource_entropy_avg,
                "num_exported_functions": num_exported,
                "debug_info_present": debug_info_present,
            },
            "raw_strings_sample": all_strings[:120],
            "score": static_score,
        }
    )
    return result


def _parse_elf(path: str, hashes: dict) -> dict:
    data = Path(path).read_bytes()
    ascii_strs = extract_strings(data, limit=20000)
    uni_strs = extract_unicode_strings(data, limit=10000)
    all_strings = ascii_strs + uni_strs
    classified = classify_strings(all_strings)
    has_network = any(s.lower() in {"libc", "libsocket"} for s in [])
    has_network = bool(re.search(r"(?i)socket\(|connect\(|getaddrinfo", "\n".join(all_strings[:200])))
    has_registry = False
    has_injection = False
    has_antidebug = bool(re.search(r"(?i)isatty|ptrace\(", "\n".join(all_strings[:200])))
    has_modbus = any("modbus" in s.lower() for s in all_strings)
    packed, packer_name = detect_packer(data)
    elf_class = "ELF64" if data[4] == 2 else "ELF32"
    machine = {"0x3E": "AMD64", "0x28": "ARM", "0xB7": "AArch64", "0x03": "x86"}.get(hex(int.from_bytes(data[18:20], "little")), "unknown")

    resources = []
    yara_matches = []
    if HAS_YARA:
        try:
            for m in yara.compile(source=YARA_RULES).match(data=data):
                yara_matches.append({"rule": m.rule, "description": m.meta.get("description", ""), "tags": list(m.tags)})
        except Exception:  # noqa: BLE001
            pass
    if not yara_matches:
        if b"UPX!" in data[:4096]:
            yara_matches.append({"rule": "UPX_Packed", "description": "Detects UPX packing"})
        if any(p in s.lower() for s in all_strings for p in ("powershell", "-enc", "iex(")):
            yara_matches.append({"rule": "PowerShellExecution", "description": "PowerShell execution strings"})
        if sum(1 for p in ("modbus", "substation", "scada", "breaker trip") if any(p in s.lower() for s in all_strings)) >= 2:
            yara_matches.append({"rule": "PowerSectorImplantStrings", "description": "Strings referencing OT/SCADA attack primitives"})

    static_score = 20 if has_network else 0
    static_score += 15 if has_modbus else 0
    static_score += 10 if classified["urls"] else 0
    static_score += 5 if classified["registry_keys"] else 0
    static_score += 15 if packed else 0
    static_score += 10 if len(yara_matches) >= 2 else 0
    static_score = min(100, static_score)

    return {
        "file_type": elf_class,
        "basic_info": {
            "filename": Path(path).name,
            "size": hashes["size"],
            "size_human": _human_size(hashes["size"]),
            "md5": hashes["md5"],
            "sha256": hashes["sha256"],
            "ssdeep": hashes["ssdeep"],
            "architecture": machine,
            "claimed_vendor": "UNKNOWN (ELF, no signature)",
            "is_signed": False,
            "signer_subject": None,
            "signer_issuer": None,
            "cert_validity_days": 0,
            "cert_misspelled": False,
            "compiler": None,
            "tricks_detected": [],
        },
        "sections": [],
        "imports": [],
        "certificates": {"is_signed": False, "subject": None, "issuer": None, "validity_days": 0, "raw_entries": 0},
        "resources": resources,
        "strings": classified,
        "yara_matches": yara_matches,
        "has_port_502": has_modbus,
        "has_modbus_strings": has_modbus,
        "suspicious_import_flags": [],
        "flags": {"network_api": has_network, "registry_api": False, "injection_api": False, "antidebug_api": has_antidebug},
        "summary": {
            "num_sections": 0,
            "num_imports": 0,
            "max_section_entropy": max(shannon_entropy(data[i: i + 4096]) for i in range(0, min(len(data), 65536), 4096)) or 0.0,
            "num_high_entropy_sections": 0,
            "resource_entropy_avg": 0.0,
            "num_exported_functions": 0,
            "debug_info_present": False,
        },
        "raw_strings_sample": all_strings[:120],
        "score": static_score,
    }


def _human_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.2f} MB"


class UnsupportedFormatError(Exception):
    pass


def run_static_scan(path: str) -> dict:
    data = Path(path).read_bytes()
    if data[:2] == b"MZ" and HAS_PEFILE:
        hashes = hash_file(data)
        return _parse_pe(path, hashes)
    if data[:4] == b"\x7fELF":
        hashes = hash_file(data)
        return _parse_elf(path, hashes)
    raise UnsupportedFormatError("Unsupported format: not a PE or ELF binary.")


def build_autopsy_graph(static: dict) -> dict:
    nodes: list[dict] = []
    links: list[dict] = []
    seen_ids: set[str] = set()

    def add_node(node_id: str, label: str, group: str, risk: str, details: str = ""):
        if node_id in seen_ids:
            return node_id
        seen_ids.add(node_id)
        nodes.append(
            {"id": node_id, "label": label, "group": group, "risk": risk, "details": details}
        )
        return node_id

    root_id = add_node("file", static.get("basic_info", {}).get("filename", "sample"), "file", "red", "Binary under investigation")

    has_network = static.get("flags", {}).get("network_api")
    has_injection = static.get("flags", {}).get("injection_api")
    has_antidebug = static.get("flags", {}).get("antidebug_api")
    risk = "red" if (has_network or has_injection) else ("yellow" if has_antidebug else "green")

    for sec in static.get("sections", []):
        sec_risk = "red" if sec.get("high_entropy") else "green"
        nid = add_node(f"sec:{sec['name']}", f"{sec['name']}\nentropy {sec['entropy']}", "section", sec_risk, f"VA {sec['virtual_address']}, raw {sec['raw_size']} bytes")
        links.append({"source": root_id, "target": nid})

    for imp in static.get("imports", []):
        dll = imp["dll"]
        dll_risk = "red" if dll.lower() in _SUSPICIOUS_DLLS else ("yellow" if imp["suspicious"] else "green")
        nid = add_node(f"imp:{dll}", dll, "import", dll_risk, f"{len(imp['functions'])} imports; suspicious: {', '.join(imp['suspicious']) or 'none'}")
        links.append({"source": root_id, "target": nid})
        for f in imp["suspicious"][:6]:
            fid = add_node(f"fun:{f}", f, "function", "red", _SUSPICIOUS_FUNCTIONS.get(f, "suspicious API"))
            links.append({"source": nid, "target": fid})

    cert = static.get("certificates", {})
    if cert.get("is_signed"):
        cid = add_node("cert", f"Signed: {cert.get('subject')}", "certificate", "green", f"Issuer: {cert.get('issuer')}")
    else:
        misspelled = static.get("basic_info", {}).get("cert_misspelled")
        cid = add_node("cert", "UNSIGNED" + (" / fake vendor" if misspelled else ""), "certificate", "red" if misspelled else "yellow", "No valid Authenticode signature")
    links.append({"source": root_id, "target": cid})

    for res in static.get("resources", []):
        r_risk = "red" if res.get("high_entropy") else "green"
        rid = add_node(f"res:{res['type']}:{res['name']}", f"{res['type']} #{res['name']}\n{res['size']}B entropy {res['entropy']}", "resource", r_risk, "High-entropy payload possible")
        links.append({"source": root_id, "target": rid})

    for cat, color, label in (("urls", "red", "URL"), ("ips", "yellow", "IP"), ("registry_keys", "red", "Registry"), ("suspicious_cmds", "red", "Cmd")):
        items = static.get("strings", {}).get(cat, [])[:8]
        if items:
            nid = add_node(f"str:{cat}", f"{label} strings ({len(items)})", "strings", color, "; ".join(items[:5]))
            links.append({"source": root_id, "target": nid})

    if static.get("yara_matches"):
        yid = add_node("yara", "YARA: " + ", ".join(m["rule"] for m in static["yara_matches"]), "yara", "red", static["yara_matches"][0].get("description", ""))
        links.append({"source": root_id, "target": yid})

    return {"nodes": nodes, "links": links}
