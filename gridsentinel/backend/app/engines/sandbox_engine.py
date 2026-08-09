"""Deceptive sandbox engine.

Tries a real Docker-backed sandbox container that hides VM artifacts, and falls
back to a deterministic simulation driven by static evidence so the demo always
produces a rich, structured behavior log.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path

from ..config import DOCKER_ENABLED, SANDBOX_IMAGE, SANDBOX_TIMEOUT
from ..utils.hasher import looks_like_dga

try:
    import docker

    HAS_DOCKER = True
except Exception:  # noqa: BLE001
    HAS_DOCKER = False

TRICKS_USED = [
    "Faked CPUID: hypervisor bit cleared, GenuineIntel returned",
    "Hid VM registry artifacts (Disk\\Enum, ProductName, BIOS)",
    "Spoofed RAM to 8GB / 4 vCPU (no tiny sandbox defaults)",
    "Patched IsDebuggerPresent / CheckRemoteDebuggerPresent to 0",
    "Normalized GetTickCount timing deltas",
    "Fake DNS resolution + inetsim C2 responder for the sample domain",
]

HYPERVISOR_MARKERS = ["vbox", "vmware", "virtualbox", "qemu", "hyper-v", "hypervisor", "xen", "parallels"]
DOMAIN_RE = re.compile(r"(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}")


def _extract_beacon(static: dict) -> tuple[list[str], list[str], list[dict]]:
    urls = static.get("strings", {}).get("urls", [])
    dns: list[str] = []
    conns: list[dict] = []
    for u in urls:
        m = re.match(r"(?i)(https?|ftp)://([^/\s:]+)(?::(\d+))?([^\s]*)", u)
        if m:
            proto, host, port, path = m.group(1), m.group(2), m.group(3), m.group(4) or "/"
            dns.append(host)
            conns.append(
                {
                    "dst": f"{host}:{port or (443 if proto == 'https' else 80)}",
                    "proto": "TCP",
                    "domain": host,
                    "path": path,
                    "action": f"{proto.upper()} beacon",
                    "suspicious": True,
                }
            )
    return dns, conns, urls


def _extract_domains(strings: list[str]) -> list[str]:
    domains: list[str] = []
    for s in strings:
        for m in DOMAIN_RE.findall(s):
            if not m.startswith(("10.", "192.", "172.", "127.")):
                domains.append(m)
    return sorted(set(domains))


def _simulate(static: dict) -> dict:
    flags = static.get("flags", {})
    tricks = static.get("basic_info", {}).get("tricks_detected", [])
    antidebug = flags.get("antidebug_api", False)
    has_vm_check = len(tricks) > 0 or antidebug
    dns, conns, urls = _extract_beacon(static)
    has_c2 = bool(urls) or bool(dns)

    activated = has_c2 and (has_vm_check or flags.get("network_api", False) or flags.get("injection_api", False))

    filename = static.get("basic_info", {}).get("filename", "sample")
    all_strings = static.get("raw_strings_sample", []) or []
    joined = "\n".join(all_strings).lower()

    behaviors: list[dict] = []
    standard_behaviors: list[dict] = []

    if activated:
        files_created: list[dict] = []
        if "powerconfig" in joined or "update.log" in joined:
            files_created.append(
                {
                    "path": "%APPDATA%\\Microsoft\\Windows\\PowerConfig\\update.log",
                    "action": "write",
                    "content_hint": "persistence marker (appears to survive reboot)",
                    "suspicious": True,
                }
            )
        if not files_created:
            files_created.append(
                {
                    "path": f"%TEMP%\\{filename.rsplit('.', 1)[0]}.tmp",
                    "action": "write",
                    "content_hint": "stage-2 payload extraction",
                    "suspicious": True,
                }
            )

        registry: list[dict] = []
        if "currentversion\\run" in joined or "software\\microsoft\\windows\\currentversion\\run" in joined:
            registry.append(
                {
                    "key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "action": "read",
                    "note": "enumerating autostart keys (persistence check)",
                    "suspicious": True,
                }
            )
        if not registry and static.get("strings", {}).get("registry_keys"):
            registry.append(
                {
                    "key": static["strings"]["registry_keys"][0],
                    "action": "read",
                    "note": "registry read for system fingerprinting",
                    "suspicious": True,
                }
            )
        if not registry:
            registry.append(
                {
                    "key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                    "action": "read",
                    "note": "enumerating installed software",
                    "suspicious": False,
                }
            )

        processes = [{"pid": 1042, "exe": filename, "parent": 1, "note": "dropped child: heartbeat beacon"}]
        dga_like = any(looks_like_dga(d) for d in dns)

        for f in files_created:
            behaviors.append({"category": "file", "description": f"Created {f['path']} ({f['action']})", "detail": f["content_hint"], "suspicious": True})
        for r in registry:
            behaviors.append({"category": "registry", "description": f"Queried {r['key']} ({r['action']})", "detail": r["note"], "suspicious": r["suspicious"]})
        for c in conns:
            behaviors.append({"category": "network", "description": f"TCP connect {c['dst']} — {c['action']}", "detail": f"GET {c['path']}", "suspicious": True})
        for d in dns:
            behaviors.append({"category": "dns", "description": f"DNS query: {d}", "detail": "DGA-like" if looks_like_dga(d) else "resolved via fake DNS", "suspicious": looks_like_dga(d)})
        for p in processes:
            behaviors.append({"category": "process", "description": f"Process spawned: {p['exe']} (pid {p['pid']})", "detail": p["note"], "suspicious": True})

        if flags.get("injection_api", False) or any(f in joined for f in ("createremotethread", "virtualallocex", "writeprocessmemory")):
            behaviors.append({"category": "api", "description": "Called VirtualAllocEx + CreateRemoteThread (injection primitives)", "detail": "process injection into remote process", "suspicious": True})
        if flags.get("network_api", False):
            behaviors.append({"category": "api", "description": "WSAStartup / socket / connect sequence observed", "detail": "network API family", "suspicious": True})
        if antidebug:
            behaviors.append({"category": "api", "description": "IsDebuggerPresent called and returned 0 (spoofed)", "detail": "anti-debug bypassed by deceptive sandbox", "suspicious": False})
        if has_vm_check:
            behaviors.append({"category": "api", "description": "CPUID hypervisor query returned GenuineIntel (spoofed)", "detail": "anti-VM bypassed by deceptive sandbox", "suspicious": False})

        if not behaviors:
            behaviors.append({"category": "network", "description": "Outbound TCP connect to 127.0.0.1:80 (C2 emulator)", "detail": "beacon captured by inetsim", "suspicious": True})
            behaviors.append({"category": "file", "description": "Created transient payload file", "detail": "dropped stage", "suspicious": True})

        standard_behaviors.append({"category": "evasion", "description": "Sample detected VM artifacts (CPUID hypervisor bit set) and entered sleep mode", "detail": "anti-VM check tripped in standard sandbox", "suspicious": True})
        standard_behaviors.append({"category": "evasion", "description": "IsDebuggerPresent returned TRUE — sample aborted", "detail": "anti-debug check tripped", "suspicious": True})
        standard_behaviors.append({"category": "process", "description": "Process exited silently (exit code 0) after 30s", "detail": "no observable behavior", "suspicious": False})

        return {
            "mode": "simulation",
            "activated": True,
            "tricks_used": TRICKS_USED,
            "behaviors": behaviors,
            "standard_behaviors": standard_behaviors,
            "files_created": files_created,
            "registry_touched": registry,
            "network_connections": conns,
            "dns_queries": dns,
            "dns_queries_dga_like": any(looks_like_dga(d) for d in dns),
            "processes_spawned": processes,
            "suspicious_apis_called": _api_calls(static, activated),
            "outbound_connections": len(conns),
            "num_behaviors": len(behaviors),
            "score": min(1.0, len(behaviors) / 10.0),
            "c2_domain": dns[0] if dns else None,
        }

    standard_behaviors.append({"category": "process", "description": "Sample ran, no network or file activity", "detail": "benign or evasion", "suspicious": False})
    standard_behaviors.append({"category": "evasion", "description": "No anti-VM artifacts present — sample was quiet in both sandboxes", "detail": "low dynamic risk", "suspicious": False})

    behaviors.append({"category": "process", "description": "Process executed with minimal observable activity", "detail": "no suspicious syscalls", "suspicious": False})

    return {
        "mode": "simulation",
        "activated": False,
        "tricks_used": TRICKS_USED,
        "behaviors": behaviors,
        "standard_behaviors": standard_behaviors,
        "files_created": [],
        "registry_touched": [],
        "network_connections": [],
        "dns_queries": [],
        "dns_queries_dga_like": False,
        "processes_spawned": [{"pid": 1042, "exe": static.get("basic_info", {}).get("filename", "sample"), "parent": 1, "note": "exited normally"}],
        "suspicious_apis_called": _api_calls(static, activated),
        "outbound_connections": 0,
        "num_behaviors": 1,
        "score": 0.0,
        "c2_domain": None,
    }


def _api_calls(static: dict, activated: bool) -> list[str]:
    calls: list[str] = []
    flags = static.get("flags", {})
    if flags.get("network_api"):
        calls += ["WSAStartup", "socket", "connect", "send"]
    if flags.get("registry_api"):
        calls += ["RegOpenKeyExW", "RegQueryValueExW"]
    if flags.get("injection_api"):
        calls += ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
    if flags.get("antidebug_api"):
        calls += ["IsDebuggerPresent", "CheckRemoteDebuggerPresent"]
    for imp in static.get("imports", []):
        for f in imp.get("suspicious", []):
            if f not in calls:
                calls.append(f)
    if activated:
        calls += ["GetTickCount"]
    return calls[:12]


def _docker_client():
    sock = "/var/run/docker.sock"
    if os.path.exists(sock):
        return docker.DockerClient(base_url=f"unix://{sock}", version="auto")
    return docker.from_env()


def _run_container(static: dict, file_path: str) -> dict | None:
    if not DOCKER_ENABLED or not HAS_DOCKER:
        return None
    try:
        client = _docker_client()
        try:
            client.images.get(SANDBOX_IMAGE)
        except Exception:  # noqa: BLE001
            build_ctx = str(Path(__file__).resolve().parent.parent / "sandbox")
            client.images.build(path=build_ctx, tag=SANDBOX_IMAGE, rm=True)

        import io
        import tarfile

        file_bytes = Path(file_path).read_bytes()
        env = {"TARGET_NAME": Path(file_path).name, "TIMEOUT": str(SANDBOX_TIMEOUT)}
        container = client.containers.create(
            image=SANDBOX_IMAGE,
            command=["--file", "/tmp/sample"],
            privileged=True,
            cap_add=["SYS_PTRACE", "NET_ADMIN", "NET_RAW"],
            environment=env,
            mem_limit="1g",
        )
        try:
            tar_stream = io.BytesIO()
            with tarfile.open(fileobj=tar_stream, mode="w") as tar:
                info = tarfile.TarInfo(name="sample")
                info.size = len(file_bytes)
                tar.addfile(info, io.BytesIO(file_bytes))
            tar_stream.seek(0)
            container.put_archive("/tmp", tar_stream.read())
            container.start()
        except Exception:  # noqa: BLE001
            container.remove(force=True)
            return None

        result = container.wait(timeout=SANDBOX_TIMEOUT + 20)
        logs = container.logs(stdout=True, stderr=True).decode("utf-8", "ignore")
        container.remove(force=True)

        parsed = _extract_json_from_logs(logs)
        if parsed:
            parsed["mode"] = "docker"
            parsed.setdefault("tricks_used", TRICKS_USED)
            parsed.setdefault("score", min(1.0, len(parsed.get("behaviors", [])) / 10.0))
            return parsed
        return None
    except Exception:  # noqa: BLE001
        return None


def _extract_json_from_logs(logs: str) -> dict | None:
    for line in reversed(logs.splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    return None


def run_sandbox(file_path: str, static: dict) -> dict:
    result = _run_container(static, file_path)
    if result is not None:
        return result
    return _simulate(static)
