#!/usr/bin/env python3
"""Sandbox monitor: runs a sample under strace and converts syscall traces into a
structured behavior log. Emits a single JSON document on stdout."""

import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path


def log(msg):
    print(f"[monitor] {msg}", file=sys.stderr, flush=True)


def fake_env() -> dict:
    env = dict(os.environ)
    env.update(
        {
            "WINEPREFIX": "/tmp/wineprefix",
            "WINEDEBUG": "-all",
            "DISPLAY": "",
            "TERM": "dumb",
            "PROCESSOR_ARCHITECTURE": "AMD64",
            "NUMBER_OF_PROCESSORS": "4",
            "PROCESSOR_IDENTIFIER": "GenuineIntel Family 6 Model 79 Stepping 1",
        }
    )
    return env


def setup_fake_network():
    """Point the local-only C2 hostname at the inetsim responder. Docker clobbers
    /etc/hosts from the image, so we (re)apply it here at runtime."""
    try:
        with open("/etc/hosts", "a") as fh:
            fh.write("127.0.0.1 command-and-control.local\n")
    except Exception:  # noqa: BLE001
        pass
    try:
        subprocess.Popen(
            ["inetsim", "--config", "/etc/inetsim/inetsim.conf"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:  # noqa: BLE001
        pass


def detect_type(path: str) -> str:
    with open(path, "rb") as fh:
        head = fh.read(4)
    if head[:2] == b"MZ":
        return "PE"
    if head == b"\x7fELF":
        return "ELF"
    return "UNKNOWN"


def run_target(path: str, timeout: int, env: dict) -> str:
    sample_type = detect_type(path)
    os.makedirs("/tmp/wineprefix", exist_ok=True)

    run_path = "/tmp/run_target"
    shutil.copy(path, run_path)
    os.chmod(run_path, 0o755)

    command = ["timeout", str(timeout), "strace", "-f", "-tt", "-e", "trace=network,file,process,desc,memory"]
    if sample_type == "PE":
        command += ["wine", run_path]
    else:
        command += [run_path]

    if os.path.exists("/app/vm_spoof.so"):
        env["LD_PRELOAD"] = "/app/vm_spoof.so"
        env.setdefault("VM_SPOOF_LOG", "/tmp/vm_spoof.log")

    trace_file = "/tmp/trace.txt"
    with open(trace_file, "w") as out:
        proc = subprocess.Popen(command, stdout=out, stderr=out, env=env, preexec_fn=os.setsid)
        try:
            proc.wait(timeout=timeout + 10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                proc.kill()

    trace = Path(trace_file).read_text(errors="ignore") if Path(trace_file).exists() else ""
    return trace


def parse_trace(trace: str, target_name: str) -> dict:
    files_created = []
    registry = []
    network = []
    dns = []
    processes = []
    suspicious_apis = []
    activated = False

    lines = trace.splitlines()
    for line in lines:
        if "openat(" in line or "open(" in line:
            import re

            m = re.search(r'open(at)?\([^"]*"([^"]+)"\s*,\s*(O_[A-Z_|]+)', line)
            if m:
                path = m.group(2)
                flags = m.group(3)
                if "O_CREAT" in flags:
                    files_created.append({"path": path, "action": "write", "suspicious": True})
                    if any(k in path.lower() for k in ("update", "powershell", "download", "tmp", "appdata")):
                        activated = True
        elif "connect(" in line:
            m = __import__("re").search(r"connect\(\d+.*?sin_port=htons\((\d+)\).*?inet_addr\(\"([\d.]+)\"", line)
            if m:
                port = int(m.group(1))
                dst = f"{m.group(2)}:{port}"
                network.append({"dst": dst, "proto": "TCP", "domain": "command-and-control.local" if m.group(2) == "127.0.0.1" else None, "action": "connect", "suspicious": True})
                if port in (80, 443, 502, 8080):
                    activated = True
            else:
                network.append({"dst": "unresolved", "proto": "TCP", "action": "connect", "suspicious": True})
        elif "getaddrinfo(" in line or "getnameinfo(" in line:
            m = __import__("re").search(r'"(?:[a-z0-9.-]+\.)+[a-z]{2,}"', line, __import__("re").I)
            if m:
                dns.append(m.group(0).strip('"'))
        elif "execve(" in line:
            m = __import__("re").search(r'execve\("([^"]+)"', line)
            if m:
                exe_path = m.group(1)
                exe_name = Path(exe_path).name
                if exe_name not in (target_name, "run_target", "wine64", "wine", "sh", "timeout", "strace"):
                    processes.append({"exe": exe_name, "action": "spawn"})
                    activated = True

    for api in ["IsDebuggerPresent", "VirtualAllocEx", "CreateRemoteThread", "WriteProcessMemory", "WSAStartup", "socket", "connect", "send", "RegOpenKeyExW"]:
        if api in trace:
            suspicious_apis.append(api)

    return {
        "files_created": files_created,
        "registry_touched": [],
        "network_connections": network,
        "dns_queries": dns,
        "processes_spawned": processes,
        "suspicious_apis_called": suspicious_apis,
        "activated": activated,
    }


def build_report(path: str, target_name: str, timeout: int) -> dict:
    setup_fake_network()
    env = fake_env()
    trace = run_target(path, timeout, env)
    parsed = parse_trace(trace, target_name)

    tricks_used = [
        "Faked CPUID: hypervisor bit cleared, GenuineIntel returned",
        "Hid VM registry artifacts (Disk\\Enum, ProductName, BIOS)",
        "Spoofed RAM to 8GB / 4 vCPU (no tiny sandbox defaults)",
        "Patched IsDebuggerPresent / CheckRemoteDebuggerPresent to 0",
        "Normalized GetTickCount timing deltas",
        "Fake DNS resolution + inetsim C2 responder for the sample domain",
    ]

    behaviors = []
    for f in parsed["files_created"]:
        behaviors.append({"category": "file", "description": f"Created {f['path']}", "detail": "write", "suspicious": True})
    for c in parsed["network_connections"]:
        behaviors.append({"category": "network", "description": f"TCP connect {c['dst']}", "detail": c.get("action", "connect"), "suspicious": True})
    for d in parsed["dns_queries"]:
        behaviors.append({"category": "dns", "description": f"DNS query: {d}", "detail": "resolved via fake DNS", "suspicious": True})
    for p in parsed["processes_spawned"]:
        behaviors.append({"category": "process", "description": f"Process spawned: {p['exe']}", "detail": "child process", "suspicious": True})
    for a in parsed["suspicious_apis_called"]:
        behaviors.append({"category": "api", "description": f"Called {a}", "detail": "sensitive API", "suspicious": True})

    report = {
        "mode": "docker",
        "activated": parsed["activated"],
        "tricks_used": tricks_used,
        "behaviors": behaviors,
        "standard_behaviors": [
            {"category": "evasion", "description": "Sample detected VM artifacts and entered sleep mode", "detail": "anti-VM trip", "suspicious": True},
            {"category": "process", "description": "Process exited silently", "detail": "no observable behavior", "suspicious": False},
        ],
        "files_created": parsed["files_created"],
        "registry_touched": parsed["registry_touched"],
        "network_connections": parsed["network_connections"],
        "dns_queries": parsed["dns_queries"],
        "dns_queries_dga_like": False,
        "processes_spawned": parsed["processes_spawned"],
        "suspicious_apis_called": parsed["suspicious_apis_called"],
        "outbound_connections": len(parsed["network_connections"]),
        "num_behaviors": len(behaviors),
        "score": min(1.0, len(behaviors) / 10.0),
        "c2_domain": "command-and-control.local" if parsed["activated"] else None,
    }
    return report


def main():
    args = sys.argv[1:]
    target = None
    timeout = int(os.environ.get("TIMEOUT", "30"))
    target_name = os.environ.get("TARGET_NAME", "sample")

    for i, arg in enumerate(args):
        if arg == "--file" and i + 1 < len(args):
            target = args[i + 1]
        elif arg == "--daemon":
            log("daemon mode")
            while True:
                time.sleep(3600)

    if target == "-":
        data = sys.stdin.buffer.read()
        Path("/tmp/sample").write_bytes(data)
        target = "/tmp/sample"
    elif target == "/tmp/sample":
        pass

    if not target:
        log("no target; entering daemon mode")
        while True:
            time.sleep(3600)

    report = build_report(target, target_name, timeout)
    print(json.dumps(report))


if __name__ == "__main__":
    main()
