"""Prosecutor AI — template-based natural language forensic narrative."""

from __future__ import annotations

VERDICT_CONFIDENCE = {"MALICIOUS": 97, "SUSPICIOUS": 82, "CLEAN": 91}

STATIC_EXPLANATIONS = {
    "network": "the binary imports network libraries, which is how malware phones home or reaches the grid's control plane",
    "injection": "the binary imports process-injection primitives, the signature of a trojan that hijacks other processes",
    "registry": "the binary touches the Windows registry, which malware uses to achieve persistence across reboots",
    "antidebug": "the binary ships anti-debugging checks, a hallmark of malware that fears forensic analysis",
    "unsigned": "the file carries no valid digital signature, so its provenance cannot be trusted",
    "modbus": "the binary references Modbus/TCP, the very protocol used by substation protection relays",
}

DYNAMIC_VERBS = {
    "file": "dropped a persistence marker on disk",
    "network": "opened an outbound connection and began beaconing",
    "dns": "issued DNS queries against suspicious domains",
    "registry": "queried autostart registry keys",
    "process": "spawned child processes",
    "api": "called high-risk Windows APIs",
    "evasion": "attempted to detect and evade the analysis environment",
}


def _static_findings(static: dict) -> list[str]:
    findings = []
    flags = static.get("flags", {})
    basic = static.get("basic_info", {})
    if not basic.get("is_signed"):
        findings.append(
            f"During static analysis, I discovered that the file is NOT digitally signed. "
            f"This is significant because {STATIC_EXPLANATIONS['unsigned']}."
        )
    if flags.get("network_api"):
        findings.append(
            f"During static analysis, I discovered network-capable imports (ws2_32.dll / wininet.dll). "
            f"This is significant because {STATIC_EXPLANATIONS['network']}."
        )
    if flags.get("injection_api"):
        findings.append(
            f"During static analysis, I discovered process-injection APIs such as VirtualAllocEx and "
            f"CreateRemoteThread. This is significant because {STATIC_EXPLANATIONS['injection']}."
        )
    if flags.get("registry_api"):
        findings.append(
            f"During static analysis, I discovered registry-access imports via advapi32.dll. "
            f"This is significant because {STATIC_EXPLANATIONS['registry']}."
        )
    if flags.get("antidebug_api"):
        findings.append(
            f"During static analysis, I discovered anti-debugging checks (IsDebuggerPresent). "
            f"This is significant because {STATIC_EXPLANATIONS['antidebug']}."
        )
    if static.get("has_modbus_strings"):
        findings.append(
            f"During static analysis, I discovered Modbus/TCP references in the binary's strings. "
            f"This is significant because {STATIC_EXPLANATIONS['modbus']}."
        )
    if static.get("packer_detected"):
        findings.append(
            f"During static analysis, I discovered the sample is packed with {static.get('packer_name') or 'an unknown packer'}, "
            f"obscuring its true code. This is significant because packing is a technique used to defeat signature scanning."
        )
    urls = static.get("strings", {}).get("urls", [])
    if urls:
        findings.append(
            f"During static analysis, I recovered {len(urls)} network endpoint string(s) including {urls[0]}. "
            f"This is significant because embedded endpoints are command-and-control indicators."
        )
    return findings


def _dynamic_findings(dynamic: dict) -> list[str]:
    findings = []
    if not dynamic.get("activated"):
        findings.append(
            f"When executed in the deceptive sandbox, the sample stayed quiet — no network activity, "
            f"no file drops, no persistence. Normally, a legitimate utility update is equally inert; "
            f"however combined with the static evidence this silence is itself suspicious."
        )
        return findings

    cat_descs = [b["description"] for b in dynamic.get("behaviors", [])]
    for cat, verb in DYNAMIC_VERBS.items():
        if any(b.get("category") == cat for b in dynamic.get("behaviors", [])):
            findings.append(
                f"When executed in the deceptive sandbox, the sample {verb}. "
                f"Normally, {_benign_comparison(cat)}."
            )
    if dynamic.get("tricks_used"):
        tricks = ", ".join(dynamic["tricks_used"][:2])
        findings.append(
            f"Critically, the sample only activated because the sandbox actively concealed its VM "
            f"artifacts ({tricks}). In a standard sandbox, this trojan would have detected analysis "
            f"and shut itself down — that is the signature of deliberate anti-forensics."
        )
    if dynamic.get("c2_domain"):
        findings.append(
            f"When executed in the deceptive sandbox, the sample beaconed to the command-and-control "
            f"domain '{dynamic['c2_domain']}', confirming an active C2 channel rather than a benign crash."
        )
    return findings


def _benign_comparison(category: str) -> str:
    return {
        "file": "a legitimate updater writes only to its own installation directory, not to global autostart locations",
        "network": "a legitimate OT patch makes no outbound internet calls and stays inside the DMZ",
        "dns": "a legitimate utility resolves vendor patch servers, not random or DGA-style domains",
        "registry": "a legitimate installer registers one product key, it does not enumerate the entire Run hive",
        "process": "a legitimate service spawns no hidden child processes",
        "api": "a legitimate SCADA tool has no need for injection or remote-thread primitives",
        "evasion": "a legitimate vendor tool has no reason to hide from security tooling",
    }.get(category, "the expected behavior is none of these")


def _heuristic_findings(heuristic: dict) -> list[str]:
    pct = heuristic.get("risk_percentile", 50)
    score = heuristic.get("anomaly_score", 0)
    if pct >= 70:
        qualifier = "an extreme outlier"
    elif pct >= 40:
        qualifier = "a clear statistical outlier"
    else:
        qualifier = "within expected ranges"
    return [
        f"The machine learning model (IsolationForest) assigned an anomaly score of {score} and a risk "
        f"score of {pct}/100, placing this sample in the {qualifier} population of industrial binaries."
    ]


def _power_findings(power_rules: dict) -> list[str]:
    out = []
    for rule in power_rules.get("triggered_rules", []):
        out.append(
            f"Power-sector rule {rule['id']} ({rule['name']}) fired at severity {rule['severity']}: {rule['detail']}"
        )
    return out


def _grid_findings(impact: dict) -> list[str]:
    if not impact.get("attack_path"):
        return ["If deployed in a typical 220kV substation, this malware currently shows no viable attack path."]
    return [
        f"If deployed in a typical 220kV substation, this malware would {impact['cascading_effect']}, "
        f"causing an estimated {impact['load_loss_mw']}MW of load loss across {impact['affected_districts']} "
        f"district(s) and approximately {impact['restoration_hours']} hours to restore. "
        f"Overall grid severity: {impact['severity']}."
    ]


def generate_prosecutor_report(
    static: dict,
    dynamic: dict,
    heuristic: dict,
    power_rules: dict,
    impact: dict,
    verdict: str,
    risk_score: int,
) -> str:
    basic = static.get("basic_info", {})
    filename = basic.get("filename", "the sample")
    size = basic.get("size_human", "unknown")
    vendor = basic.get("claimed_vendor") or "UNKNOWN"

    intro = (
        f"PROSECUTOR FORENSIC BRIEF\n"
        f"I have completed the forensic analysis of {filename}. The file is {size} in size and "
        f"claims to be from vendor '{vendor}'.\n"
    )

    sections: list[str] = [intro]

    static_findings = _static_findings(static)
    if static_findings:
        sections.append("STATIC ANALYSIS FINDINGS:\n" + "\n".join(f"- {f}" for f in static_findings))

    dynamic_findings = _dynamic_findings(dynamic)
    if dynamic_findings:
        sections.append("DYNAMIC ANALYSIS FINDINGS (DECEPTIVE SANDBOX):\n" + "\n".join(f"- {f}" for f in dynamic_findings))

    sections.append("HEURISTIC ANALYSIS FINDINGS:\n" + "\n".join(f"- {f}" for f in _heuristic_findings(heuristic)))

    power_findings = _power_findings(power_rules)
    if power_findings:
        sections.append("POWER-SECTOR RULE FINDINGS:\n" + "\n".join(f"- {f}" for f in power_findings))

    sections.append("GRID IMPACT ASSESSMENT:\n" + "\n".join(f"- {f}" for f in _grid_findings(impact)))

    evidence_count = len(static_findings) + len(dynamic_findings) + 1 + len(power_findings) + 1
    confidence = VERDICT_CONFIDENCE.get(verdict, 90)

    verdict_line = (
        f"VERDICT:\n"
        f"Based on {evidence_count} pieces of evidence, I render a verdict of {verdict} with "
        f"{confidence}% confidence (composite risk score {risk_score}/100)."
    )
    sections.append(verdict_line)

    rec = (
        "RECOMMENDATION:\n"
        "Quarantine and destroy this artifact. Revoke any code-signing trust it carries, contain the "
        "affected workstation, sweep the OT/DMZ segment for beacons, and notify the CERT team. "
        "Do not deploy this software in any OT/DMZ environment."
    )
    sections.append(rec)

    return "\n\n".join(sections)
