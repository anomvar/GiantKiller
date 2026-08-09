"""Grid impact twin: rule-based narrative animator for the power topology."""

from __future__ import annotations

TOPOLOGY = {
    "nodes": [
        {"id": "SCADA_HMI", "type": "control", "label": "SCADA Workstation", "x": 0, "y": 0},
        {"id": "Relay_1", "type": "relay", "label": "220kV Line Relay", "x": 1, "y": 0},
        {"id": "Transformer_T3", "type": "transformer", "label": "400/220kV Transformer", "x": 2, "y": 0},
        {"id": "Bus_3", "type": "bus", "label": "Bus Section 3", "x": 3, "y": 0},
        {"id": "Load_A", "type": "load", "label": "City A (150MW)", "x": 4, "y": -1},
        {"id": "Load_B", "type": "load", "label": "City B (190MW)", "x": 4, "y": 1},
    ],
    "edges": [
        {"from": "SCADA_HMI", "to": "Relay_1"},
        {"from": "Relay_1", "to": "Transformer_T3"},
        {"from": "Transformer_T3", "to": "Bus_3"},
        {"from": "Bus_3", "to": "Load_A"},
        {"from": "Bus_3", "to": "Load_B"},
    ],
}

FULL_PATH = ["SCADA_HMI", "Relay_1", "Transformer_T3", "Bus_3"]


def _build_animation_sequence(path: list[str], compromised: list[str], impact_desc: str) -> list[dict]:
    n = len(path)
    seq = []
    for i, node in enumerate(path):
        t = round(i / max(1, n - 1), 3)
        seq.append({"t": t, "node": node, "event": "compromised"})
        if i < n - 1:
            seq.append(
                {
                    "t": round((i + 0.5) / max(1, n - 1), 3),
                    "edge": f"{path[i]}→{path[i + 1]}",
                    "event": "pulse",
                }
            )
    seq.append({"t": 1.0, "node": "Load_A", "event": "power_loss"})
    seq.append({"t": 1.0, "node": "Load_B", "event": "power_loss"})
    seq.append({"t": 1.0, "node": "Bus_3", "event": "cascading_effect", "detail": impact_desc})
    return seq


def run_impact(static: dict, dynamic: dict, power_rules: dict) -> dict:
    triggered = {r["id"]: r for r in power_rules.get("triggered_rules", [])}
    has_modbus = "PWR003" in triggered
    beaconing = bool(dynamic.get("outbound_connections", 0))
    has_critical_c2 = has_modbus and beaconing
    fake_cert_only = "PWR004" in triggered and not beaconing
    network_only = static.get("flags", {}).get("network_api", False)

    if has_critical_c2:
        path = FULL_PATH
        compromised = ["SCADA_HMI", "Relay_1"]
        effect = "Trip command issued to 220kV line relay via forged Modbus frame"
        load_loss = 340
        districts = 2
        severity = "CRITICAL — Potential Grid Instability"
        restoration = 4
        attack_phases = [
            {"phase": "1. Recon", "detail": "Beaconing to C2 every 60s from the compromised HES workstation"},
            {"phase": "2. Pivot", "detail": "Abuse of Modbus/TCP port 502 to reach the protection relay"},
            {"phase": "3. Act", "detail": "Trip command injected; relay opens, overloading transformer"},
        ]
    elif network_only or (fake_cert_only and not beaconing):
        path = ["SCADA_HMI", "Relay_1"]
        compromised = ["SCADA_HMI"]
        effect = "Supply chain compromise — backdoor ready for lateral movement"
        load_loss = 0
        districts = 0
        severity = "HIGH — Lateral movement risk"
        restoration = 2
        attack_phases = [
            {"phase": "1. Entry", "detail": "Trojanized update installed on SCADA workstation"},
            {"phase": "2. Persist", "detail": "Autostart registry key planted; beacon armed"},
        ]
    elif triggered:
        path = ["SCADA_HMI"]
        compromised = ["SCADA_HMI"]
        effect = "Tampered control asset — monitoring required, no active grid commands"
        load_loss = 0
        districts = 0
        severity = "MEDIUM — Asset compromise"
        restoration = 1
        attack_phases = [
            {"phase": "1. Entry", "detail": "Suspicious binary present on control-system asset"},
        ]
    else:
        path = []
        compromised = []
        effect = "No credible attack path identified"
        load_loss = 0
        districts = 0
        severity = "INFORMATIONAL — No impact"
        restoration = 0
        attack_phases = []

    return {
        "topology": TOPOLOGY,
        "attack_path": path,
        "compromised_nodes": compromised,
        "cascading_effect": effect,
        "load_loss_mw": load_loss,
        "affected_districts": districts,
        "severity": severity,
        "restoration_hours": restoration,
        "attack_phases": attack_phases,
        "animation_sequence": _build_animation_sequence(path, compromised, effect),
    }
