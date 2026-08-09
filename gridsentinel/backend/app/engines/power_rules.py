"""Power-sector-specific detection rules (SIH1388)."""

from __future__ import annotations


class PowerContext:
    def __init__(self, static: dict, dynamic: dict):
        self._static = static
        self._dynamic = dynamic
        self.filename = static.get("basic_info", {}).get("filename", "").lower()
        self.has_network_api = static.get("flags", {}).get("network_api", False)
        self.is_signed = static.get("basic_info", {}).get("is_signed", False)
        self.has_port_502 = static.get("has_port_502", False)
        self.has_modbus_strings = static.get("has_modbus_strings", False)
        self.strings = static.get("raw_strings_sample", []) or []
        self.outbound_connections = dynamic.get("outbound_connections", 0)
        self.dns_queries_dga_like = dynamic.get("dns_queries_dga_like", False)
        self.issuer = (static.get("certificates", {}).get("issuer") or "").lower()
        self.subject = (static.get("certificates", {}).get("subject") or "").lower()
        self.antidebug = static.get("flags", {}).get("antidebug_api", False)
        self.resources_high_entropy = any(r.get("high_entropy") for r in static.get("resources", []))
        self.tricks = static.get("basic_info", {}).get("tricks_detected", [])

    def cert_issuer_contains_any(self, needles: list[str]) -> bool:
        hay = self.issuer + " " + self.subject
        return any(n in hay for n in needles)

    @property
    def strings_join(self) -> str:
        return " ".join(self.strings).lower()


RULES = [
    {
        "id": "PWR001",
        "name": "SCADA Network Exposure",
        "severity": "CRITICAL",
        "check": lambda c: c.has_network_api and "scada" in c.filename,
        "detail": lambda c: "Sample targets SCADA assets and contains network-capable API imports (ws2_32/wininet).",
    },
    {
        "id": "PWR002",
        "name": "Unsigned HES Patch",
        "severity": "HIGH",
        "check": lambda c: "hes" in c.filename and not c.is_signed,
        "detail": lambda c: "Human-Equipment-System (HES) patch binary is unsigned — supply-chain tampering vector.",
    },
    {
        "id": "PWR003",
        "name": "Modbus/TCP Reference in Binary",
        "severity": "CRITICAL",
        "check": lambda c: c.has_port_502 or c.has_modbus_strings,
        "detail": lambda c: "Binary references Modbus/TCP (port 502), the dominant protocol for grid RTU/relay comms.",
    },
    {
        "id": "PWR004",
        "name": "Fake Vendor Certificate",
        "severity": "CRITICAL",
        "check": lambda c: c.cert_issuer_contains_any(["siemenss", "abb ", "schneiderr", "general electricc"]),
        "detail": lambda c: "Certificate issuer contains misspelled vendor name typical of forged OT supply-chain certs.",
    },
    {
        "id": "PWR005",
        "name": "DMZ Beaconing Behavior",
        "severity": "HIGH",
        "check": lambda c: c.outbound_connections > 0 and c.dns_queries_dga_like,
        "detail": lambda c: "Outbound beacon observed with DGA-like DNS — C2 channel from the OT DMZ.",
    },
    {
        "id": "PWR006",
        "name": "High-Entropy Resource in SCADA Binary",
        "severity": "MEDIUM",
        "check": lambda c: c.resources_high_entropy,
        "detail": lambda c: "Resource section entropy >7.0 — possible steganographic payload or packed blob.",
    },
    {
        "id": "PWR007",
        "name": "Anti-VM Stub in Industrial Software",
        "severity": "MEDIUM",
        "check": lambda c: bool(c.antidebug or c.tricks),
        "detail": lambda c: "Anti-debug/anti-VM checks present — unusual for legitimate OT vendor software.",
    },
]


SEVERITY_ORDER = {"INFORMATIONAL": 0, "NONE": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def evaluate_power_rules(static: dict, dynamic: dict) -> dict:
    ctx = PowerContext(static, dynamic)
    triggered = []
    for rule in RULES:
        try:
            if rule["check"](ctx):
                triggered.append(
                    {
                        "id": rule["id"],
                        "name": rule["name"],
                        "severity": rule["severity"],
                        "detail": rule["detail"](ctx),
                    }
                )
        except Exception:  # noqa: BLE001
            continue
    top_severity = max((r["severity"] for r in triggered), key=lambda s: SEVERITY_ORDER.get(s, 0)) if triggered else "NONE"
    return {
        "triggered_rules": triggered,
        "num_triggered": len(triggered),
        "critical": sum(1 for r in triggered if r["severity"] == "CRITICAL"),
        "high": sum(1 for r in triggered if r["severity"] == "HIGH"),
        "medium": sum(1 for r in triggered if r["severity"] == "MEDIUM"),
        "severity": top_severity,
    }
