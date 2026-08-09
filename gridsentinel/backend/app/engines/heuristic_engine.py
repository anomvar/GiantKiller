"""Heuristic engine: IsolationForest anomaly scoring, power-sector rules, verdict."""

from __future__ import annotations

import pickle
import random
import shutil
import tempfile
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest

from ..config import ML_MODEL_PATH
from .power_rules import evaluate_power_rules  # noqa: F401  (re-exported for the pipeline)

FEATURE_NAMES = [
    "file_size_log",
    "num_sections",
    "max_section_entropy",
    "num_imports",
    "num_suspicious_imports",
    "has_network_api",
    "has_registry_api",
    "has_process_injection_api",
    "num_high_entropy_sections",
    "string_count_urls",
    "string_count_ips",
    "string_count_registry",
    "string_count_suspicious_cmds",
    "has_self_signed_cert",
    "cert_validity_days",
    "packer_detected",
    "resource_entropy_avg",
    "num_exported_functions",
    "debug_info_present",
    "sandbox_score",
]

_model = None
_train_anomalies: np.ndarray = np.array([])


def _benign_base():
    return [
        14.0 + random.uniform(-1, 2),
        random.randint(3, 6),
        random.uniform(4.5, 6.2),
        random.randint(2, 9),
        random.randint(0, 1),
        0,
        0,
        0,
        0,
        random.randint(0, 1),
        0,
        random.randint(0, 1),
        0,
        0,
        random.randint(365, 3650),
        0,
        random.uniform(3.5, 5.5),
        random.randint(0, 12),
        random.choice([0, 1]),
        random.uniform(0.0, 0.1),
    ]


def _malicious_base():
    return [
        16.0 + random.uniform(-1, 2),
        random.randint(5, 9),
        random.uniform(6.4, 7.9),
        random.randint(8, 25),
        random.randint(3, 8),
        random.randint(0, 1),
        random.randint(0, 1),
        random.randint(0, 1),
        random.randint(1, 4),
        random.randint(2, 12),
        random.randint(1, 6),
        random.randint(2, 9),
        random.randint(1, 8),
        1,
        0,
        random.choice([0, 1]),
        random.uniform(6.0, 7.8),
        random.randint(0, 4),
        0,
        random.uniform(0.4, 1.0),
    ]


def _generate_training_set(n_benign: int = 50, n_malicious: int = 50) -> tuple[np.ndarray, np.ndarray]:
    random.seed(1337)
    benign = np.array([_benign_base() for _ in range(n_benign)])
    malicious = np.array([_malicious_base() for _ in range(n_malicious)])
    X = np.vstack([benign, malicious])
    y = np.concatenate([np.zeros(n_benign), np.ones(n_malicious)])
    return X, y


def ensure_model() -> None:
    global _model, _train_anomalies
    if _model is not None:
        return

    if ML_MODEL_PATH.exists():
        try:
            with open(ML_MODEL_PATH, "rb") as fh:
                payload = pickle.load(fh)
            if isinstance(payload, dict) and "model" in payload and "anomalies" in payload:
                _model = payload["model"]
                _train_anomalies = np.asarray(payload["anomalies"], dtype=float)
                return
        except Exception:  # noqa: BLE001
            pass

    X, y = _generate_training_set()
    model = IsolationForest(contamination=0.1, random_state=42, n_estimators=200)
    model.fit(X)
    anomalies = -model.decision_function(X)

    with tempfile.NamedTemporaryFile("wb", delete=False, dir=ML_MODEL_PATH.parent, suffix=".pkl") as tmp:
        pickle.dump({"model": model, "anomalies": anomalies.tolist(), "feature_names": FEATURE_NAMES}, tmp)
        tmp_path = tmp.name
    shutil.move(tmp_path, ML_MODEL_PATH)

    _model = model
    _train_anomalies = anomalies


def _extract_features(static: dict, dynamic: dict) -> np.ndarray:
    summary = static.get("summary", {})
    flags = static.get("flags", {})
    strings = static.get("strings", {})
    basic = static.get("basic_info", {})
    cert = static.get("certificates", {})

    vector = [
        float(np.log1p(basic.get("size", 0))),
        float(summary.get("num_sections", 0)),
        float(summary.get("max_section_entropy", 0.0)),
        float(summary.get("num_imports", 0)),
        float(summary.get("num_suspicious_imports", len(static.get("suspicious_import_flags", [])))),
        float(1 if flags.get("network_api") else 0),
        float(1 if flags.get("registry_api") else 0),
        float(1 if flags.get("injection_api") else 0),
        float(summary.get("num_high_entropy_sections", 0)),
        float(len(strings.get("urls", []))),
        float(len(strings.get("ips", []))),
        float(len(strings.get("registry_keys", []))),
        float(len(strings.get("suspicious_cmds", []))),
        float(0 if cert.get("is_signed") else 1),
        float(cert.get("validity_days", 0)),
        float(1 if static.get("packer_detected") else 0),
        float(summary.get("resource_entropy_avg", 0.0)),
        float(summary.get("num_exported_functions", 0)),
        float(1 if summary.get("debug_info_present") else 0),
        float(dynamic.get("score", 0.0)),
    ]
    return np.asarray(vector, dtype=float)


def _percentile(anomaly: float) -> float:
    if _train_anomalies.size == 0:
        return 50.0
    pct = float(np.mean(anomaly >= _train_anomalies) * 100.0)
    return max(0.0, min(100.0, pct))


def run_heuristic(static: dict, dynamic: dict) -> dict:
    ensure_model()
    x = _extract_features(static, dynamic).reshape(1, -1)
    anomaly = float(-_model.decision_function(x)[0])
    percentile = _percentile(anomaly)

    boost = 0.0
    if static.get("flags", {}).get("network_api"):
        boost += 5
    if static.get("flags", {}).get("injection_api"):
        boost += 5
    if dynamic.get("activated"):
        boost += 10
    if dynamic.get("dns_queries_dga_like"):
        boost += 5
    percentile = max(0.0, min(100.0, percentile + boost))

    return {
        "anomaly_score": round(anomaly, 4),
        "risk_percentile": round(percentile, 1),
        "features": {name: round(float(v), 4) for name, v in zip(FEATURE_NAMES, x.tolist()[0])},
        "model": type(_model).__name__,
        "contamination": 0.1,
    }


def compute_final_verdict(
    static: dict, dynamic: dict, heuristic: dict, power_rules: dict, impact: dict
) -> tuple[int, dict, str]:
    static_score = static.get("score", 0)

    if dynamic.get("activated"):
        dynamic_score = min(100.0, 55.0 + 7.0 * len(dynamic.get("behaviors", [])))
    else:
        dynamic_score = 10.0

    heuristic_score = heuristic.get("risk_percentile", 50.0)

    sev = power_rules.get("severity", "NONE")
    if sev == "CRITICAL":
        power_score = 100.0
    elif sev == "HIGH":
        power_score = 75.0
    elif sev == "MEDIUM":
        power_score = 55.0
    else:
        power_score = 5.0

    weights = {"static": 0.30, "dynamic": 0.25, "heuristic": 0.25, "power_rules": 0.20}
    risk = round(
        weights["static"] * static_score
        + weights["dynamic"] * dynamic_score
        + weights["heuristic"] * heuristic_score
        + weights["power_rules"] * power_score
    )
    risk = max(0, min(100, risk))

    if power_rules.get("critical", 0) > 0 or risk >= 70:
        verdict = "MALICIOUS"
    elif power_rules.get("high", 0) > 0 or risk >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return risk, {
        "static": int(static_score),
        "dynamic": int(dynamic_score),
        "heuristic": int(heuristic_score),
        "power_rules": int(power_score),
    }, verdict
