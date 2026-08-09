import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = BASE_DIR / "uploads"
DB_PATH = BASE_DIR / "scan_results.db"
ML_MODEL_PATH = Path(__file__).resolve().parent / "ml_model" / "anomaly_model.pkl"

ALLOWED_EXTENSIONS = {".exe", ".dll", ".msi", ".elf", ".zip", ".bin", ".scr", ".cpl"}
MAX_UPLOAD_SIZE = int(os.environ.get("GRIDSENTINEL_MAX_UPLOAD", 50 * 1024 * 1024))

SANDBOX_IMAGE = os.environ.get("GRIDSENTINEL_SANDBOX_IMAGE", "gridsentinel-sandbox:latest")
SANDBOX_TIMEOUT = int(os.environ.get("GRIDSENTINEL_SANDBOX_TIMEOUT", "30"))
DOCKER_ENABLED = os.environ.get("GRIDSENTINEL_DOCKER_ENABLED", "false").lower() == "true"

CORS_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]

PIPELINE_STAGES = ["static", "sandbox", "heuristic", "grid_impact"]
