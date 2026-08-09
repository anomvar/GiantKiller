from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, Integer, String, Text
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.types import JSON

from .database import Base


def gen_id() -> str:
    return str(uuid4())


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True, default=gen_id)
    filename = Column(String, nullable=False)
    file_path = Column(String, nullable=False)
    file_hash_sha256 = Column(String, default="")
    upload_time = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="pending")
    verdict = Column(String, default="PENDING")
    risk_score = Column(Integer, default=0)
    risk_breakdown = Column(JSON, default=dict)
    static_results = Column(MutableDict.as_mutable(JSON), default=dict)
    dynamic_results = Column(MutableDict.as_mutable(JSON), default=dict)
    heuristic_results = Column(MutableDict.as_mutable(JSON), default=dict)
    power_rules = Column(MutableDict.as_mutable(JSON), default=dict)
    grid_impact = Column(MutableDict.as_mutable(JSON), default=dict)
    prosecutor_report = Column(Text, default="")
    error = Column(Text, default="")
    completed_at = Column(DateTime, nullable=True)

    def to_summary(self) -> dict:
        return {
            "scan_id": self.id,
            "filename": self.filename,
            "sha256": self.file_hash_sha256,
            "status": self.status,
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "risk_breakdown": self.risk_breakdown or {},
            "upload_time": self.upload_time.isoformat() if self.upload_time else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }

    def to_full_report(self) -> dict:
        return {
            **self.to_summary(),
            "static": self.static_results or {},
            "dynamic": self.dynamic_results or {},
            "heuristic": self.heuristic_results or {},
            "power_rules": self.power_rules or {},
            "grid_impact": self.grid_impact or {},
            "prosecutor_report": self.prosecutor_report or "",
            "error": self.error or "",
        }
