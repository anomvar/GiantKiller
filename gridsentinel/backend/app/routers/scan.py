from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..engines import grid_impact, heuristic_engine, sandbox_engine, static_engine
from ..models import Scan
from ..utils.prosecutor_nlg import generate_prosecutor_report

router = APIRouter(tags=["scan"])


def _update_status(db: Session, scan_id: str, status: str):
    scan = db.get(Scan, scan_id)
    if scan:
        scan.status = status
        db.commit()


def run_pipeline(scan_id: str):
    db = next(get_db())
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            return

        try:
            _update_status(db, scan_id, "static")
            static = static_engine.run_static_scan(scan.file_path)
            static["_graph"] = static_engine.build_autopsy_graph(static)
            scan.static_results = static
            db.commit()

            _update_status(db, scan_id, "sandbox")
            dynamic = sandbox_engine.run_sandbox(scan.file_path, static)
            scan.dynamic_results = dynamic
            db.commit()

            _update_status(db, scan_id, "heuristic")
            heuristic = heuristic_engine.run_heuristic(static, dynamic)
            scan.heuristic_results = heuristic
            power_rules = heuristic_engine.evaluate_power_rules(static, dynamic)
            scan.power_rules = power_rules
            db.commit()

            _update_status(db, scan_id, "grid_impact")
            impact = grid_impact.run_impact(static, dynamic, power_rules)
            scan.grid_impact = impact
            db.commit()

            risk_score, risk_breakdown, verdict = heuristic_engine.compute_final_verdict(
                static, dynamic, heuristic, power_rules, impact
            )
            scan.risk_score = risk_score
            scan.risk_breakdown = risk_breakdown
            scan.verdict = verdict

            report_text = generate_prosecutor_report(
                static=static,
                dynamic=dynamic,
                heuristic=heuristic,
                power_rules=power_rules,
                impact=impact,
                verdict=verdict,
                risk_score=risk_score,
            )
            scan.prosecutor_report = report_text

            scan.status = "complete"
            scan.completed_at = datetime.utcnow()
            db.commit()
        except Exception as exc:  # noqa: BLE001
            scan.status = "error"
            scan.error = f"{type(exc).__name__}: {exc}"
            db.commit()
    finally:
        db.close()


@router.post("/scan/{scan_id}", status_code=202)
def trigger_scan(scan_id: str, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    if scan.status in ("processing", "complete"):
        return {"scan_id": scan_id, "status": scan.status, "message": "Scan already running or finished."}
    scan.status = "processing"
    db.commit()
    background_tasks.add_task(run_pipeline, scan_id)
    return {"scan_id": scan_id, "status": "processing", "message": "Scan pipeline started."}


@router.get("/scan/{scan_id}/status")
def get_status(scan_id: str, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return {
        "scan_id": scan_id,
        "filename": scan.filename,
        "status": scan.status,
        "verdict": scan.verdict,
        "risk_score": scan.risk_score,
        "stages": ["static", "sandbox", "heuristic", "grid_impact"],
        "current_stage": None if scan.status in ("pending", "processing", "complete", "error") else scan.status,
        "error": scan.error or None,
    }
