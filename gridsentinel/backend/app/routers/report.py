from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Scan

router = APIRouter(tags=["report"])


def _get_scan(db: Session, scan_id: str) -> Scan:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan


@router.get("/scan/{scan_id}/report")
def get_report(scan_id: str, db: Session = Depends(get_db)):
    scan = _get_scan(db, scan_id)
    return scan.to_full_report()


@router.get("/scan/{scan_id}/autopsy")
def get_autopsy(scan_id: str, db: Session = Depends(get_db)):
    scan = _get_scan(db, scan_id)
    static = scan.static_results or {}
    if not static:
        raise HTTPException(status_code=409, detail="Static analysis not completed yet.")
    from ..engines.static_engine import build_autopsy_graph
    return build_autopsy_graph(static)


@router.get("/scan/{scan_id}/grid-impact")
def get_grid_impact(scan_id: str, db: Session = Depends(get_db)):
    scan = _get_scan(db, scan_id)
    impact = scan.grid_impact or {}
    if not impact:
        raise HTTPException(status_code=409, detail="Grid impact simulation not completed yet.")
    return impact
