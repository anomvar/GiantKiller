from fastapi import APIRouter, HTTPException, UploadFile, File

from ..config import ALLOWED_EXTENSIONS, MAX_UPLOAD_SIZE, UPLOAD_DIR
from ..database import get_db
from ..models import Scan, gen_id
from ..utils.hasher import hash_file

router = APIRouter(tags=["upload"])


@router.post("/upload", status_code=201)
async def upload_sample(file: UploadFile = File(...)):
    original_name = file.filename or "unknown.bin"
    ext = (".%s" % original_name.rsplit(".", 1)[-1]).lower() if "." in original_name else ""

    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported format '{ext or 'no extension'}'. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
        )

    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="Empty file uploaded.")
    if len(data) > MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=413, detail="File exceeds maximum allowed size.")

    hashes = hash_file(data)
    if hashes.get("magic") == "UNSUPPORTED":
        raise HTTPException(status_code=415, detail="Unsupported format: not a PE or ELF binary.")

    scan_id = gen_id()
    scan_dir = UPLOAD_DIR / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    saved_path = scan_dir / original_name
    saved_path.write_bytes(data)

    db = next(get_db())
    try:
        scan = Scan(
            id=scan_id,
            filename=original_name,
            file_path=str(saved_path),
            file_hash_sha256=hashes["sha256"],
            status="pending",
        )
        db.add(scan)
        db.commit()
    finally:
        db.close()

    return {
        "scan_id": scan_id,
        "filename": original_name,
        "sha256": hashes["sha256"],
        "md5": hashes["md5"],
        "size": len(data),
        "message": "Upload accepted. Scan pipeline ready.",
    }
