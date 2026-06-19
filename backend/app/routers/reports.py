import io
import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Scan
from app.services.pdf_report import build_report

router = APIRouter(prefix="/api/scans", tags=["reports"])


@router.get("/{scan_id}/report")
def download_report(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found.")

    payload = {
        "original_filename": scan.original_filename,
        "sha256": scan.sha256,
        "sha1": scan.sha1,
        "md5": scan.md5,
        "file_size": scan.file_size,
        "mime_type": scan.mime_type,
        "category": scan.category,
        "entropy": scan.entropy,
        "risk_score": scan.risk_score,
        "risk_level": scan.risk_level,
        "risk_reasons": json.loads(scan.risk_reasons_json or "[]"),
        "recommendations": json.loads(scan.recommendations_json or "[]"),
        "metadata": json.loads(scan.metadata_json or "{}"),
        "uploaded_at": scan.uploaded_at.strftime("%Y-%m-%d %H:%M UTC") if scan.uploaded_at else "",
    }

    pdf_bytes = build_report(payload)
    filename = f"Hexora_report_{scan.sha256[:12]}.pdf"

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
