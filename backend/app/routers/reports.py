import io
import json
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Scan
from app.services.pdf_report import build_report

router = APIRouter(prefix="/api/scans", tags=["reports"])

IST = timezone(timedelta(hours=5, minutes=30))


@router.get("/{scan_id}/report")
def download_report(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found.")

    uploaded_str = ""
    if scan.uploaded_at:
        dt = scan.uploaded_at
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        ist_dt = dt.astimezone(IST)
        uploaded_str = ist_dt.strftime("%d %b %Y, %I:%M %p IST")

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
        "uploaded_at": uploaded_str,
    }

    try:
        pdf_bytes = build_report(payload)
    except Exception as e:
        raise HTTPException(500, f"Error building PDF report: {str(e)}")

    filename = f"Hexora_report_{scan.sha256[:12]}.pdf"

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
