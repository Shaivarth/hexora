import json

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, Request, Response 
import secrets
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import Scan
from app.schemas import ScanDetail
from app.services import metadata_extractor, mime_detect, risk_engine, strings_scan
from app.services.file_ingest import UploadTooLarge, ingest_to_disk
from app.utils.security import build_storage_name, safe_extension, sanitize_filename

router = APIRouter(prefix="/api/scans", tags=["scans"])


def _to_detail_dict(scan: Scan) -> dict:
    return {
        "id": scan.id,
        "original_filename": scan.original_filename,
        "file_extension": scan.file_extension,
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
        "uploaded_at": scan.uploaded_at,
    }


@router.post("", response_model=ScanDetail)
async def upload_and_scan(
    request: Request,
    response: Response,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    if not file.filename:
        raise HTTPException(400, "A filename is required.")

    session_id = request.cookies.get("hexora_session")

    if not session_id:
        session_id = secrets.token_hex(32)
        response.set_cookie(
            key="hexora_session",
            value=session_id,
            httponly=True,
            samesite="lax",
            max_age=60 * 60 * 24 * 365,  # 1 year
        )

    display_name = sanitize_filename(file.filename)
    extension = safe_extension(file.filename)
    storage_name = build_storage_name(extension)
    dest_path = settings.UPLOAD_DIR / storage_name

    try:
        ingest = ingest_to_disk(file.file, dest_path, settings.MAX_UPLOAD_SIZE_BYTES)
    except UploadTooLarge:
        raise HTTPException(
            413,
            f"File exceeds the {settings.MAX_UPLOAD_SIZE_MB} MB upload limit.",
        )

    if ingest.size == 0:
        dest_path.unlink(missing_ok=True)
        raise HTTPException(400, "Uploaded file is empty.")

    detection = mime_detect.detect(ingest.header, dest_path, file.filename)
    string_findings = strings_scan.scan_strings(dest_path)
    metadata = metadata_extractor.extract(
        dest_path, detection["category"], detection["mime_type"], ingest.header
    )
    metadata["strings"] = {
        "suspicious_matches": string_findings["matches"],
        "urls_found": string_findings["urls"],
        "ips_found": string_findings["ips"],
        "sample_strings": string_findings["sample_strings"],
        "scan_truncated": string_findings["truncated"],
    }

    assessment = risk_engine.assess(
        original_filename=file.filename,
        claimed_extension=detection["claimed_extension"],
        category=detection["category"],
        mime_type=detection["mime_type"],
        file_size=ingest.size,
        entropy=ingest.entropy,
        extension_mismatch=detection["extension_mismatch"],
        metadata=metadata,
        string_findings=string_findings,
    )

    scan = Scan(
        session_id=session_id,
        original_filename=display_name,
        stored_filename=storage_name,
        file_extension=extension,
        sha256=ingest.sha256,
        sha1=ingest.sha1,
        md5=ingest.md5,
        file_size=ingest.size,
        mime_type=detection["mime_type"],
        category=detection["category"],
        entropy=ingest.entropy,
        risk_score=assessment["score"],
        risk_level=assessment["level"],
        risk_reasons_json=json.dumps(assessment["reasons"]),
        recommendations_json=json.dumps(assessment["recommendations"]),
        metadata_json=json.dumps(metadata),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    return _to_detail_dict(scan)


@router.get("/{scan_id}", response_model=ScanDetail)
def get_scan(
    scan_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    session_id = request.cookies.get("hexora_session")

    scan = (
        db.query(Scan)
        .filter(
            Scan.id == scan_id,
            Scan.session_id == session_id,
        )
        .first()
    )

    if not scan:
        raise HTTPException(404, "Scan not found.")

    return _to_detail_dict(scan)
