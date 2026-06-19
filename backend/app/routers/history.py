from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import Scan
from app.schemas import PaginatedScans

router = APIRouter(prefix="/api/scans", tags=["history"])

SORTABLE_FIELDS = {
    "uploaded_at": Scan.uploaded_at,
    "risk_score": Scan.risk_score,
    "file_size": Scan.file_size,
    "original_filename": Scan.original_filename,
}


@router.get("", response_model=PaginatedScans)
def list_scans(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    page_size: int = Query(settings.DEFAULT_PAGE_SIZE, ge=1, le=settings.MAX_PAGE_SIZE),
    search: Optional[str] = Query(None, description="Matches filename or any hash"),
    risk_level: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None, description="ISO date, inclusive"),
    date_to: Optional[str] = Query(None, description="ISO date, inclusive"),
    sort_by: str = Query("uploaded_at"),
    sort_dir: str = Query("desc", pattern="^(asc|desc)$"),
):
    query = db.query(Scan)

    if search:
        s = f"%{search.strip()}%"
        query = query.filter(
            or_(
                Scan.original_filename.ilike(s),
                Scan.sha256.ilike(s),
                Scan.sha1.ilike(s),
                Scan.md5.ilike(s),
            )
        )

    if risk_level and risk_level.lower() != "all":
        query = query.filter(Scan.risk_level == risk_level)

    if category and category.lower() != "all":
        query = query.filter(Scan.category == category)

    if date_from:
        try:
            query = query.filter(Scan.uploaded_at >= datetime.fromisoformat(date_from))
        except ValueError:
            pass

    if date_to:
        try:
            end = datetime.fromisoformat(date_to) + timedelta(days=1)
            query = query.filter(Scan.uploaded_at < end)
        except ValueError:
            pass

    total = query.count()

    sort_col = SORTABLE_FIELDS.get(sort_by, Scan.uploaded_at)
    sort_col = sort_col.desc() if sort_dir == "desc" else sort_col.asc()
    query = query.order_by(sort_col)

    items = query.offset((page - 1) * page_size).limit(page_size).all()
    total_pages = max(1, (total + page_size - 1) // page_size)

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
    }
