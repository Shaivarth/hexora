from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Scan
from app.schemas import DashboardStats

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

RISK_LEVELS = ["Low", "Medium", "High", "Critical"]
CATEGORIES = ["executable", "document", "archive", "image", "script", "other"]


@router.get("/stats", response_model=DashboardStats)
def get_stats(
    request: Request,
    db: Session = Depends(get_db),
):
    session_id = request.cookies.get("hexora_session")

    if not session_id:
        return {
            "total_scans": 0,
            "high_risk_count": 0,
            "critical_risk_count": 0,
            "average_risk_score": 0,
            "category_distribution": {c: 0 for c in CATEGORIES},
            "risk_distribution": {lvl: 0 for lvl in RISK_LEVELS},
            "recent_scans": [],
            "scans_last_7_days": {},
        }

    base_query = db.query(Scan).filter(Scan.session_id == session_id)

    total_scans = base_query.count()
    high_risk_count = base_query.filter(Scan.risk_level == "High").count()
    critical_risk_count = base_query.filter(Scan.risk_level == "Critical").count()
    avg_score = base_query.with_entities(func.avg(Scan.risk_score)).scalar() or 0.0

    category_rows = (
        base_query.with_entities(Scan.category, func.count(Scan.id)).group_by(Scan.category).all()
    )
    category_distribution = {c: 0 for c in CATEGORIES}
    for cat, count in category_rows:
        category_distribution[cat or "other"] = count

    risk_rows = (base_query.with_entities(Scan.risk_level, func.count(Scan.id)).group_by(Scan.risk_level).all())
    risk_distribution = {lvl: 0 for lvl in RISK_LEVELS}
    for lvl, count in risk_rows:
        if lvl in risk_distribution:
            risk_distribution[lvl] = count

    recent = (base_query.order_by(Scan.uploaded_at.desc()).limit(8).all())

    # Last 7 days, bucketed by upload date.
    since = datetime.now(timezone.utc) - timedelta(days=6)
    daily_rows = (base_query.with_entities(Scan.uploaded_at).filter(Scan.uploaded_at >= since.replace(tzinfo=None)).all())
    buckets = defaultdict(int)
    for i in range(7):
        day = (since + timedelta(days=i)).strftime("%Y-%m-%d")
        buckets[day] = 0
    for (uploaded_at,) in daily_rows:
        if uploaded_at:
            key = uploaded_at.strftime("%Y-%m-%d")
            if key in buckets:
                buckets[key] += 1

    return {
        "total_scans": total_scans,
        "high_risk_count": high_risk_count,
        "critical_risk_count": critical_risk_count,
        "average_risk_score": round(float(avg_score), 1),
        "category_distribution": category_distribution,
        "risk_distribution": risk_distribution,
        "recent_scans": recent,
        "scans_last_7_days": dict(buckets),
    }
