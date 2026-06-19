from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Scan
from app.schemas import DashboardStats

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

RISK_LEVELS = ["Low", "Medium", "High", "Critical"]
CATEGORIES = ["executable", "document", "archive", "image", "script", "other"]


@router.get("/stats", response_model=DashboardStats)
def get_stats(db: Session = Depends(get_db)):
    total_scans = db.query(func.count(Scan.id)).scalar() or 0
    high_risk_count = db.query(func.count(Scan.id)).filter(Scan.risk_level == "High").scalar() or 0
    critical_risk_count = db.query(func.count(Scan.id)).filter(Scan.risk_level == "Critical").scalar() or 0
    avg_score = db.query(func.avg(Scan.risk_score)).scalar() or 0.0

    category_rows = db.query(Scan.category, func.count(Scan.id)).group_by(Scan.category).all()
    category_distribution = {c: 0 for c in CATEGORIES}
    for cat, count in category_rows:
        category_distribution[cat or "other"] = count

    risk_rows = db.query(Scan.risk_level, func.count(Scan.id)).group_by(Scan.risk_level).all()
    risk_distribution = {lvl: 0 for lvl in RISK_LEVELS}
    for lvl, count in risk_rows:
        if lvl in risk_distribution:
            risk_distribution[lvl] = count

    recent = db.query(Scan).order_by(Scan.uploaded_at.desc()).limit(8).all()

    # Last 7 days, bucketed by date (UTC).
    since = datetime.now(timezone.utc) - timedelta(days=6)
    daily_rows = (
        db.query(Scan.uploaded_at)
        .filter(Scan.uploaded_at >= since.replace(tzinfo=None))
        .all()
    )
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
