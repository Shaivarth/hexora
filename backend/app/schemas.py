from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict


class ScanSummary(BaseModel):
    """Lightweight representation used in lists / tables."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    original_filename: str
    file_extension: str
    sha256: str
    file_size: int
    mime_type: str
    category: str
    risk_score: int
    risk_level: str
    uploaded_at: datetime


class ScanDetail(ScanSummary):
    """Full representation used on the scan result page."""
    model_config = ConfigDict(from_attributes=True)

    sha1: str
    md5: str
    entropy: float
    risk_reasons: List[Dict[str, Any]] = []
    recommendations: List[str] = []
    metadata: Dict[str, Any] = {}


class PaginatedScans(BaseModel):
    items: List[ScanSummary]
    total: int
    page: int
    page_size: int
    total_pages: int


class DashboardStats(BaseModel):
    total_scans: int
    high_risk_count: int
    critical_risk_count: int
    average_risk_score: float
    category_distribution: Dict[str, int]
    risk_distribution: Dict[str, int]
    recent_scans: List[ScanSummary]
    scans_last_7_days: Dict[str, int]
