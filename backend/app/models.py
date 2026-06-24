import uuid

from sqlalchemy import Column, DateTime, Float, Integer, String, Text
from sqlalchemy.sql import func

from app.database import Base


def gen_uuid() -> str:
    return uuid.uuid4().hex


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(32), primary_key=True, default=gen_uuid)
    session_id = Column(String(64), index=True, nullable=False, default="")

    # Identity
    original_filename = Column(String(512), nullable=False)
    stored_filename = Column(String(255), nullable=False)
    file_extension = Column(String(32), default="")

    # Hashes
    sha256 = Column(String(64), index=True, nullable=False)
    sha1 = Column(String(40), index=True, nullable=False)
    md5 = Column(String(32), index=True, nullable=False)

    # Basic properties
    file_size = Column(Integer, nullable=False)
    mime_type = Column(String(128), default="application/octet-stream")
    category = Column(String(32), default="other", index=True)
    entropy = Column(Float, default=0.0)

    # Risk
    risk_score = Column(Integer, default=0, index=True)
    risk_level = Column(String(16), default="Low", index=True)
    risk_reasons_json = Column(Text, default="[]")
    recommendations_json = Column(Text, default="[]")

    # Free-form extracted metadata (JSON-encoded dict)
    metadata_json = Column(Text, default="{}")

    # Timestamps
    uploaded_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
