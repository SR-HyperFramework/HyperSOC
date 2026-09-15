import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Integer, JSON, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class ThreatIntelIndicator(Base):
    __tablename__ = "threat_intel_indicators"
    __table_args__ = (
        UniqueConstraint("indicator_type", "indicator", name="uq_threat_intel_indicators_type_value"),
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="ck_threat_intel_indicators_risk_score"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    indicator_type: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    indicator: Mapped[str] = mapped_column(String(2048), nullable=False, index=True)
    providers: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    verdict: Mapped[str] = mapped_column(String(20), nullable=False, default="unknown")
    cached_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    last_lookup_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class AlertThreatIntel(Base):
    __tablename__ = "alert_threat_intel"
    __table_args__ = (
        UniqueConstraint("alert_id", "threat_intel_indicator_id", "evidence_path", name="uq_alert_threat_intel_path"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    threat_intel_indicator_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("threat_intel_indicators.id", ondelete="CASCADE"), nullable=False, index=True
    )
    evidence_path: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
