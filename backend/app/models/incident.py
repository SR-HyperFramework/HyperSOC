import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint(
            "status IN ('NEW', 'TRIAGED', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE')",
            name="ck_incidents_status",
        ),
        CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'critical')",
            name="ck_incidents_severity",
        ),
        CheckConstraint("confidence >= 0 AND confidence <= 100", name="ck_incidents_confidence"),
        CheckConstraint("alert_count >= 0", name="ck_incidents_alert_count"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="NEW", index=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="medium", index=True)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    primary_host: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    primary_user: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    primary_src_ip: Mapped[str | None] = mapped_column(String, nullable=True, index=True)

    mitre_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    alert_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    ai_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_analysis: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class IncidentAlert(Base):
    __tablename__ = "incident_alerts"
    __table_args__ = (UniqueConstraint("incident_id", "alert_id", name="uq_incident_alerts_incident_alert"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    alert_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
