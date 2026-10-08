import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, JSON, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Investigation(Base):
    __tablename__ = "investigations"
    __table_args__ = (
        CheckConstraint("status IN ('PENDING_REVIEW', 'CONFIRMED', 'CORRECTED')", name="ck_investigations_status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider_mode: Mapped[str] = mapped_column(String(20), nullable=False)
    model_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    workflow_key: Mapped[str | None] = mapped_column(String(100), nullable=True, unique=True)
    # Material incident facts the report was generated from; see incident_signature().
    incident_signature: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="PENDING_REVIEW", index=True)
    plan: Mapped[dict] = mapped_column(JSON, nullable=False)
    evidence: Mapped[list] = mapped_column(JSON, nullable=False)
    report: Mapped[dict] = mapped_column(JSON, nullable=False)
    reviewed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    final_classification: Mapped[str | None] = mapped_column(String(32), nullable=True)
    reviewer_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
