import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Integer, JSON, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class ResponseAction(Base):
    __tablename__ = "response_actions"
    __table_args__ = (
        CheckConstraint("type IN ('BLOCK_IP', 'DISABLE_USER', 'KILL_PROCESS', 'QUARANTINE_FILE')", name="ck_response_actions_type"),
        CheckConstraint("risk IN ('low', 'medium', 'high')", name="ck_response_actions_risk"),
        CheckConstraint("status IN ('PENDING', 'APPROVED', 'EXECUTING', 'SUCCESS', 'FAILED', 'REJECTED')", name="ck_response_actions_status"),
        CheckConstraint("duration_minutes IS NULL OR duration_minutes > 0", name="ck_response_actions_duration_positive"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )

    type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    target: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    risk: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING", index=True)
    requested_by: Mapped[str] = mapped_column(String(64), nullable=False, default="AI")

    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rejected_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    rejected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    duration_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    policy_result: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    execution_result: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
