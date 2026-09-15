import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (UniqueConstraint("fingerprint", name="uq_alerts_fingerprint"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    external_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    source: Mapped[str] = mapped_column(String, nullable=False, default="wazuh")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    agent_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    agent_name: Mapped[str | None] = mapped_column(String, nullable=True)

    rule_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    rule_level: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rule_description: Mapped[str | None] = mapped_column(String, nullable=True)

    mitre_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    groups: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    src_ip: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    dst_ip: Mapped[str | None] = mapped_column(String, nullable=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)

    username: Mapped[str | None] = mapped_column(String, nullable=True, index=True)

    process_name: Mapped[str | None] = mapped_column(String, nullable=True)
    process_command_line: Mapped[str | None] = mapped_column(String, nullable=True)

    file_path: Mapped[str | None] = mapped_column(String, nullable=True)
    file_hash: Mapped[str | None] = mapped_column(String, nullable=True, index=True)

    raw_event: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    fingerprint: Mapped[str] = mapped_column(String, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String, nullable=False, default="received")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
