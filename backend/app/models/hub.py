"""Persistent canonical evidence and entity relationships for the intelligence hub."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, JSON, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class HubEntity(Base):
    __tablename__ = "hub_entities"
    __table_args__ = (UniqueConstraint("kind", "external_key", name="uq_hub_entity_key"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    external_key: Mapped[str] = mapped_column(String(512), nullable=False)
    label: Mapped[str] = mapped_column(String(512), nullable=False)
    attributes: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    source: Mapped[str] = mapped_column(String(128), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class HubRelationship(Base):
    __tablename__ = "hub_relationships"
    __table_args__ = (
        UniqueConstraint("source_id", "target_id", "relation", "source_ref", name="uq_hub_relationship_evidence"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("hub_entities.id", ondelete="CASCADE"), index=True)
    target_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("hub_entities.id", ondelete="CASCADE"), index=True)
    relation: Mapped[str] = mapped_column(String(64), nullable=False)
    source_ref: Mapped[str] = mapped_column(String(512), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    attributes: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class HubEvidence(Base):
    __tablename__ = "hub_evidence"
    __table_args__ = (UniqueConstraint("source", "external_id", name="uq_hub_evidence_source"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="SET NULL"), index=True)
    source: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    external_id: Mapped[str] = mapped_column(String(512), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    host_key: Mapped[str | None] = mapped_column(String(512), index=True)
    identity_key: Mapped[str | None] = mapped_column(String(512), index=True)
    normalized: Mapped[dict] = mapped_column(JSON, nullable=False)
    attributes: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
