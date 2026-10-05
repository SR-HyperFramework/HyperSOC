import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, JSON, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class BehaviorModel(Base):
    __tablename__ = "behavior_models"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    algorithm: Mapped[str] = mapped_column(String(64), nullable=False)
    host_key: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    sample_count: Mapped[int] = mapped_column(Integer, nullable=False)
    trained_since: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    trained_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    corpus_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    parameters: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
