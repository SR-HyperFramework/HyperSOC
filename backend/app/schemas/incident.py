from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

IncidentStatus = Literal["NEW", "TRIAGED", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"]
IncidentSeverity = Literal["low", "medium", "high", "critical"]


class _IncidentSchema(BaseModel):
    model_config = {"extra": "ignore"}


class IncidentOut(_IncidentSchema):
    id: UUID
    title: str
    status: IncidentStatus
    severity: IncidentSeverity
    confidence: int = Field(ge=0, le=100)
    first_seen: datetime
    last_seen: datetime
    primary_host: str | None
    primary_user: str | None
    primary_src_ip: str | None
    mitre_ids: list[str]
    alert_count: int = Field(ge=0)
    ai_summary: str | None
    ai_analysis: str | None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    model_config = {"from_attributes": True}


class IncidentDetailOut(IncidentOut):
    alert_ids: list[UUID] = Field(default_factory=list)


class CorrelationRunRequest(_IncidentSchema):
    lookback_minutes: int = Field(default=60, ge=1, le=10_080)
    window_minutes: int = Field(default=10, ge=1, le=1_440)
    min_alerts: int = Field(default=2, ge=2, le=100)
    refresh_threat_intel: bool = False


class CorrelationRunOut(_IncidentSchema):
    created_count: int = Field(default=0, ge=0)
    updated_count: int = Field(default=0, ge=0)
    incidents: list[IncidentDetailOut] = Field(default_factory=list)
