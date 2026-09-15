from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field

IndicatorType = Literal["ip", "domain", "hash", "url"]
Verdict = Literal["unknown", "benign", "suspicious", "malicious"]


class _ThreatIntelSchema(BaseModel):
    model_config = {"extra": "ignore"}


class ThreatIntelProviderResult(_ThreatIntelSchema):
    provider: str
    verdict: Verdict = "unknown"
    risk_score: int = Field(default=0, ge=0, le=100)
    confidence: int | None = Field(default=None, ge=0, le=100)
    summary: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class ThreatIntelResultOut(_ThreatIntelSchema):
    indicator: str
    type: IndicatorType
    providers: dict[str, ThreatIntelProviderResult] = Field(default_factory=dict)
    risk_score: int = Field(default=0, ge=0, le=100)
    verdict: Verdict = "unknown"
    cached: bool = False
    cached_until: datetime | None = None
    last_lookup_at: datetime | None = None


class AlertThreatIntelItemOut(ThreatIntelResultOut):
    evidence_path: str


class AlertThreatIntelOut(_ThreatIntelSchema):
    alert_id: UUID
    indicators: list[AlertThreatIntelItemOut] = Field(default_factory=list)
    max_risk_score: int = Field(default=0, ge=0, le=100)
    verdict: Verdict = "unknown"
