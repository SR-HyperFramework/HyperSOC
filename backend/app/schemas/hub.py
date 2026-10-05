from datetime import datetime, timezone
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator

from app.schemas.normalized_alert import NormalizedAlert

EntityKind = Literal["asset", "identity", "ip", "domain", "hash", "process", "file", "technique"]
EvidenceCategory = Literal["detection", "behavior", "posture"]


class HubEntityWrite(BaseModel):
    model_config = {"extra": "forbid"}
    kind: EntityKind
    external_key: str = Field(min_length=1, max_length=512)
    label: str = Field(min_length=1, max_length=512)
    attributes: dict[str, Any] = Field(default_factory=dict)
    source: str = Field(min_length=1, max_length=128)
    observed_at: datetime

    @field_validator("external_key", "label", "source")
    @classmethod
    def nonblank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("value cannot be blank")
        return value.strip()

    @field_validator("observed_at")
    @classmethod
    def aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("observed_at must include a timezone")
        return value


class HubEntityOut(HubEntityWrite):
    model_config = {"from_attributes": True}
    id: UUID

    @field_validator("observed_at")
    @classmethod
    def aware(cls, value: datetime) -> datetime:
        # SQLite test storage loses timezone metadata; database timestamps are UTC.
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


class HubRelationshipWrite(BaseModel):
    model_config = {"extra": "forbid"}
    source_id: UUID
    target_id: UUID
    relation: str = Field(min_length=1, max_length=64, pattern=r"^[a-z_]+$")
    source_ref: str = Field(min_length=1, max_length=512)
    observed_at: datetime
    confidence: float = Field(default=1.0, ge=0, le=1)
    attributes: dict[str, Any] = Field(default_factory=dict)


class HubRelationshipOut(HubRelationshipWrite):
    model_config = {"from_attributes": True}
    id: UUID


class InventoryRelationship(BaseModel):
    model_config = {"extra": "forbid"}
    source_kind: EntityKind
    source_key: str = Field(min_length=1, max_length=512)
    target_kind: EntityKind
    target_key: str = Field(min_length=1, max_length=512)
    relation: str = Field(min_length=1, max_length=64, pattern=r"^[a-z_]+$")
    source_ref: str = Field(min_length=1, max_length=512)
    observed_at: datetime
    confidence: float = Field(default=1.0, ge=0, le=1)
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("observed_at")
    @classmethod
    def aware(cls, value):
        if value.tzinfo is None:
            raise ValueError("observed_at must include a timezone")
        return value


class HubInventoryBatch(BaseModel):
    model_config = {"extra": "forbid"}
    entities: list[HubEntityWrite] = Field(default_factory=list, max_length=200)
    relationships: list[InventoryRelationship] = Field(default_factory=list, max_length=200)


class HubEventIn(BaseModel):
    """Versioned connector contract: source adapters supply canonical evidence."""
    model_config = {"extra": "forbid"}
    schema_version: Literal["1.0"] = "1.0"
    source: str = Field(min_length=1, max_length=128)
    external_id: str = Field(min_length=1, max_length=512)
    category: EvidenceCategory = "detection"
    alert: NormalizedAlert
    attributes: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def timezone_required(self):
        if self.alert.timestamp.tzinfo is None:
            raise ValueError("alert.timestamp must include a timezone")
        if not self.source.strip() or not self.external_id.strip():
            raise ValueError("source and external_id cannot be blank")
        self.alert.detection.source = self.source
        return self


class HubSearch(BaseModel):
    model_config = {"extra": "forbid"}
    host: str | None = Field(default=None, max_length=512)
    identity: str | None = Field(default=None, max_length=512)
    source: str | None = Field(default=None, max_length=128)
    category: EvidenceCategory | None = None
    since: datetime
    until: datetime
    limit: int = Field(default=50, ge=1, le=200)

    @model_validator(mode="after")
    def bounded_window(self):
        if self.since.tzinfo is None or self.until.tzinfo is None:
            raise ValueError("search timestamps must include a timezone")
        delta = self.until - self.since
        if delta.total_seconds() < 0 or delta.days > 90:
            raise ValueError("search window must be between zero and 90 days")
        return self


class HubGraph(BaseModel):
    nodes: list[HubEntityOut] = Field(default_factory=list)
    edges: list[HubRelationshipOut] = Field(default_factory=list)
    truncated: bool = False


class HubContext(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    incident_id: UUID | None
    alert_id: UUID | None = None
    collected_at: datetime
    assets: list[HubEntityOut] = Field(default_factory=list)
    identities: list[HubEntityOut] = Field(default_factory=list)
    evidence: list[dict] = Field(default_factory=list)
    historical_incidents: list[dict] = Field(default_factory=list)
    graph: HubGraph = Field(default_factory=HubGraph)
    analytics: dict = Field(default_factory=dict)
    gaps: list[str] = Field(default_factory=list)


class BehaviorTrainingRequest(BaseModel):
    model_config = {"extra": "forbid"}
    host: str = Field(min_length=1, max_length=512)
    since: datetime
    until: datetime

    @model_validator(mode="after")
    def validate_window(self):
        HubSearch(host=self.host, since=self.since, until=self.until)
        return self
