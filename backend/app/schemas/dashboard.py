from datetime import datetime

from pydantic import BaseModel, Field


class DashboardSummaryOut(BaseModel):
    critical_incidents: int = Field(ge=0)
    high_incidents: int = Field(ge=0)
    open_incidents: int = Field(ge=0)
    alerts_last_24h: int = Field(ge=0)
    total_incidents: int = Field(ge=0)
    total_alerts: int = Field(ge=0)


class DashboardMitreTechniqueOut(BaseModel):
    technique_id: str = Field(min_length=1, max_length=32)
    alert_count: int = Field(ge=0)
    incident_count: int = Field(ge=0)
    total_count: int = Field(ge=0)


class DashboardTimelinePointOut(BaseModel):
    bucket_start: datetime
    alert_count: int = Field(ge=0)
    incident_count: int = Field(ge=0)


class DashboardTimelineOut(BaseModel):
    bucket_minutes: int = Field(ge=1)
    points: list[DashboardTimelinePointOut] = Field(default_factory=list)
