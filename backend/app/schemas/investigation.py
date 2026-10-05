from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator

InvestigationClassification = Literal["true_positive", "false_positive", "needs_investigation", "unknown"]
ToolName = Literal["incident_alerts", "cached_intel", "knowledge_search", "internal_context"]


class InvestigationPlan(BaseModel):
    model_config = {"extra": "forbid"}

    tools: list[ToolName] = Field(min_length=1, max_length=4)

    @model_validator(mode="after")
    def unique_tools(self):
        if len(set(self.tools)) != len(self.tools):
            raise ValueError("Duplicate investigation tools are not allowed")
        return self


class EvidenceItem(BaseModel):
    model_config = {"extra": "forbid"}

    id: str
    tool: ToolName
    source: str
    source_ref: str
    observed_at: datetime | None = None
    collected_at: datetime
    content: str = Field(max_length=1200)


class InvestigationFinding(BaseModel):
    model_config = {"extra": "forbid"}

    claim: str = Field(min_length=1, max_length=500)
    evidence_ids: list[str] = Field(min_length=1, max_length=5)


class InvestigationDraft(BaseModel):
    model_config = {"extra": "forbid"}

    classification: InvestigationClassification
    findings: list[InvestigationFinding] = Field(default_factory=list, max_length=10)
    gaps: list[str] = Field(default_factory=list, max_length=5)
    next_steps: list[str] = Field(default_factory=list, max_length=5)


class InvestigationOut(BaseModel):
    model_config = {"from_attributes": True}

    id: UUID
    incident_id: UUID
    provider_mode: str
    model_name: str | None
    status: Literal["PENDING_REVIEW", "CONFIRMED", "CORRECTED"]
    plan: InvestigationPlan
    evidence: list[EvidenceItem]
    report: InvestigationDraft
    reviewed_by: str | None
    final_classification: InvestigationClassification | None
    reviewer_notes: str | None
    reviewed_at: datetime | None
    created_at: datetime


class InvestigationReviewRequest(BaseModel):
    model_config = {"extra": "forbid"}

    reviewed_by: str = Field(min_length=1, max_length=255)
    classification: InvestigationClassification
    notes: str = Field(default="", max_length=2000)

    @field_validator("reviewed_by")
    @classmethod
    def require_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Reviewer name cannot be blank")
        return value
