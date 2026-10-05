from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

ResponseActionType = Literal["BLOCK_IP", "DISABLE_USER", "KILL_PROCESS", "QUARANTINE_FILE"]
ResponseActionRisk = Literal["low", "medium", "high"]
ResponseActionStatus = Literal["PENDING", "APPROVED", "EXECUTING", "SUCCESS", "FAILED", "REJECTED"]


class _ResponseActionSchema(BaseModel):
    model_config = {"extra": "ignore"}


class ResponseActionCreate(_ResponseActionSchema):
    type: ResponseActionType
    target: str = Field(min_length=1, max_length=512)
    reason: str = Field(min_length=1, max_length=2000)
    risk: ResponseActionRisk = "medium"
    requested_by: str = Field(default="AI", min_length=1, max_length=64)
    duration_minutes: int | None = Field(default=None, ge=1, le=1440)


class ResponseActionPolicyResult(BaseModel):
    allowed: bool
    reasons: list[str] = Field(default_factory=list)
    normalized_target: str | None = None


class ResponseActionOut(_ResponseActionSchema):
    id: UUID
    incident_id: UUID
    type: ResponseActionType
    target: str
    reason: str
    risk: ResponseActionRisk
    status: ResponseActionStatus
    requested_by: str
    approved_by: str | None = None
    approved_at: datetime | None = None
    rejected_by: str | None = None
    rejected_at: datetime | None = None
    rejection_reason: str | None = None
    duration_minutes: int | None = None
    policy_result: dict = Field(default_factory=dict)
    execution_result: dict | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    model_config = {"from_attributes": True}


class ResponseActionApprovalRequest(_ResponseActionSchema):
    approved_by: str = Field(min_length=1, max_length=255)


class ResponseActionRejectRequest(_ResponseActionSchema):
    rejected_by: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=1, max_length=2000)


class ResponseVerificationRequest(_ResponseActionSchema):
    evidence_id: UUID | None = None
    evidence_ids: list[UUID] = Field(default_factory=list, max_length=50)
    notes: str = Field(min_length=1, max_length=2000)
