from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.incident import IncidentDetailOut, IncidentSeverity, IncidentStatus
from app.schemas.threat_intel import IndicatorType, Verdict

AI_TRIAGE_CONTEXT_VERSION = "ai_triage_context.v2"
AI_TRIAGE_PROMPT_VERSION = "ai_triage_prompt.v2"
AI_TRIAGE_RESULT_VERSION = "ai_triage_result.v1"
UNTRUSTED_EVENT_DATA_START = "<UNTRUSTED_EVENT_DATA>"
UNTRUSTED_EVENT_DATA_END = "</UNTRUSTED_EVENT_DATA>"

AITriageClassification = Literal["true_positive", "false_positive", "needs_investigation", "unknown"]


class _AITriageSchema(BaseModel):
    model_config = {"extra": "ignore"}


class _StrictAITriageSchema(BaseModel):
    model_config = {"extra": "forbid"}


class AITriageRunRequest(_AITriageSchema):
    force: bool = False
    persist: bool = True


class AITriageIncidentContext(_StrictAITriageSchema):
    id: UUID
    title: str
    status: IncidentStatus
    severity: IncidentSeverity
    confidence: int = Field(ge=0, le=100)
    first_seen: datetime
    last_seen: datetime
    primary_host: str | None = None
    primary_user: str | None = None
    primary_src_ip: str | None = None
    mitre_ids: list[str] = Field(default_factory=list, max_length=50)
    alert_count: int = Field(ge=0)


class AITriageAlertEvidence(_StrictAITriageSchema):
    alert_id: UUID
    timestamp: datetime
    host: dict[str, Any] = Field(default_factory=dict)
    identity: dict[str, Any] = Field(default_factory=dict)
    network: dict[str, Any] = Field(default_factory=dict)
    process: dict[str, Any] = Field(default_factory=dict)
    file: dict[str, Any] = Field(default_factory=dict)
    detection: dict[str, Any] = Field(default_factory=dict)
    raw_ref: str | None = None


class AITriageProviderSummary(_StrictAITriageSchema):
    provider: str
    verdict: Verdict = "unknown"
    risk_score: int = Field(default=0, ge=0, le=100)
    confidence: int | None = Field(default=None, ge=0, le=100)
    summary: str | None = None
    error: str | None = None


class AITriageEnrichmentEvidence(_StrictAITriageSchema):
    alert_id: UUID
    evidence_path: str = Field(max_length=128)
    indicator: str = Field(max_length=2048)
    type: IndicatorType
    verdict: Verdict = "unknown"
    risk_score: int = Field(default=0, ge=0, le=100)
    providers: dict[str, AITriageProviderSummary] = Field(default_factory=dict)


class AITriageMitreContext(_StrictAITriageSchema):
    technique_id: str = Field(max_length=32)
    source: str = Field(default="incident", max_length=64)
    summary: str | None = Field(default=None, max_length=500)


class AITriagePlaybookContext(_StrictAITriageSchema):
    name: str = Field(max_length=128)
    source: str = Field(max_length=128)
    summary: str = Field(max_length=1000)


class AITriageDecisionAssessment(_StrictAITriageSchema):
    incident_alert_count: int = Field(ge=0)
    evidence_alert_count: int = Field(ge=0)
    omitted_alert_count: int = Field(ge=0)
    evidence_truncated: bool = False
    event_families: dict[str, int] = Field(default_factory=dict)
    event_kinds: dict[str, int] = Field(default_factory=dict)
    detection_groups: dict[str, int] = Field(default_factory=dict)
    authentication_outcomes: dict[str, int] = Field(default_factory=dict)
    maximum_rule_level: int = Field(default=0, ge=0, le=100)
    mitre_ids: list[str] = Field(default_factory=list, max_length=50)
    active_response_alerts: int = Field(default=0, ge=0)
    suspicious_or_malicious_iocs: int = Field(default=0, ge=0)
    benign_iocs: int = Field(default=0, ge=0)
    test_net_or_non_global_ip_context: bool = False
    has_trusted_benign_explanation: bool = False
    caveats: list[str] = Field(default_factory=list, max_length=20)


class AITriageContext(_StrictAITriageSchema):
    schema_version: Literal["ai_triage_context.v2"] = AI_TRIAGE_CONTEXT_VERSION
    incident: AITriageIncidentContext
    assessment: AITriageDecisionAssessment
    alerts: list[AITriageAlertEvidence] = Field(default_factory=list)
    enrichment: list[AITriageEnrichmentEvidence] = Field(default_factory=list)
    mitre_context: list[AITriageMitreContext] = Field(default_factory=list)
    playbook_context: list[AITriagePlaybookContext] = Field(default_factory=list)
    internal_context: dict[str, Any] = Field(default_factory=dict)


class AITriageSanitizerMetadata(_StrictAITriageSchema):
    truncated: int = Field(default=0, ge=0)
    redacted: int = Field(default=0, ge=0)
    stripped_controls: int = Field(default=0, ge=0)
    binary_stripped: int = Field(default=0, ge=0)
    huge_blobs_stripped: int = Field(default=0, ge=0)
    depth_limited: int = Field(default=0, ge=0)
    dropped_items: int = Field(default=0, ge=0)
    total_chars: int = Field(default=0, ge=0)


class AITriagePromptEnvelope(_StrictAITriageSchema):
    schema_version: Literal["ai_triage_prompt.v2"] = AI_TRIAGE_PROMPT_VERSION
    system_instruction: str = Field(max_length=4000)
    untrusted_data_start: Literal["<UNTRUSTED_EVENT_DATA>"] = UNTRUSTED_EVENT_DATA_START
    incident_context: AITriageContext
    untrusted_data_end: Literal["</UNTRUSTED_EVENT_DATA>"] = UNTRUSTED_EVENT_DATA_END
    sanitizer: AITriageSanitizerMetadata = Field(default_factory=AITriageSanitizerMetadata)


class AITriageMitreFinding(_StrictAITriageSchema):
    technique_id: str = Field(max_length=32)
    reason: str = Field(max_length=500)


class AITriageEvidenceRef(_StrictAITriageSchema):
    alert_id: UUID
    field_path: str = Field(max_length=128)
    reason: str = Field(max_length=500)


class AITriageIOCAnalysis(_StrictAITriageSchema):
    indicator: str = Field(max_length=2048)
    type: IndicatorType
    verdict: Verdict = "unknown"
    risk_score: int = Field(default=0, ge=0, le=100)
    reason: str = Field(max_length=500)


class AITriageResult(_StrictAITriageSchema):
    schema_version: Literal["ai_triage_result.v1"] = AI_TRIAGE_RESULT_VERSION
    title: str = Field(min_length=1, max_length=255)
    classification: AITriageClassification
    severity: IncidentSeverity
    confidence: int = Field(ge=0, le=100)
    summary: str = Field(min_length=1, max_length=1000)
    attack_chain: list[str] = Field(default_factory=list, max_length=20)
    mitre: list[AITriageMitreFinding] = Field(default_factory=list, max_length=50)
    evidence: list[AITriageEvidenceRef] = Field(default_factory=list, max_length=50)
    ioc_analysis: list[AITriageIOCAnalysis] = Field(default_factory=list, max_length=50)
    hypotheses: list[str] = Field(default_factory=list, max_length=20)
    recommended_investigation: list[str] = Field(default_factory=list, max_length=20)
    recommended_actions: list[str] = Field(default_factory=list, max_length=20)
    false_positive_probability: int = Field(ge=0, le=100)
    needs_human_review: bool = True


class AITriageRunOut(_AITriageSchema):
    incident_id: UUID
    provider_mode: str
    stored: bool
    result: AITriageResult
    incident: IncidentDetailOut | None = None


class AITriageAnalysisOut(_AITriageSchema):
    incident_id: UUID
    has_analysis: bool
    result: AITriageResult | None = None
