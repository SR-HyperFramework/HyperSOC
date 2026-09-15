import uuid
from datetime import datetime
from typing import Any, Self

from pydantic import BaseModel, Field, model_validator


class _AlertSchema(BaseModel):
    model_config = {"extra": "ignore"}


class AgentIn(_AlertSchema):
    id: str | None = None
    name: str | None = None
    ip: str | None = None


class RuleIn(_AlertSchema):
    id: str | None = None
    level: int | None = None
    description: str | None = None
    groups: list[str] = Field(default_factory=list)
    mitre_ids: list[str] = Field(default_factory=list)


class EventIn(_AlertSchema):
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    username: str | None = None
    process_name: str | None = None
    process_command_line: str | None = None
    file_path: str | None = None
    file_hash: str | None = None


class AlertIngest(_AlertSchema):
    source: str = "wazuh"
    timestamp: datetime
    agent: AgentIn = Field(default_factory=AgentIn)
    rule: RuleIn = Field(default_factory=RuleIn)
    event: EventIn = Field(default_factory=EventIn)
    raw: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_source(self) -> Self:
        if self.source != "wazuh":
            raise ValueError("source must be wazuh")
        return self


class AlertOut(_AlertSchema):
    id: uuid.UUID
    external_id: str | None
    source: str
    timestamp: datetime

    agent_id: str | None
    agent_name: str | None

    rule_id: str | None
    rule_level: int | None
    rule_description: str | None

    mitre_ids: list[str]
    groups: list[str]

    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None

    username: str | None

    process_name: str | None
    process_command_line: str | None

    file_path: str | None
    file_hash: str | None

    status: str
    created_at: datetime

    model_config = {"from_attributes": True}
