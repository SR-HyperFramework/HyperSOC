import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class _NormalizedSchema(BaseModel):
    """Base contract for canonical alerts and their optional evidence fields."""

    model_config = {"extra": "ignore"}


class NormalizedHost(_NormalizedSchema):
    id: str | None = None
    name: str | None = None
    ip: str | None = None


class NormalizedIdentity(_NormalizedSchema):
    username: str | None = None
    actor: str | None = None
    target: str | None = None
    domain: str | None = None
    auth_outcome: str | None = None
    auth_status: str | None = None
    auth_method: str | None = None
    logon_type: str | None = None
    failure_reason: str | None = None
    attempt_count: int | None = None


class NormalizedNetwork(_NormalizedSchema):
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    domain: str | None = None
    url: str | None = None
    dns_query: str | None = None
    http_method: str | None = None
    http_status: int | None = None
    user_agent: str | None = None
    referrer: str | None = None


class NormalizedProcess(_NormalizedSchema):
    name: str | None = None
    image: str | None = None
    command_line: str | None = None
    parent_name: str | None = None
    parent_image: str | None = None
    parent_command_line: str | None = None
    current_directory: str | None = None
    pid: int | None = None
    parent_pid: int | None = None
    guid: str | None = None
    hash: str | None = None
    hash_algorithm: str | None = None
    script_block: str | None = None


class NormalizedFile(_NormalizedSchema):
    path: str | None = None
    name: str | None = None
    hash: str | None = None
    hash_algorithm: str | None = None
    action: str | None = None


class NormalizedDetection(_NormalizedSchema):
    source: str = "wazuh"
    event_family: str = "wazuh"
    event_kind: str | None = None
    event_id: str | None = None
    rule_id: str | None = None
    level: int | None = None
    severity: str | None = None
    description: str | None = None
    groups: list[str] = Field(default_factory=list)
    mitre_ids: list[str] = Field(default_factory=list)
    status: str | None = None
    outcome: str | None = None
    provider: str | None = None
    decoder: str | None = None


class NormalizedAlert(_NormalizedSchema):
    """Provider-neutral alert evidence for enrichment and correlation services.

    `raw_ref` identifies the native Wazuh event when it exposes one. It is
    provenance metadata only: the untrusted raw payload remains in Phase 3
    storage and is intentionally not embedded in this downstream contract.
    """

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    timestamp: datetime
    host: NormalizedHost = Field(default_factory=NormalizedHost)
    identity: NormalizedIdentity = Field(default_factory=NormalizedIdentity)
    network: NormalizedNetwork = Field(default_factory=NormalizedNetwork)
    process: NormalizedProcess = Field(default_factory=NormalizedProcess)
    file: NormalizedFile = Field(default_factory=NormalizedFile)
    detection: NormalizedDetection = Field(default_factory=NormalizedDetection)
    raw_ref: str | None = None
