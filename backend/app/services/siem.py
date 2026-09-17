from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from app.core.config import settings
from app.models.response_action import ResponseAction


class SIEMResponseError(Exception):
    """Raised when a SIEM provider cannot execute an approved response action."""


@dataclass(frozen=True)
class SIEMExecutionResult:
    provider: str
    action: str
    target: str
    status: str
    message: str
    metadata: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "action": self.action,
            "target": self.target,
            "status": self.status,
            "message": self.message,
            "metadata": self.metadata,
        }


class SIEMProvider(Protocol):
    provider_mode: str

    async def execute_response(self, action: ResponseAction) -> SIEMExecutionResult:
        ...


class OfflineWazuhActiveResponseProvider:
    """Deterministic Wazuh Active Response simulator for tests and local labs."""

    provider_mode = "offline"

    async def execute_response(self, action: ResponseAction) -> SIEMExecutionResult:
        if action.type != "BLOCK_IP":
            raise SIEMResponseError(f"Unsupported active response action type: {action.type}")
        return SIEMExecutionResult(
            provider="wazuh-active-response-offline",
            action=action.type,
            target=action.target,
            status="SUCCESS",
            message="Offline Wazuh Active Response simulation recorded the approved BLOCK_IP action.",
            metadata={
                "agent_scope": settings.wazuh_active_response_agents,
                "duration_minutes": action.duration_minutes,
                "command": "firewall-drop",
                "execution_mode": "offline",
            },
        )


class UnavailableSIEMProvider:
    def __init__(self, provider_mode: str) -> None:
        self.provider_mode = provider_mode

    async def execute_response(self, _action: ResponseAction) -> SIEMExecutionResult:
        raise SIEMResponseError(f"SIEM provider mode '{self.provider_mode}' is not implemented")


def build_siem_provider(provider_mode: str | None = None) -> SIEMProvider:
    mode = provider_mode or settings.wazuh_active_response_provider_mode
    if mode == "offline":
        return OfflineWazuhActiveResponseProvider()
    return UnavailableSIEMProvider(mode)
