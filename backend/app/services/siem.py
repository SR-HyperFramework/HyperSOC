from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from app.core.config import settings
from app.models.response_action import ResponseAction

_AGENT_ID_RE = re.compile(r"^[0-9]{1,8}$")
_MAX_RESPONSE_BYTES = 1_048_576
_MAX_FAILED_ITEMS = 20


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


def parse_agent_list(value: str) -> list[str]:
    """Containment is scoped to explicitly named agents, never to the whole fleet."""
    agents = [item.strip() for item in value.split(",") if item.strip()]
    if not agents:
        raise ValueError("WAZUH_ACTIVE_RESPONSE_AGENTS must list at least one Wazuh agent id")
    if any(agent.casefold() in ("all", "*") for agent in agents):
        raise ValueError("WAZUH_ACTIVE_RESPONSE_AGENTS must list explicit agent ids, not 'all' or '*'")
    if any(not _AGENT_ID_RE.fullmatch(agent) for agent in agents):
        raise ValueError("WAZUH_ACTIVE_RESPONSE_AGENTS must contain numeric Wazuh agent ids such as 001,002")
    return agents


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _safe_int(value: Any, *, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


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


class WazuhActiveResponseProvider:
    """Wazuh Manager API client that sends approved containment commands to named agents."""

    provider_mode = "wazuh"

    def __init__(
        self,
        *,
        base_url: str,
        username: str,
        password: str,
        agents: str,
        command: str = "firewall-drop",
        timeout_seconds: int = 10,
        verify_tls: bool = True,
        client_factory: Callable[..., httpx.AsyncClient] | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.agents = parse_agent_list(agents)
        self.command = command
        self.timeout_seconds = timeout_seconds
        self.verify_tls = verify_tls
        self.client_factory = client_factory or httpx.AsyncClient

    async def execute_response(self, action: ResponseAction) -> SIEMExecutionResult:
        if action.type != "BLOCK_IP":
            raise SIEMResponseError(f"Unsupported active response action type: {action.type}")

        async with self.client_factory(timeout=self.timeout_seconds, verify=self.verify_tls) as client:
            token = await self._authenticate(client)
            payload = await self._send_active_response(client, token, action.target)
        return self._result(action, payload)

    async def _authenticate(self, client: httpx.AsyncClient) -> str:
        try:
            response = await client.post(
                f"{self.base_url}/security/user/authenticate",
                auth=(self.username, self.password),
                headers={"Accept": "application/json"},
            )
        except httpx.HTTPError as exc:
            raise SIEMResponseError("Wazuh API authentication request failed") from exc

        if response.status_code in (401, 403):
            raise SIEMResponseError("Wazuh API rejected the configured credentials")
        if response.status_code != 200:
            raise SIEMResponseError(f"Wazuh API authentication returned HTTP {response.status_code}")

        token = _mapping(self._json(response).get("data")).get("token")
        if not isinstance(token, str) or not token:
            raise SIEMResponseError("Wazuh API authentication response did not include a token")
        return token

    async def _send_active_response(self, client: httpx.AsyncClient, token: str, target: str) -> dict[str, Any]:
        try:
            response = await client.put(
                f"{self.base_url}/active-response",
                params={"agents_list": ",".join(self.agents)},
                headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                json={
                    "command": self.command,
                    "arguments": [],
                    "alert": {"data": {"srcip": target}},
                },
            )
        except httpx.HTTPError as exc:
            raise SIEMResponseError("Wazuh active response request failed") from exc

        if response.status_code in (401, 403):
            raise SIEMResponseError("Wazuh API rejected the active response request")
        if response.status_code not in (200, 206, 207):
            raise SIEMResponseError(f"Wazuh active response returned HTTP {response.status_code}")
        return self._json(response)

    def _json(self, response: httpx.Response) -> dict[str, Any]:
        if len(response.content) > _MAX_RESPONSE_BYTES:
            raise SIEMResponseError("Wazuh API response exceeded the size limit")
        try:
            payload = response.json()
        except ValueError as exc:
            raise SIEMResponseError("Wazuh API returned a non-JSON response") from exc
        if not isinstance(payload, Mapping):
            raise SIEMResponseError("Wazuh API returned an unexpected JSON shape")
        return dict(payload)

    def _result(self, action: ResponseAction, payload: dict[str, Any]) -> SIEMExecutionResult:
        data = _mapping(payload.get("data"))
        affected = [str(item) for item in data.get("affected_items") or [] if _AGENT_ID_RE.fullmatch(str(item))]
        affected_count = _safe_int(data.get("total_affected_items"), default=len(affected))
        failed_count = _safe_int(data.get("total_failed_items"))
        api_error = _safe_int(payload.get("error"))
        requested_count = len(self.agents)

        contained = api_error == 0 and failed_count == 0 and affected_count == requested_count
        metadata = {
            "agents_requested": list(self.agents),
            "agents_affected": affected,
            "total_affected_items": affected_count,
            "total_failed_items": failed_count,
            "failed_error_codes": self._failed_error_codes(data),
            "api_error": api_error,
            "command": self.command,
            "duration_minutes": action.duration_minutes,
            "execution_mode": "wazuh",
        }

        if contained:
            message = f"Wazuh applied the BLOCK_IP command on all {requested_count} requested agents."
        else:
            message = (
                f"Wazuh did not apply the BLOCK_IP command on every requested agent: "
                f"{affected_count} of {requested_count} affected, {failed_count} failed."
            )
        return SIEMExecutionResult(
            provider="wazuh-active-response",
            action=action.type,
            target=action.target,
            status="SUCCESS" if contained else "FAILED",
            message=message,
            metadata=metadata,
        )

    def _failed_error_codes(self, data: Mapping[str, Any]) -> list[int]:
        codes: list[int] = []
        for item in list(data.get("failed_items") or [])[:_MAX_FAILED_ITEMS]:
            code = _mapping(_mapping(item).get("error")).get("code")
            if code is not None:
                codes.append(_safe_int(code))
        return codes


class UnavailableSIEMProvider:
    def __init__(self, provider_mode: str) -> None:
        self.provider_mode = provider_mode

    async def execute_response(self, _action: ResponseAction) -> SIEMExecutionResult:
        raise SIEMResponseError(f"SIEM provider mode '{self.provider_mode}' is not implemented")


def build_siem_provider(provider_mode: str | None = None) -> SIEMProvider:
    mode = provider_mode or settings.wazuh_active_response_provider_mode
    if mode == "offline":
        return OfflineWazuhActiveResponseProvider()
    if mode == "wazuh":
        return WazuhActiveResponseProvider(
            base_url=settings.wazuh_api_url,
            username=settings.wazuh_api_username,
            password=settings.wazuh_api_password,
            agents=settings.wazuh_active_response_agents,
            command=settings.wazuh_active_response_command,
            timeout_seconds=settings.wazuh_active_response_timeout_seconds,
            verify_tls=settings.wazuh_api_verify_tls,
        )
    return UnavailableSIEMProvider(mode)
