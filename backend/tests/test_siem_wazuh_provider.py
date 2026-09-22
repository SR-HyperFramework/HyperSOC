import asyncio
import json

import httpx
import pytest

from app.core.config import settings
from app.services.response import ResponseActionConflict, ResponseActionService
from app.services.siem import (
    OfflineWazuhActiveResponseProvider,
    SIEMResponseError,
    WazuhActiveResponseProvider,
    build_siem_provider,
    parse_agent_list,
)
from tests.test_response_service import _MemoryDb, _action, _incident

_TOKEN_PAYLOAD = {"data": {"token": "jwt-token-value"}}


def _ar_payload(*, affected=("001",), failed_items=(), total_affected=None, total_failed=None, error=0):
    return {
        "data": {
            "affected_items": list(affected),
            "total_affected_items": len(affected) if total_affected is None else total_affected,
            "failed_items": list(failed_items),
            "total_failed_items": len(failed_items) if total_failed is None else total_failed,
        },
        "error": error,
    }


class _WazuhAPI:
    """Routes the two-step authenticate-then-command flow to canned responses."""

    def __init__(self, *, auth_status=200, auth_payload=None, ar_status=200, ar_payload=None, transport_error=False):
        self.auth_status = auth_status
        self.auth_payload = _TOKEN_PAYLOAD if auth_payload is None else auth_payload
        self.ar_status = ar_status
        self.ar_payload = _ar_payload() if ar_payload is None else ar_payload
        self.transport_error = transport_error
        self.requests: list[httpx.Request] = []
        self.client_kwargs: list[dict] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.transport_error:
            raise httpx.ConnectError("connection refused")
        if request.url.path.endswith("/security/user/authenticate"):
            return httpx.Response(self.auth_status, json=self.auth_payload)
        if request.url.path.endswith("/active-response"):
            return httpx.Response(self.ar_status, json=self.ar_payload)
        return httpx.Response(404, json={})

    def factory(self, **kwargs):
        self.client_kwargs.append(kwargs)
        return httpx.AsyncClient(transport=httpx.MockTransport(self), timeout=kwargs.get("timeout"))


def _provider(api: _WazuhAPI, *, agents="001", **kwargs) -> WazuhActiveResponseProvider:
    return WazuhActiveResponseProvider(
        base_url="https://wazuh.internal:55000",
        username="soc-api",
        password="super-secret-password",
        agents=agents,
        client_factory=api.factory,
        **kwargs,
    )


def test_block_ip_authenticates_then_sends_command_to_named_agents():
    api = _WazuhAPI(ar_payload=_ar_payload(affected=("001", "002")))
    provider = _provider(api, agents="001,002")

    result = asyncio.run(provider.execute_response(_action(status="APPROVED")))

    assert result.status == "SUCCESS"
    assert result.provider == "wazuh-active-response"
    assert result.metadata["agents_affected"] == ["001", "002"]
    assert result.metadata["total_failed_items"] == 0

    auth_request, ar_request = api.requests
    assert auth_request.method == "POST"
    assert auth_request.url.path == "/security/user/authenticate"
    assert ar_request.method == "PUT"
    assert ar_request.url.params["agents_list"] == "001,002"
    assert ar_request.headers["Authorization"] == "Bearer jwt-token-value"

    body = json.loads(ar_request.read())
    assert body["command"] == "firewall-drop"
    assert body["alert"]["data"]["srcip"] == "8.8.8.8"


def test_tls_verification_and_timeout_reach_the_http_client():
    api = _WazuhAPI()
    provider = _provider(api, timeout_seconds=7, verify_tls=False)

    asyncio.run(provider.execute_response(_action(status="APPROVED")))

    assert api.client_kwargs[0]["verify"] is False
    assert api.client_kwargs[0]["timeout"] == 7


@pytest.mark.parametrize(
    ("ar_payload", "agents"),
    [
        (_ar_payload(affected=("001",), failed_items=({"error": {"code": 1701}, "id": ["002"]},)), "001,002"),
        (_ar_payload(affected=("001",)), "001,002"),
        (_ar_payload(affected=(), total_affected=0), "001"),
        (_ar_payload(affected=("001",), error=1), "001"),
    ],
)
def test_partial_or_rejected_delivery_is_reported_as_failed(ar_payload, agents):
    provider = _provider(_WazuhAPI(ar_payload=ar_payload), agents=agents)

    result = asyncio.run(provider.execute_response(_action(status="APPROVED")))

    assert result.status == "FAILED"
    assert "did not apply" in result.message


def test_failed_agent_error_codes_are_recorded_for_triage():
    api = _WazuhAPI(
        ar_payload=_ar_payload(
            affected=("001",),
            failed_items=({"error": {"code": 1701, "message": "Agent is not active"}, "id": ["002"]},),
        )
    )
    provider = _provider(api, agents="001,002")

    result = asyncio.run(provider.execute_response(_action(status="APPROVED")))

    assert result.metadata["failed_error_codes"] == [1701]
    assert result.metadata["agents_requested"] == ["001", "002"]


def test_partial_delivery_does_not_mark_the_incident_contained():
    async def scenario():
        incident = _incident()
        action = _action(status="APPROVED")
        db = _MemoryDb(incident=incident, actions=[action])
        api = _WazuhAPI(ar_payload=_ar_payload(affected=("001",)))
        service = ResponseActionService(siem_provider=_provider(api, agents="001,002"))

        executed = await service.execute(db, action.id)

        assert executed is not None
        assert executed.status == "FAILED"
        assert incident.status == "NEW"

    asyncio.run(scenario())


def test_full_delivery_marks_the_incident_contained():
    async def scenario():
        incident = _incident()
        action = _action(status="APPROVED")
        db = _MemoryDb(incident=incident, actions=[action])
        service = ResponseActionService(siem_provider=_provider(_WazuhAPI(), agents="001"))

        executed = await service.execute(db, action.id)

        assert executed is not None
        assert executed.status == "SUCCESS"
        assert incident.status == "CONTAINED"

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("api", "expected"),
    [
        (_WazuhAPI(auth_status=401), "rejected the configured credentials"),
        (_WazuhAPI(auth_status=500), "authentication returned HTTP 500"),
        (_WazuhAPI(auth_payload={"data": {}}), "did not include a token"),
        (_WazuhAPI(ar_status=403), "rejected the active response request"),
        (_WazuhAPI(ar_status=500), "returned HTTP 500"),
        (_WazuhAPI(transport_error=True), "request failed"),
    ],
)
def test_api_failures_raise_siem_response_error_without_leaking_credentials(api, expected):
    provider = _provider(api)

    with pytest.raises(SIEMResponseError) as exc_info:
        asyncio.run(provider.execute_response(_action(status="APPROVED")))

    message = str(exc_info.value)
    assert expected in message
    assert "super-secret-password" not in message
    assert "soc-api" not in message


def test_provider_failure_marks_action_failed_through_the_service():
    async def scenario():
        incident = _incident()
        action = _action(status="APPROVED")
        db = _MemoryDb(incident=incident, actions=[action])
        service = ResponseActionService(siem_provider=_provider(_WazuhAPI(auth_status=401)))

        with pytest.raises(ResponseActionConflict):
            await service.execute(db, action.id)

        assert action.status == "FAILED"
        assert incident.status == "NEW"

    asyncio.run(scenario())


def test_non_block_ip_actions_are_refused_before_any_network_call():
    api = _WazuhAPI()
    provider = _provider(api)
    action = _action(status="APPROVED")
    action.type = "DISABLE_USER"

    with pytest.raises(SIEMResponseError, match="Unsupported active response action type"):
        asyncio.run(provider.execute_response(action))

    assert api.requests == []


@pytest.mark.parametrize("value", ["all", "*", "001,all", "", " , ", "001,agent-2", "abc"])
def test_agent_list_rejects_fleet_wide_and_malformed_scopes(value):
    with pytest.raises(ValueError):
        parse_agent_list(value)


def test_agent_list_accepts_explicit_ids():
    assert parse_agent_list(" 001 , 002 ") == ["001", "002"]


def test_build_siem_provider_selects_mode(monkeypatch):
    monkeypatch.setattr(settings, "wazuh_active_response_provider_mode", "offline")
    assert isinstance(build_siem_provider(), OfflineWazuhActiveResponseProvider)

    monkeypatch.setattr(settings, "wazuh_active_response_provider_mode", "wazuh")
    monkeypatch.setattr(settings, "wazuh_api_url", "https://wazuh.internal:55000")
    monkeypatch.setattr(settings, "wazuh_api_username", "soc-api")
    monkeypatch.setattr(settings, "wazuh_api_password", "secret")
    monkeypatch.setattr(settings, "wazuh_active_response_agents", "001,002")

    provider = build_siem_provider()

    assert isinstance(provider, WazuhActiveResponseProvider)
    assert provider.agents == ["001", "002"]
    assert provider.verify_tls is True


def test_wazuh_mode_rejects_fleet_wide_agent_scope_at_startup(monkeypatch):
    monkeypatch.setattr(settings, "wazuh_active_response_provider_mode", "wazuh")
    monkeypatch.setattr(settings, "wazuh_api_url", "https://wazuh.internal:55000")
    monkeypatch.setattr(settings, "wazuh_api_username", "soc-api")
    monkeypatch.setattr(settings, "wazuh_api_password", "secret")
    monkeypatch.setattr(settings, "wazuh_active_response_agents", "all")

    with pytest.raises(ValueError, match="explicit agent ids"):
        build_siem_provider()
