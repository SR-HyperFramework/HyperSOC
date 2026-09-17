from datetime import datetime, timezone
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from app.api.response import get_response_action_service
from app.core.database import get_db
from app.main import app
from app.schemas.response_action import ResponseActionOut
from app.services.response import ResponseActionConflict

_INCIDENT_ID = UUID("00000000-0000-0000-0000-000000000200")
_ACTION_ID = UUID("00000000-0000-0000-0000-000000000500")
_NOW = datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc)


class _RouteResponseService:
    def __init__(self) -> None:
        self.create_calls = []
        self.list_calls = []
        self.approve_calls = []
        self.reject_calls = []
        self.execute_calls = []
        self.missing = False
        self.conflict = False

    async def create_for_incident(self, _db, incident_id, request):
        self.create_calls.append((incident_id, request))
        if self.missing:
            return None
        if self.conflict:
            raise ResponseActionConflict("policy rejected")
        return _action_out(incident_id=incident_id)

    async def list_for_incident(self, _db, incident_id):
        self.list_calls.append(incident_id)
        if self.missing:
            return None
        return [_action_out(incident_id=incident_id)]

    async def approve(self, _db, action_id, request):
        self.approve_calls.append((action_id, request))
        if self.missing:
            return None
        if self.conflict:
            raise ResponseActionConflict("not pending")
        return _action_out(action_id=action_id, status="APPROVED", approved_by=request.approved_by)

    async def reject(self, _db, action_id, request):
        self.reject_calls.append((action_id, request))
        if self.missing:
            return None
        if self.conflict:
            raise ResponseActionConflict("not pending")
        return _action_out(action_id=action_id, status="REJECTED", rejected_by=request.rejected_by, rejection_reason=request.reason)

    async def execute(self, _db, action_id):
        self.execute_calls.append(action_id)
        if self.missing:
            return None
        if self.conflict:
            raise ResponseActionConflict("not approved")
        return _action_out(action_id=action_id, status="SUCCESS", execution_result={"provider": "wazuh-active-response-offline", "status": "SUCCESS"})


class _FakeDb:
    pass


def _action_out(
    *,
    incident_id=_INCIDENT_ID,
    action_id=_ACTION_ID,
    status="PENDING",
    approved_by=None,
    rejected_by=None,
    rejection_reason=None,
    execution_result=None,
) -> ResponseActionOut:
    return ResponseActionOut(
        id=action_id,
        incident_id=incident_id,
        type="BLOCK_IP",
        target="8.8.8.8",
        reason="Contain suspicious source after approval.",
        risk="medium",
        status=status,
        requested_by="AI",
        approved_by=approved_by,
        approved_at=_NOW if approved_by else None,
        rejected_by=rejected_by,
        rejected_at=_NOW if rejected_by else None,
        rejection_reason=rejection_reason,
        duration_minutes=30,
        policy_result={"allowed": True, "reasons": [], "normalized_target": "8.8.8.8"},
        execution_result=execution_result,
        created_at=_NOW,
        updated_at=_NOW,
    )


@pytest.fixture
def api_client():
    previous_overrides = dict(app.dependency_overrides)
    state = {"service": _RouteResponseService()}

    async def override_get_db():
        yield _FakeDb()

    def override_service():
        return state["service"]

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_response_action_service] = override_service
    try:
        yield TestClient(app), state
    finally:
        app.dependency_overrides = previous_overrides


def test_create_response_action_returns_pending_action(api_client):
    client, state = api_client

    response = client.post(
        f"/api/v1/incidents/{_INCIDENT_ID}/actions",
        json={"type": "BLOCK_IP", "target": "8.8.8.8", "reason": "Contain suspicious source", "duration_minutes": 30},
    )

    assert response.status_code == 201
    assert response.json()["status"] == "PENDING"
    assert response.json()["execution_result"] is None
    assert state["service"].create_calls[0][0] == _INCIDENT_ID


def test_create_response_action_maps_missing_conflict_and_validation(api_client):
    client, state = api_client

    state["service"].missing = True
    assert client.post(f"/api/v1/incidents/{_INCIDENT_ID}/actions", json={"type": "BLOCK_IP", "target": "8.8.8.8", "reason": "x"}).status_code == 404

    state["service"].missing = False
    state["service"].conflict = True
    assert client.post(f"/api/v1/incidents/{_INCIDENT_ID}/actions", json={"type": "BLOCK_IP", "target": "8.8.8.8", "reason": "x"}).status_code == 409

    assert client.post(f"/api/v1/incidents/{_INCIDENT_ID}/actions", json={"type": "SHELL", "target": "x", "reason": "x"}).status_code == 422


def test_list_response_actions_returns_incident_actions(api_client):
    client, state = api_client

    response = client.get(f"/api/v1/incidents/{_INCIDENT_ID}/actions")

    assert response.status_code == 200
    assert response.json()[0]["id"] == str(_ACTION_ID)
    assert state["service"].list_calls == [_INCIDENT_ID]


def test_approve_response_action_records_human_approval(api_client):
    client, state = api_client

    response = client.post(f"/api/v1/actions/{_ACTION_ID}/approve", json={"approved_by": "analyst"})

    assert response.status_code == 200
    assert response.json()["status"] == "APPROVED"
    assert response.json()["approved_by"] == "analyst"
    assert response.json()["execution_result"] is None
    assert state["service"].approve_calls[0][0] == _ACTION_ID


def test_reject_response_action_records_human_rejection(api_client):
    client, state = api_client

    response = client.post(f"/api/v1/actions/{_ACTION_ID}/reject", json={"rejected_by": "analyst", "reason": "known benign scanner"})

    assert response.status_code == 200
    assert response.json()["status"] == "REJECTED"
    assert response.json()["rejected_by"] == "analyst"
    assert response.json()["rejection_reason"] == "known benign scanner"
    assert state["service"].reject_calls[0][0] == _ACTION_ID


def test_execute_response_action_runs_only_service_approved_execution(api_client):
    client, state = api_client

    response = client.post(f"/api/v1/actions/{_ACTION_ID}/execute")

    assert response.status_code == 200
    assert response.json()["status"] == "SUCCESS"
    assert response.json()["execution_result"]["provider"] == "wazuh-active-response-offline"
    assert state["service"].execute_calls == [_ACTION_ID]


def test_approve_reject_and_execute_map_missing_and_conflict(api_client):
    client, state = api_client

    state["service"].missing = True
    assert client.post(f"/api/v1/actions/{_ACTION_ID}/approve", json={"approved_by": "analyst"}).status_code == 404
    assert client.post(f"/api/v1/actions/{_ACTION_ID}/execute").status_code == 404

    state["service"].missing = False
    state["service"].conflict = True
    assert client.post(f"/api/v1/actions/{_ACTION_ID}/reject", json={"rejected_by": "analyst", "reason": "x"}).status_code == 409
    assert client.post(f"/api/v1/actions/{_ACTION_ID}/execute").status_code == 409
