from datetime import datetime, timezone
from uuid import UUID

import pytest

from app.models.incident import Incident
from app.models.response_action import ResponseAction
from app.schemas.response_action import ResponseActionApprovalRequest, ResponseActionCreate, ResponseActionRejectRequest
from app.services.response import ResponseActionConflict, ResponseActionPolicy, ResponseActionService
from app.services.siem import SIEMResponseError

_NOW = datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc)
_INCIDENT_ID = UUID("00000000-0000-0000-0000-000000000200")
_ACTION_ID = UUID("00000000-0000-0000-0000-000000000500")


class _ScalarResult:
    def __init__(self, rows):
        self._rows = list(rows)

    def all(self):
        return list(self._rows)


class _FailingSIEMProvider:
    provider_mode = "failing"

    async def execute_response(self, _action):
        raise SIEMResponseError("wazuh unavailable")


class _MemoryDb:
    def __init__(self, *, incident=None, actions=None) -> None:
        self.incident = incident
        self.actions = {action.id: action for action in (actions or [])}
        self.added = []
        self.commits = 0
        self.refreshed = []

    async def get(self, model, item_id, **_kwargs):
        if model is Incident and self.incident and item_id == self.incident.id:
            return self.incident
        if model is ResponseAction:
            return self.actions.get(item_id)
        return None

    def add(self, row):
        self.added.append(row)
        if isinstance(row, ResponseAction):
            self.actions[row.id] = row

    async def scalars(self, statement):
        text = str(statement)
        if "response_actions" in text:
            return _ScalarResult([row for row in self.actions.values() if row.incident_id == self.incident.id])
        return _ScalarResult([])

    async def commit(self):
        self.commits += 1

    async def rollback(self):
        return None

    async def refresh(self, row):
        self.refreshed.append(row)


def _incident() -> Incident:
    return Incident(
        id=_INCIDENT_ID,
        title="Possible brute-force authentication chain for root on linux-server",
        status="NEW",
        severity="high",
        confidence=80,
        first_seen=_NOW,
        last_seen=_NOW,
        primary_host="linux-server",
        primary_user="root",
        primary_src_ip="8.8.8.8",
        mitre_ids=["T1110"],
        alert_count=3,
        ai_summary=None,
        ai_analysis=None,
        created_at=_NOW,
        updated_at=_NOW,
    )


def _action(*, status="PENDING", target="8.8.8.8") -> ResponseAction:
    return ResponseAction(
        id=_ACTION_ID,
        incident_id=_INCIDENT_ID,
        type="BLOCK_IP",
        target=target,
        reason="Source IP is correlated with the incident and should be contained after approval.",
        risk="medium",
        status=status,
        requested_by="AI",
        approved_by=None,
        approved_at=None,
        rejected_by=None,
        rejected_at=None,
        rejection_reason=None,
        duration_minutes=30,
        policy_result={"allowed": True, "reasons": [], "normalized_target": target},
        execution_result=None,
        created_at=_NOW,
        updated_at=_NOW,
    )


def test_policy_allows_public_block_ip_and_normalizes_target():
    result = ResponseActionPolicy().validate(
        ResponseActionCreate(type="BLOCK_IP", target=" 8.8.8.8 ", reason="contain suspicious source")
    )

    assert result.allowed is True
    assert result.normalized_target == "8.8.8.8"
    assert result.reasons == []


def test_policy_rejects_unsupported_actions_invalid_ips_and_protected_ranges():
    policy = ResponseActionPolicy()

    unsupported = policy.validate(ResponseActionCreate(type="DISABLE_USER", target="root", reason="not yet enabled"))
    invalid = policy.validate(ResponseActionCreate(type="BLOCK_IP", target="not-an-ip", reason="invalid"))
    localhost = policy.validate(ResponseActionCreate(type="BLOCK_IP", target="127.0.0.1", reason="bad target"))
    private = policy.validate(ResponseActionCreate(type="BLOCK_IP", target="10.10.10.50", reason="management subnet"))

    assert unsupported.allowed is False
    assert "not enabled" in unsupported.reasons[0]
    assert invalid.allowed is False
    assert "valid single IP" in invalid.reasons[0]
    assert localhost.allowed is False
    assert any("localhost" in reason for reason in localhost.reasons)
    assert private.allowed is False
    assert any("private management subnet" in reason for reason in private.reasons)


def test_create_for_incident_persists_pending_action_after_policy_validation():
    async def scenario():
        db = _MemoryDb(incident=_incident())
        service = ResponseActionService(clock=lambda: _NOW)

        output = await service.create_for_incident(
            db,
            _INCIDENT_ID,
            ResponseActionCreate(type="BLOCK_IP", target="8.8.8.8", reason="contain suspicious source", duration_minutes=30),
        )

        assert output is not None
        assert output.status == "PENDING"
        assert output.target == "8.8.8.8"
        assert output.policy_result["allowed"] is True
        assert db.commits == 1
        assert len(db.added) == 1

    import asyncio

    asyncio.run(scenario())


def test_create_rejects_policy_failure_and_missing_incident():
    async def scenario():
        service = ResponseActionService(clock=lambda: _NOW)
        assert await service.create_for_incident(_MemoryDb(), _INCIDENT_ID, ResponseActionCreate(type="BLOCK_IP", target="8.8.8.8", reason="x")) is None
        with pytest.raises(ResponseActionConflict):
            await service.create_for_incident(
                _MemoryDb(incident=_incident()),
                _INCIDENT_ID,
                ResponseActionCreate(type="BLOCK_IP", target="10.10.10.50", reason="private target"),
            )

    import asyncio

    asyncio.run(scenario())


def test_approve_and_reject_require_pending_state_and_never_execute():
    async def scenario():
        action = _action()
        db = _MemoryDb(incident=_incident(), actions=[action])
        service = ResponseActionService(clock=lambda: _NOW)

        approved = await service.approve(db, _ACTION_ID, ResponseActionApprovalRequest(approved_by="analyst"))

        assert approved is not None
        assert approved.status == "APPROVED"
        assert approved.approved_by == "analyst"
        assert approved.execution_result is None
        with pytest.raises(ResponseActionConflict):
            await service.reject(db, _ACTION_ID, ResponseActionRejectRequest(rejected_by="analyst", reason="too late"))

    import asyncio

    asyncio.run(scenario())


def test_reject_records_human_reason():
    async def scenario():
        action = _action()
        db = _MemoryDb(incident=_incident(), actions=[action])
        service = ResponseActionService(clock=lambda: _NOW)

        rejected = await service.reject(db, _ACTION_ID, ResponseActionRejectRequest(rejected_by="analyst", reason="known scanner"))

        assert rejected is not None
        assert rejected.status == "REJECTED"
        assert rejected.rejected_by == "analyst"
        assert rejected.rejection_reason == "known scanner"
        assert rejected.execution_result is None

    import asyncio

    asyncio.run(scenario())


def test_execute_requires_approved_action_and_records_offline_wazuh_result():
    async def scenario():
        incident = _incident()
        action = _action(status="APPROVED")
        db = _MemoryDb(incident=incident, actions=[action])
        service = ResponseActionService(clock=lambda: _NOW)

        executed = await service.execute(db, _ACTION_ID)

        assert executed is not None
        assert executed.status == "SUCCESS"
        assert executed.execution_result["provider"] == "wazuh-active-response-offline"
        assert executed.execution_result["metadata"]["command"] == "firewall-drop"
        assert incident.status == "NEW"
        assert executed.execution_result["metadata"]["execution_mode"] == "offline"
        assert executed.execution_result["metadata"]["containment_verified"] is False

    import asyncio

    asyncio.run(scenario())


def test_execute_rejects_unapproved_action_and_marks_provider_failure():
    async def scenario():
        pending = _action(status="PENDING")
        db = _MemoryDb(incident=_incident(), actions=[pending])
        service = ResponseActionService(clock=lambda: _NOW)
        with pytest.raises(ResponseActionConflict):
            await service.execute(db, _ACTION_ID)

        approved = _action(status="APPROVED")
        failing_db = _MemoryDb(incident=_incident(), actions=[approved])
        failing = ResponseActionService(siem_provider=_FailingSIEMProvider(), clock=lambda: _NOW)
        with pytest.raises(ResponseActionConflict):
            await failing.execute(failing_db, _ACTION_ID)
        assert approved.status == "FAILED"
        assert approved.execution_result["status"] == "FAILED"
        assert "wazuh unavailable" in approved.execution_result["error"]

    import asyncio

    asyncio.run(scenario())
