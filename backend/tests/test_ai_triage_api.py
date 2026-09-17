from datetime import datetime, timezone
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from app.api.incidents import get_ai_triage_service
from app.core.database import get_db
from app.main import app
from app.schemas.ai_triage import AITriageResult, AITriageRunOut
from app.schemas.incident import IncidentDetailOut, IncidentOut
from app.services.ai_triage import AITriageValidationError

_INCIDENT_ID = UUID("00000000-0000-0000-0000-000000000200")
_ALERT_ID = UUID("00000000-0000-0000-0000-000000000100")
_NOW = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)


class _RouteService:
    def __init__(self) -> None:
        self.run_calls = []
        self.analysis_calls = []
        self.missing = False
        self.fail_validation = False
        self.has_analysis = True

    async def run(self, _db, incident_id: UUID, request) -> AITriageRunOut | None:
        self.run_calls.append((incident_id, request))
        if self.missing:
            return None
        if self.fail_validation:
            raise AITriageValidationError("invalid structured output")
        return AITriageRunOut(
            incident_id=incident_id,
            provider_mode="offline",
            stored=request.persist,
            result=_triage_result(),
            incident=_incident_detail(),
        )

    async def stored_analysis(self, _db, incident_id: UUID):
        self.analysis_calls.append(incident_id)
        if self.missing:
            return None
        if self.fail_validation:
            raise AITriageValidationError("invalid stored analysis")
        return {"incident_id": incident_id, "has_analysis": self.has_analysis, "result": _triage_result() if self.has_analysis else None}


class _FakeDb:
    pass


def _incident_out() -> IncidentOut:
    return IncidentOut(
        id=_INCIDENT_ID,
        title="Possible brute-force authentication chain for root on linux-server",
        status="NEW",
        severity="high",
        confidence=85,
        first_seen=_NOW,
        last_seen=_NOW,
        primary_host="linux-server",
        primary_user="root",
        primary_src_ip="10.10.10.50",
        mitre_ids=["T1110"],
        alert_count=10,
        ai_summary="Offline AI triage classified this incident as true_positive.",
        ai_analysis=None,
        created_at=_NOW,
        updated_at=_NOW,
    )


def _incident_detail() -> IncidentDetailOut:
    return IncidentDetailOut(**_incident_out().model_dump(), alert_ids=[_ALERT_ID])


def _triage_result() -> AITriageResult:
    return AITriageResult(
        title="AI triage: brute force",
        classification="true_positive",
        severity="high",
        confidence=88,
        summary="Correlated SSH authentication activity should be investigated.",
        attack_chain=["Failed SSH authentication"],
        mitre=[{"technique_id": "T1110", "reason": "Repeated authentication failures"}],
        evidence=[{"alert_id": _ALERT_ID, "field_path": "network.src_ip", "reason": "Primary source IP pivot"}],
        ioc_analysis=[],
        hypotheses=["Brute-force activity"],
        recommended_investigation=["Review SSH logs"],
        recommended_actions=["Consider blocking the source IP after analyst approval"],
        false_positive_probability=12,
        needs_human_review=True,
    )


@pytest.fixture
def api_client():
    previous_overrides = dict(app.dependency_overrides)
    state = {"service": _RouteService()}

    async def override_get_db():
        yield _FakeDb()

    def override_service():
        return state["service"]

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_ai_triage_service] = override_service
    try:
        yield TestClient(app), state
    finally:
        app.dependency_overrides = previous_overrides


def test_run_ai_triage_returns_validated_result(api_client):
    client, state = api_client

    response = client.post(f"/api/v1/incidents/{_INCIDENT_ID}/ai-triage", json={"force": True})

    assert response.status_code == 200
    body = response.json()
    assert body["incident_id"] == str(_INCIDENT_ID)
    assert body["provider_mode"] == "offline"
    assert body["result"]["summary"] == "Correlated SSH authentication activity should be investigated."
    assert body["result"]["classification"] == "true_positive"
    assert body["incident"]["alert_ids"] == [str(_ALERT_ID)]
    assert state["service"].run_calls[0][0] == _INCIDENT_ID
    assert state["service"].run_calls[0][1].force is True


def test_phase_10_triage_alias_runs_ai_triage(api_client):
    client, state = api_client

    response = client.post(f"/api/v1/incidents/{_INCIDENT_ID}/triage", json={"persist": False})

    assert response.status_code == 200
    assert response.json()["stored"] is False
    assert state["service"].run_calls[0][1].force is False
    assert state["service"].run_calls[0][1].persist is False


def test_phase_10_reanalyze_forces_ai_triage(api_client):
    client, state = api_client

    response = client.post(f"/api/v1/incidents/{_INCIDENT_ID}/reanalyze", json={"persist": False})

    assert response.status_code == 200
    assert state["service"].run_calls[0][1].force is True
    assert state["service"].run_calls[0][1].persist is False


def test_get_incident_analysis_returns_stored_structured_output(api_client):
    client, state = api_client

    response = client.get(f"/api/v1/incidents/{_INCIDENT_ID}/analysis")

    assert response.status_code == 200
    body = response.json()
    assert body["incident_id"] == str(_INCIDENT_ID)
    assert body["has_analysis"] is True
    assert body["result"]["classification"] == "true_positive"
    assert state["service"].analysis_calls == [_INCIDENT_ID]


def test_get_incident_analysis_handles_missing_and_invalid_analysis(api_client):
    client, state = api_client
    state["service"].has_analysis = False

    response = client.get(f"/api/v1/incidents/{_INCIDENT_ID}/analysis")

    assert response.status_code == 200
    assert response.json()["has_analysis"] is False
    assert response.json()["result"] is None

    state["service"].missing = True
    assert client.get(f"/api/v1/incidents/{_INCIDENT_ID}/analysis").status_code == 404

    state["service"].missing = False
    state["service"].fail_validation = True
    assert client.get(f"/api/v1/incidents/{_INCIDENT_ID}/analysis").status_code == 502


def test_run_ai_triage_uses_default_request_body(api_client):
    client, state = api_client

    response = client.post(f"/api/v1/incidents/{_INCIDENT_ID}/ai-triage")

    assert response.status_code == 200
    assert state["service"].run_calls[0][1].force is False
    assert state["service"].run_calls[0][1].persist is True


def test_run_ai_triage_returns_404_for_missing_incident(api_client):
    client, state = api_client
    state["service"].missing = True

    response = client.post(f"/api/v1/incidents/{_INCIDENT_ID}/ai-triage")

    assert response.status_code == 404


def test_run_ai_triage_maps_provider_validation_failure_to_502(api_client):
    client, state = api_client
    state["service"].fail_validation = True

    response = client.post(f"/api/v1/incidents/{_INCIDENT_ID}/ai-triage")

    assert response.status_code == 502


def test_run_ai_triage_validates_request_body(api_client):
    client, _state = api_client

    response = client.post(f"/api/v1/incidents/{_INCIDENT_ID}/ai-triage", json={"force": "not-a-bool"})

    assert response.status_code == 422
