from datetime import datetime, timezone
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from app.api.incidents import get_correlation_service
from app.core.database import get_db
from app.main import app
from app.schemas.incident import CorrelationRunOut, IncidentDetailOut, IncidentOut

_INCIDENT_ID = UUID("00000000-0000-0000-0000-000000000200")
_ALERT_ID = UUID("00000000-0000-0000-0000-000000000100")
_NOW = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)


class _RouteService:
    def __init__(self) -> None:
        self.run_requests = []
        self.list_calls = []
        self.detail_calls = []
        self.missing = False

    async def run(self, _db, request) -> CorrelationRunOut:
        self.run_requests.append(request)
        incident = _incident_detail(alert_count=10)
        return CorrelationRunOut(created_count=1, updated_count=0, incidents=[incident])

    async def list_incidents(self, _db, *, status=None, limit=50, offset=0) -> list[IncidentOut]:
        self.list_calls.append((status, limit, offset))
        return [_incident_out(alert_count=10)]

    async def get_incident(self, _db, incident_id: UUID) -> IncidentDetailOut | None:
        self.detail_calls.append(incident_id)
        if self.missing:
            return None
        return _incident_detail(alert_count=10)


class _FakeDb:
    pass


def _incident_out(*, alert_count: int) -> IncidentOut:
    return IncidentOut(
        id=_INCIDENT_ID,
        title="Related alerts from 10.10.10.50 on linux-server",
        status="NEW",
        severity="high",
        confidence=85,
        first_seen=_NOW,
        last_seen=_NOW,
        primary_host="linux-server",
        primary_user="root",
        primary_src_ip="10.10.10.50",
        mitre_ids=["T1110"],
        alert_count=alert_count,
        ai_summary=None,
        ai_analysis=None,
        created_at=_NOW,
        updated_at=_NOW,
    )


def _incident_detail(*, alert_count: int) -> IncidentDetailOut:
    return IncidentDetailOut(**_incident_out(alert_count=alert_count).model_dump(), alert_ids=[_ALERT_ID])


@pytest.fixture
def api_client():
    previous_overrides = dict(app.dependency_overrides)
    state = {"service": _RouteService()}

    async def override_get_db():
        yield _FakeDb()

    def override_service():
        return state["service"]

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_correlation_service] = override_service
    try:
        yield TestClient(app), state
    finally:
        app.dependency_overrides = previous_overrides


def test_run_correlation_returns_created_incidents(api_client):
    client, state = api_client

    response = client.post(
        "/api/v1/correlation/run",
        json={"lookback_minutes": 120, "window_minutes": 10, "min_alerts": 2},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["created_count"] == 1
    assert body["updated_count"] == 0
    assert body["incidents"][0]["alert_count"] == 10
    assert body["incidents"][0]["alert_ids"] == [str(_ALERT_ID)]
    assert state["service"].run_requests[0].lookback_minutes == 120


def test_run_correlation_uses_default_body(api_client):
    client, state = api_client

    response = client.post("/api/v1/correlation/run")

    assert response.status_code == 200
    assert state["service"].run_requests[0].window_minutes == 10


def test_list_incidents_filters_and_paginates(api_client):
    client, state = api_client

    response = client.get("/api/v1/incidents?status=NEW&limit=20&offset=5")

    assert response.status_code == 200
    body = response.json()
    assert body[0]["id"] == str(_INCIDENT_ID)
    assert body[0]["mitre_ids"] == ["T1110"]
    assert state["service"].list_calls == [("NEW", 20, 5)]


def test_list_incidents_validates_status_and_pagination(api_client):
    client, _state = api_client

    assert client.get("/api/v1/incidents?status=CLOSED").status_code == 422
    assert client.get("/api/v1/incidents?limit=0").status_code == 422
    assert client.get("/api/v1/incidents?offset=-1").status_code == 422


def test_get_incident_returns_detail(api_client):
    client, state = api_client

    response = client.get(f"/api/v1/incidents/{_INCIDENT_ID}")

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == str(_INCIDENT_ID)
    assert body["alert_ids"] == [str(_ALERT_ID)]
    assert state["service"].detail_calls == [_INCIDENT_ID]


def test_get_incident_returns_404_for_missing_incident(api_client):
    client, state = api_client
    state["service"].missing = True

    response = client.get(f"/api/v1/incidents/{_INCIDENT_ID}")

    assert response.status_code == 404
