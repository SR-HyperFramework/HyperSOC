from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.api.dashboard import get_dashboard_service
from app.core.database import get_db
from app.main import app
from app.schemas.dashboard import DashboardMitreTechniqueOut, DashboardSummaryOut, DashboardTimelineOut, DashboardTimelinePointOut

_NOW = datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc)


class _RouteDashboardService:
    def __init__(self) -> None:
        self.summary_calls = 0
        self.mitre_calls = []
        self.timeline_calls = []

    async def summary(self, _db) -> DashboardSummaryOut:
        self.summary_calls += 1
        return DashboardSummaryOut(
            critical_incidents=1,
            high_incidents=2,
            open_incidents=3,
            alerts_last_24h=4,
            total_incidents=5,
            total_alerts=6,
        )

    async def mitre(self, _db, *, limit: int = 10) -> list[DashboardMitreTechniqueOut]:
        self.mitre_calls.append(limit)
        return [DashboardMitreTechniqueOut(technique_id="T1110", alert_count=4, incident_count=1, total_count=5)]

    async def timeline(self, _db, *, hours: int = 24, bucket_minutes: int = 60) -> DashboardTimelineOut:
        self.timeline_calls.append((hours, bucket_minutes))
        return DashboardTimelineOut(
            bucket_minutes=bucket_minutes,
            points=[DashboardTimelinePointOut(bucket_start=_NOW, alert_count=4, incident_count=1)],
        )


class _FakeDb:
    pass


@pytest.fixture
def api_client():
    previous_overrides = dict(app.dependency_overrides)
    state = {"service": _RouteDashboardService()}

    async def override_get_db():
        yield _FakeDb()

    def override_service():
        return state["service"]

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_dashboard_service] = override_service
    try:
        yield TestClient(app), state
    finally:
        app.dependency_overrides = previous_overrides


def test_dashboard_summary_returns_counts(api_client):
    client, state = api_client

    response = client.get("/api/v1/dashboard/summary")

    assert response.status_code == 200
    assert response.json()["critical_incidents"] == 1
    assert response.json()["alerts_last_24h"] == 4
    assert state["service"].summary_calls == 1


def test_dashboard_mitre_validates_limit_and_returns_ranked_shape(api_client):
    client, state = api_client

    response = client.get("/api/v1/dashboard/mitre?limit=5")

    assert response.status_code == 200
    assert response.json()[0] == {
        "technique_id": "T1110",
        "alert_count": 4,
        "incident_count": 1,
        "total_count": 5,
    }
    assert state["service"].mitre_calls == [5]
    assert client.get("/api/v1/dashboard/mitre?limit=0").status_code == 422
    assert client.get("/api/v1/dashboard/mitre?limit=51").status_code == 422


def test_dashboard_timeline_validates_window_and_returns_points(api_client):
    client, state = api_client

    response = client.get("/api/v1/dashboard/timeline?hours=12&bucket_minutes=30")

    assert response.status_code == 200
    assert response.json()["bucket_minutes"] == 30
    assert response.json()["points"][0]["alert_count"] == 4
    assert state["service"].timeline_calls == [(12, 30)]
    assert client.get("/api/v1/dashboard/timeline?hours=0").status_code == 422
    assert client.get("/api/v1/dashboard/timeline?bucket_minutes=4").status_code == 422
