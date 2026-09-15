from datetime import datetime, timezone
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from app.api.threat_intel import get_threat_intel_service
from app.core.database import get_db
from app.main import app
from app.models.alert import Alert
from app.schemas.threat_intel import AlertThreatIntelOut, AlertThreatIntelItemOut, ThreatIntelProviderResult, ThreatIntelResultOut
from app.services.threat_intel.indicators import InvalidIndicatorError

_ALERT_ID = UUID("00000000-0000-0000-0000-000000000100")


class _FakeDb:
    def __init__(self, alert: Alert | None = None) -> None:
        self.alert = alert

    async def get(self, model, item_id):
        if model is Alert and item_id == _ALERT_ID:
            return self.alert
        return None


class _RouteService:
    def __init__(self) -> None:
        self.lookup_calls = []
        self.enriched_alerts = []
        self.read_alerts = []

    async def lookup(self, _db, indicator_type: str, indicator: str, *, refresh: bool = False) -> ThreatIntelResultOut:
        self.lookup_calls.append((indicator_type, indicator, refresh))
        if indicator == "bad-indicator":
            raise InvalidIndicatorError("invalid test indicator")
        return ThreatIntelResultOut(
            indicator="10.10.10.50",
            type="ip",
            providers={
                "offline": ThreatIntelProviderResult(
                    provider="offline",
                    verdict="benign",
                    risk_score=0,
                    confidence=100,
                    summary="Non-routable, local, or reserved IP address",
                )
            },
            risk_score=0,
            verdict="benign",
            cached=False,
            cached_until=datetime(2026, 9, 16, 18, 0, tzinfo=timezone.utc),
            last_lookup_at=datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc),
        )

    async def enrich_persisted_alert(self, _db, alert: Alert, *, refresh: bool = False) -> AlertThreatIntelOut:
        self.enriched_alerts.append((alert.id, refresh))
        return _alert_threat_intel_out(alert.id, cached=False)

    async def get_alert_enrichments(self, _db, alert_id: UUID) -> AlertThreatIntelOut:
        self.read_alerts.append(alert_id)
        return _alert_threat_intel_out(alert_id, cached=True)


def _alert_row() -> Alert:
    return Alert(
        id=_ALERT_ID,
        external_id="1700000000.1",
        source="wazuh",
        timestamp=datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc),
        agent_id="001",
        agent_name="linux-endpoint",
        rule_id="5710",
        rule_level=5,
        rule_description="sshd auth failed",
        mitre_ids=["T1110"],
        groups=["sshd"],
        src_ip="10.10.10.50",
        dst_ip=None,
        src_port=None,
        dst_port=22,
        username="root",
        process_name=None,
        process_command_line=None,
        file_path=None,
        file_hash=None,
        raw_event={
            "id": "1700000000.1",
            "timestamp": "2026-09-16T12:00:00Z",
            "agent": {"id": "001", "name": "linux-endpoint"},
            "rule": {"groups": ["sshd"], "description": "sshd auth failed"},
            "data": {"srcip": "10.10.10.50", "srcuser": "root"},
        },
        fingerprint="fingerprint",
        status="received",
    )


def _alert_threat_intel_out(alert_id: UUID, *, cached: bool) -> AlertThreatIntelOut:
    return AlertThreatIntelOut(
        alert_id=alert_id,
        indicators=[
            AlertThreatIntelItemOut(
                evidence_path="network.src_ip",
                indicator="10.10.10.50",
                type="ip",
                providers={
                    "offline": ThreatIntelProviderResult(
                        provider="offline",
                        verdict="benign",
                        risk_score=0,
                        confidence=100,
                        summary="Non-routable, local, or reserved IP address",
                    )
                },
                risk_score=0,
                verdict="benign",
                cached=cached,
            )
        ],
        max_risk_score=0,
        verdict="benign",
    )


@pytest.fixture
def api_client():
    previous_overrides = dict(app.dependency_overrides)
    state = {"db": _FakeDb(_alert_row()), "service": _RouteService()}

    async def override_get_db():
        yield state["db"]

    def override_service():
        return state["service"]

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_threat_intel_service] = override_service
    try:
        yield TestClient(app), state
    finally:
        app.dependency_overrides = previous_overrides


def test_lookup_indicator_returns_unified_result(api_client):
    client, state = api_client

    response = client.get("/api/v1/threat-intel/lookup?type=ip&indicator=10.10.10.50")

    assert response.status_code == 200
    body = response.json()
    assert body["indicator"] == "10.10.10.50"
    assert body["type"] == "ip"
    assert body["providers"]["offline"]["provider"] == "offline"
    assert body["verdict"] == "benign"
    assert state["service"].lookup_calls == [("ip", "10.10.10.50", False)]


def test_lookup_indicator_rejects_invalid_type(api_client):
    client, _state = api_client

    response = client.get("/api/v1/threat-intel/lookup?type=email&indicator=root@example.com")

    assert response.status_code == 422


def test_lookup_indicator_rejects_invalid_indicator(api_client):
    client, _state = api_client

    response = client.get("/api/v1/threat-intel/lookup?type=ip&indicator=bad-indicator")

    assert response.status_code == 422


def test_enrich_alert_returns_alert_level_threat_intel(api_client):
    client, state = api_client

    response = client.post(f"/api/v1/alerts/{_ALERT_ID}/threat-intel?refresh=true")

    assert response.status_code == 200
    body = response.json()
    assert body["alert_id"] == str(_ALERT_ID)
    assert body["indicators"][0]["evidence_path"] == "network.src_ip"
    assert body["indicators"][0]["providers"]["offline"]["provider"] == "offline"
    assert state["service"].enriched_alerts == [(_ALERT_ID, True)]


def test_get_alert_threat_intel_returns_persisted_associations(api_client):
    client, state = api_client

    response = client.get(f"/api/v1/alerts/{_ALERT_ID}/threat-intel")

    assert response.status_code == 200
    body = response.json()
    assert body["alert_id"] == str(_ALERT_ID)
    assert body["indicators"][0]["cached"] is True
    assert state["service"].read_alerts == [_ALERT_ID]


def test_alert_threat_intel_returns_404_for_missing_alert(api_client):
    client, state = api_client
    state["db"].alert = None

    response = client.post(f"/api/v1/alerts/{_ALERT_ID}/threat-intel")

    assert response.status_code == 404
