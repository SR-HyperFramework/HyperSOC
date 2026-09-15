import time

from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.database import get_db
from app.core.security import sign_payload
from app.main import app
from app.models.alert import Alert


class _FakeResult:
    def __init__(self, value):
        self._value = value

    def scalar(self):
        return self._value


class FakeSession:
    def __init__(self):
        self.added = []

    async def scalar(self, *_args, **_kwargs):
        return None

    async def get(self, *_args, **_kwargs):
        return None

    async def commit(self):
        pass

    async def refresh(self, row):
        row.id = "00000000-0000-0000-0000-000000000000"
        row.created_at = "2026-09-11T00:00:00Z"

    def add(self, row):
        self.added.append(row)


async def _override_get_db():
    yield FakeSession()


app.dependency_overrides[get_db] = _override_get_db
client = TestClient(app)


def _signed_headers(body: bytes) -> dict:
    timestamp = str(time.time())
    signature = sign_payload(settings.app_secret_key, timestamp, body)
    return {"X-SOC-Timestamp": timestamp, "X-SOC-Signature": signature}


def test_post_alert_rejects_missing_signature():
    response = client.post("/api/v1/alerts", json={"timestamp": "2026-09-11T00:00:00Z"})
    assert response.status_code == 401


def test_post_alert_rejects_bad_signature():
    body = b'{"timestamp":"2026-09-11T00:00:00Z"}'
    headers = {"X-SOC-Timestamp": str(time.time()), "X-SOC-Signature": "deadbeef"}
    response = client.post("/api/v1/alerts", data=body, headers=headers)
    assert response.status_code == 401


def test_post_alert_rejects_non_finite_timestamp():
    body = b'{"timestamp":"2026-09-11T00:00:00Z"}'
    headers = {
        "X-SOC-Timestamp": "nan",
        "X-SOC-Signature": sign_payload(settings.app_secret_key, "nan", body),
    }
    response = client.post("/api/v1/alerts", data=body, headers=headers)
    assert response.status_code == 401


def test_post_alert_rejects_malformed_signature():
    body = b'{"timestamp":"2026-09-11T00:00:00Z"}'
    headers = {"X-SOC-Timestamp": str(time.time()), "X-SOC-Signature": "not-a-signature"}
    response = client.post("/api/v1/alerts", data=body, headers=headers)
    assert response.status_code == 401


def test_post_alert_rejects_stale_timestamp():
    body = b'{"timestamp":"2026-09-11T00:00:00Z"}'
    timestamp = str(time.time() - settings.ingest_signature_max_skew_seconds - 1)
    headers = {
        "X-SOC-Timestamp": timestamp,
        "X-SOC-Signature": sign_payload(settings.app_secret_key, timestamp, body),
    }
    response = client.post("/api/v1/alerts", data=body, headers=headers)
    assert response.status_code == 401


def test_post_alert_rejects_malformed_signed_json():
    body = b"not-json"
    response = client.post("/api/v1/alerts", data=body, headers=_signed_headers(body))
    assert response.status_code == 400


def test_post_alert_rejects_oversized_payload(monkeypatch):
    monkeypatch.setattr(settings, "ingest_max_body_bytes", 10)
    body = b'{"timestamp":"2026-09-11T00:00:00Z"}'
    response = client.post("/api/v1/alerts", data=body, headers=_signed_headers(body))
    assert response.status_code == 413


def test_list_alerts_validates_pagination():
    assert client.get("/api/v1/alerts?limit=0").status_code == 422
    assert client.get("/api/v1/alerts?limit=101").status_code == 422
    assert client.get("/api/v1/alerts?offset=-1").status_code == 422


def test_get_alert_rejects_invalid_uuid():
    assert client.get("/api/v1/alerts/not-a-uuid").status_code == 422


def test_post_alert_accepts_valid_signature():
    payload = {
        "source": "wazuh",
        "timestamp": "2026-09-11T00:00:00Z",
        "agent": {"id": "001", "name": "Win10-Endpoint", "ip": "192.168.121.131"},
        "rule": {"id": "5710", "level": 5, "description": "sshd auth failed", "mitre_ids": ["T1110"]},
        "event": {"src_ip": "10.10.10.50", "username": "root"},
        "raw": {"id": "123"},
    }
    import json

    body = json.dumps(payload).encode()
    response = client.post("/api/v1/alerts", data=body, headers=_signed_headers(body))
    assert response.status_code == 201
    assert response.json()["rule_id"] == "5710"
    assert response.json()["mitre_ids"] == ["T1110"]
