from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import UUID, uuid4

from app.models.alert import Alert
from app.models.incident import Incident
from app.schemas.incident import CorrelationRunRequest
from app.schemas.normalized_alert import NormalizedAlert, NormalizedHost, NormalizedNetwork
from app.services.correlation import CorrelationService, ThreatIntelSummary


class _Clock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


class _MemoryCorrelationService(CorrelationService):
    def __init__(self, alerts: list[Alert], *, clock: _Clock, threat_intel=None) -> None:
        super().__init__(clock=clock)
        self.alerts = alerts
        self.threat_intel = threat_intel or {}
        self.incidents: dict[UUID, Incident] = {}
        self.links: list[tuple[UUID, UUID]] = []

    async def _load_alerts(self, _db, *, since: datetime) -> list[Alert]:
        return [alert for alert in self.alerts if alert.timestamp >= since]

    async def _threat_intel_summaries(self, _db, alert_id: UUID) -> list[ThreatIntelSummary]:
        return list(self.threat_intel.get(alert_id, []))

    async def _upsert_incident(self, db, draft):
        existing = await self._find_existing_incident(db, draft)
        if existing is None:
            incident = Incident(
                id=uuid4(),
                title=draft.title,
                status="NEW",
                severity=draft.severity,
                confidence=draft.confidence,
                first_seen=draft.first_seen,
                last_seen=draft.last_seen,
                primary_host=draft.primary_host,
                primary_user=draft.primary_user,
                primary_src_ip=draft.primary_src_ip,
                mitre_ids=draft.mitre_ids,
                alert_count=0,
            )
            self.incidents[incident.id] = incident
            created = True
        else:
            incident = existing
            created = False

        await self._ensure_incident_alerts(db, incident.id, draft.alert_ids)
        await self._update_incident_fields(db, incident, draft)
        return SimpleNamespace(incident=incident, created=created)

    async def _find_existing_incident(self, _db, draft):
        for incident_id, alert_id in self.links:
            if alert_id in draft.alert_ids:
                incident = self.incidents[incident_id]
                if incident.status in {"NEW", "TRIAGED", "INVESTIGATING"}:
                    return incident

        for incident in self.incidents.values():
            if incident.status not in {"NEW", "TRIAGED", "INVESTIGATING"}:
                continue
            if incident.primary_host != draft.primary_host or incident.primary_src_ip != draft.primary_src_ip:
                continue
            if incident.first_seen <= draft.last_seen and incident.last_seen >= draft.first_seen:
                return incident
        return None

    async def _ensure_incident_alerts(self, _db, incident_id: UUID, alert_ids: list[UUID]) -> None:
        for alert_id in alert_ids:
            link = (incident_id, alert_id)
            if link not in self.links:
                self.links.append(link)

    async def _incident_alert_ids(self, _db, incident_id: UUID) -> list[UUID]:
        return [alert_id for linked_incident_id, alert_id in self.links if linked_incident_id == incident_id]

    async def _commit(self, _db) -> None:
        return None

    async def _lock_writes(self, _db) -> None:
        return None

    async def _finish_run(self, _db) -> None:
        return None

    async def _refresh(self, _db, _row) -> None:
        return None


def _alert(
    when: datetime,
    *,
    alert_id: UUID | None = None,
    agent_id: str = "001",
    agent_name: str = "linux-server",
    src_ip: str = "10.10.10.50",
    username: str = "root",
    rule_id: str = "5710",
    rule_level: int = 5,
    rule_description: str = "sshd auth failed",
    mitre_ids: list[str] | None = None,
    file_hash: str | None = None,
    raw_event: dict | None = None,
) -> Alert:
    return Alert(
        id=alert_id or uuid4(),
        external_id=None,
        source="wazuh",
        timestamp=when,
        agent_id=agent_id,
        agent_name=agent_name,
        rule_id=rule_id,
        rule_level=rule_level,
        rule_description=rule_description,
        mitre_ids=mitre_ids or [],
        groups=["sshd"],
        src_ip=src_ip,
        dst_ip=None,
        src_port=None,
        dst_port=22,
        username=username,
        process_name=None,
        process_command_line=None,
        file_path=None,
        file_hash=file_hash,
        raw_event=raw_event or {},
        fingerprint=str(uuid4()),
        status="received",
    )


def _ssh_raw(when: datetime, *, outcome: str, src_ip: str = "10.10.10.50", username: str = "root") -> dict:
    return {
        "id": str(uuid4()),
        "timestamp": when.isoformat(),
        "agent": {"id": "001", "name": "linux-server"},
        "rule": {"id": "5710", "level": 8, "description": f"sshd auth {outcome}", "groups": ["sshd"], "mitre": {"id": ["T1110"]}},
        "data": {"srcip": src_ip, "srcuser": username, "status": outcome},
    }


def test_ten_related_alerts_become_one_incident():
    async def scenario():
        start = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)
        alerts = [_alert(start + timedelta(seconds=index * 30)) for index in range(10)]
        service = _MemoryCorrelationService(alerts, clock=_Clock(start + timedelta(minutes=15)))

        result = await service.run(None, CorrelationRunRequest(lookback_minutes=60, window_minutes=10))

        assert result.created_count == 1
        assert result.updated_count == 0
        assert len(result.incidents) == 1
        incident = result.incidents[0]
        assert incident.alert_count == 10
        assert incident.primary_host == "linux-server"
        assert incident.primary_src_ip == "10.10.10.50"
        assert set(incident.alert_ids) == {alert.id for alert in alerts}

    import asyncio

    asyncio.run(scenario())


def test_unrelated_alerts_do_not_merge_across_pivots_or_window():
    async def scenario():
        start = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)
        alerts = [
            _alert(start, src_ip="10.10.10.50"),
            _alert(start + timedelta(minutes=20), src_ip="10.10.10.50"),
            _alert(start + timedelta(minutes=1), src_ip="10.10.10.51"),
        ]
        service = _MemoryCorrelationService(alerts, clock=_Clock(start + timedelta(minutes=30)))

        result = await service.run(None, CorrelationRunRequest(lookback_minutes=60, window_minutes=10))

        assert result.created_count == 0
        assert result.incidents == []

    import asyncio

    asyncio.run(scenario())


def test_correlation_runs_are_idempotent():
    async def scenario():
        start = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)
        alerts = [_alert(start + timedelta(seconds=index * 30)) for index in range(10)]
        service = _MemoryCorrelationService(alerts, clock=_Clock(start + timedelta(minutes=15)))
        request = CorrelationRunRequest(lookback_minutes=60, window_minutes=10)

        first = await service.run(None, request)
        second = await service.run(None, request)

        assert first.created_count == 1
        assert second.created_count == 0
        assert second.updated_count == 1
        assert len(service.links) == 10
        assert second.incidents[0].alert_count == 10

    import asyncio

    asyncio.run(scenario())


def test_brute_force_chain_sets_expected_title_severity_and_mitre_ids():
    async def scenario():
        start = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)
        alerts = [
            _alert(start + timedelta(minutes=index), raw_event=_ssh_raw(start + timedelta(minutes=index), outcome="failed"))
            for index in range(3)
        ]
        alerts.append(_alert(start + timedelta(minutes=4), raw_event=_ssh_raw(start + timedelta(minutes=4), outcome="success")))
        service = _MemoryCorrelationService(alerts, clock=_Clock(start + timedelta(minutes=10)))

        result = await service.run(None, CorrelationRunRequest(lookback_minutes=60, window_minutes=10))

        incident = result.incidents[0]
        assert "brute-force" in incident.title
        assert incident.severity == "high"
        assert incident.primary_user == "root"
        assert incident.mitre_ids == ["T1110"]

    import asyncio

    asyncio.run(scenario())


def test_malicious_hash_enrichment_raises_malware_incident_severity():
    async def scenario():
        start = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)
        malicious = _alert(start, file_hash="A" * 64, rule_description="file created")
        executed = _alert(start + timedelta(minutes=1), rule_description="process executed")
        threat_intel = {
            malicious.id: [
                ThreatIntelSummary(
                    verdict="malicious",
                    risk_score=85,
                    evidence_path="file.hash",
                    indicator_type="hash",
                    indicator="A" * 64,
                )
            ]
        }
        service = _MemoryCorrelationService([malicious, executed], clock=_Clock(start + timedelta(minutes=5)), threat_intel=threat_intel)

        result = await service.run(None, CorrelationRunRequest(lookback_minutes=60, window_minutes=10))

        incident = result.incidents[0]
        assert "malware" in incident.title
        assert incident.severity == "critical"
        assert incident.confidence >= 70

    import asyncio

    asyncio.run(scenario())


def test_correlation_uses_normalized_alert_bridge(monkeypatch):
    async def scenario():
        start = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)
        alerts = [_alert(start + timedelta(minutes=index), raw_event={"do_not_parse_directly": True}) for index in range(2)]
        calls = []

        def fake_normalize(alert: Alert) -> NormalizedAlert:
            calls.append(alert.id)
            return NormalizedAlert(
                id=alert.id,
                timestamp=alert.timestamp,
                host=NormalizedHost(id=alert.agent_id, name=alert.agent_name),
                network=NormalizedNetwork(src_ip=alert.src_ip),
            )

        monkeypatch.setattr("app.services.correlation.normalize_persisted_alert", fake_normalize)
        service = _MemoryCorrelationService(alerts, clock=_Clock(start + timedelta(minutes=5)))

        await service.run(None, CorrelationRunRequest(lookback_minutes=60, window_minutes=10))

        assert calls == [alert.id for alert in alerts]

    import asyncio

    asyncio.run(scenario())
