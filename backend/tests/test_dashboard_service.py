from datetime import datetime, timedelta, timezone
from uuid import UUID

from app.models.alert import Alert
from app.models.incident import Incident
from app.services.dashboard import DashboardService

_NOW = datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc)


class _ScalarResult:
    def __init__(self, rows):
        self._rows = list(rows)

    def all(self):
        return list(self._rows)


class _MemoryDashboardDb:
    def __init__(self, *, alerts=None, incidents=None) -> None:
        self.alerts = alerts or []
        self.incidents = incidents or []

    async def scalar(self, statement):
        text = str(statement)
        params = statement.compile().params
        if "FROM incidents" in text:
            rows = self.incidents
            if "incidents.severity =" in text:
                severity = next((value for key, value in params.items() if key.startswith("severity")), None)
                rows = [row for row in rows if row.severity == severity]
            if "incidents.status IN" in text:
                statuses = next((value for key, value in params.items() if key.startswith("status")), {"NEW", "TRIAGED", "INVESTIGATING"})
                rows = [row for row in rows if row.status in set(statuses)]
            return len(rows)
        if "FROM alerts" in text:
            rows = self.alerts
            if "alerts.timestamp >=" in text:
                since = next((value for key, value in params.items() if key.startswith("timestamp")), _NOW - timedelta(hours=24))
                rows = [row for row in rows if row.timestamp >= since]
            return len(rows)
        return 0

    async def scalars(self, statement):
        text = str(statement)
        if "alerts.mitre_ids" in text:
            return _ScalarResult([row.mitre_ids for row in self.alerts])
        if "incidents.mitre_ids" in text:
            return _ScalarResult([row.mitre_ids for row in self.incidents])
        if "alerts.timestamp" in text:
            return _ScalarResult([row.timestamp for row in self.alerts if row.timestamp >= _NOW - timedelta(hours=24)])
        if "incidents.first_seen" in text:
            return _ScalarResult([row.first_seen for row in self.incidents if row.first_seen >= _NOW - timedelta(hours=24)])
        return _ScalarResult([])


def _alert(index: int, *, hours_ago: int, mitre_ids=None) -> Alert:
    return Alert(
        id=UUID(f"00000000-0000-0000-0000-{index:012d}"),
        external_id=str(index),
        source="wazuh",
        timestamp=_NOW - timedelta(hours=hours_ago),
        agent_id="001",
        agent_name="linux-server",
        rule_id="5710",
        rule_level=8,
        rule_description="sshd auth failed",
        mitre_ids=mitre_ids or [],
        groups=["sshd"],
        raw_event={},
        fingerprint=f"fingerprint-{index}",
        status="received",
        created_at=_NOW,
    )


def _incident(index: int, *, status: str, severity: str, hours_ago: int, mitre_ids=None) -> Incident:
    return Incident(
        id=UUID(f"00000000-0000-0001-0000-{index:012d}"),
        title=f"Incident {index}",
        status=status,
        severity=severity,
        confidence=80,
        first_seen=_NOW - timedelta(hours=hours_ago),
        last_seen=_NOW - timedelta(hours=hours_ago),
        primary_host="linux-server",
        primary_user="root",
        primary_src_ip="10.10.10.50",
        mitre_ids=mitre_ids or [],
        alert_count=1,
        ai_summary=None,
        ai_analysis=None,
        created_at=_NOW,
        updated_at=_NOW,
    )


def test_summary_counts_incident_and_recent_alert_buckets():
    async def scenario():
        db = _MemoryDashboardDb(
            alerts=[_alert(1, hours_ago=1), _alert(2, hours_ago=25)],
            incidents=[
                _incident(1, status="NEW", severity="critical", hours_ago=1),
                _incident(2, status="INVESTIGATING", severity="high", hours_ago=2),
                _incident(3, status="RESOLVED", severity="high", hours_ago=3),
            ],
        )
        service = DashboardService(clock=lambda: _NOW)

        output = await service.summary(db)

        assert output.critical_incidents == 1
        assert output.high_incidents == 2
        assert output.open_incidents == 2
        assert output.alerts_last_24h == 1
        assert output.total_incidents == 3
        assert output.total_alerts == 2

    import asyncio

    asyncio.run(scenario())


def test_mitre_aggregates_alerts_and_incidents_by_technique():
    async def scenario():
        db = _MemoryDashboardDb(
            alerts=[_alert(1, hours_ago=1, mitre_ids=["T1110"]), _alert(2, hours_ago=1, mitre_ids=["T1110", "T1078"])],
            incidents=[_incident(1, status="NEW", severity="critical", hours_ago=1, mitre_ids=["T1110"])],
        )
        service = DashboardService(clock=lambda: _NOW)

        output = await service.mitre(db, limit=10)

        assert output[0].technique_id == "T1110"
        assert output[0].alert_count == 2
        assert output[0].incident_count == 1
        assert output[0].total_count == 3
        assert output[1].technique_id == "T1078"

    import asyncio

    asyncio.run(scenario())


def test_timeline_buckets_alerts_and_incidents():
    async def scenario():
        db = _MemoryDashboardDb(
            alerts=[_alert(1, hours_ago=1), _alert(2, hours_ago=25)],
            incidents=[_incident(1, status="NEW", severity="critical", hours_ago=1)],
        )
        service = DashboardService(clock=lambda: _NOW)

        output = await service.timeline(db, hours=24, bucket_minutes=60)

        assert output.bucket_minutes == 60
        assert len(output.points) == 1
        assert output.points[0].alert_count == 1
        assert output.points[0].incident_count == 1

    import asyncio

    asyncio.run(scenario())
