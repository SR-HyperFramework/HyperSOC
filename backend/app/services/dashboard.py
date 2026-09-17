from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.models.incident import Incident
from app.schemas.dashboard import (
    DashboardMitreTechniqueOut,
    DashboardSummaryOut,
    DashboardTimelineOut,
    DashboardTimelinePointOut,
)

_OPEN_INCIDENT_STATUSES = {"NEW", "TRIAGED", "INVESTIGATING"}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


@dataclass(frozen=True)
class _TimelineBucket:
    bucket_start: datetime
    alert_count: int = 0
    incident_count: int = 0


class DashboardService:
    """Read-only analyst dashboard aggregation service."""

    def __init__(self, *, clock=_utc_now) -> None:
        self._clock = clock

    async def summary(self, db: AsyncSession) -> DashboardSummaryOut:
        since = _as_utc(self._clock()) - timedelta(hours=24)
        return DashboardSummaryOut(
            critical_incidents=await self._count_incidents(db, severity="critical"),
            high_incidents=await self._count_incidents(db, severity="high"),
            open_incidents=await self._count_open_incidents(db),
            alerts_last_24h=await self._count_alerts_since(db, since),
            total_incidents=await self._count_all(db, Incident),
            total_alerts=await self._count_all(db, Alert),
        )

    async def mitre(self, db: AsyncSession, *, limit: int = 10) -> list[DashboardMitreTechniqueOut]:
        alert_counts: Counter[str] = Counter()
        incident_counts: Counter[str] = Counter()

        alert_rows = await db.scalars(select(Alert.mitre_ids))
        for values in alert_rows.all():
            for technique_id in values or []:
                if technique_id:
                    alert_counts[str(technique_id)] += 1

        incident_rows = await db.scalars(select(Incident.mitre_ids))
        for values in incident_rows.all():
            for technique_id in values or []:
                if technique_id:
                    incident_counts[str(technique_id)] += 1

        technique_ids = set(alert_counts) | set(incident_counts)
        rows = [
            DashboardMitreTechniqueOut(
                technique_id=technique_id,
                alert_count=alert_counts[technique_id],
                incident_count=incident_counts[technique_id],
                total_count=alert_counts[technique_id] + incident_counts[technique_id],
            )
            for technique_id in technique_ids
        ]
        rows.sort(key=lambda item: (-item.total_count, item.technique_id))
        return rows[:limit]

    async def timeline(self, db: AsyncSession, *, hours: int = 24, bucket_minutes: int = 60) -> DashboardTimelineOut:
        now = _as_utc(self._clock())
        since = now - timedelta(hours=hours)
        buckets: dict[datetime, _TimelineBucket] = {}

        alert_rows = await db.scalars(select(Alert.timestamp).where(Alert.timestamp >= since).order_by(Alert.timestamp.asc()))
        for timestamp in alert_rows.all():
            bucket_start = self._bucket_start(_as_utc(timestamp), bucket_minutes=bucket_minutes)
            bucket = buckets.get(bucket_start, _TimelineBucket(bucket_start=bucket_start))
            buckets[bucket_start] = _TimelineBucket(bucket_start=bucket_start, alert_count=bucket.alert_count + 1, incident_count=bucket.incident_count)

        incident_rows = await db.scalars(select(Incident.first_seen).where(Incident.first_seen >= since).order_by(Incident.first_seen.asc()))
        for timestamp in incident_rows.all():
            bucket_start = self._bucket_start(_as_utc(timestamp), bucket_minutes=bucket_minutes)
            bucket = buckets.get(bucket_start, _TimelineBucket(bucket_start=bucket_start))
            buckets[bucket_start] = _TimelineBucket(bucket_start=bucket_start, alert_count=bucket.alert_count, incident_count=bucket.incident_count + 1)

        points = [
            DashboardTimelinePointOut(
                bucket_start=bucket.bucket_start,
                alert_count=bucket.alert_count,
                incident_count=bucket.incident_count,
            )
            for bucket in sorted(buckets.values(), key=lambda item: item.bucket_start)
        ]
        return DashboardTimelineOut(bucket_minutes=bucket_minutes, points=points)

    async def _count_incidents(self, db: AsyncSession, *, severity: str) -> int:
        return await self._count_statement(db, select(func.count()).select_from(Incident).where(Incident.severity == severity))

    async def _count_open_incidents(self, db: AsyncSession) -> int:
        return await self._count_statement(db, select(func.count()).select_from(Incident).where(Incident.status.in_(_OPEN_INCIDENT_STATUSES)))

    async def _count_alerts_since(self, db: AsyncSession, since: datetime) -> int:
        return await self._count_statement(db, select(func.count()).select_from(Alert).where(Alert.timestamp >= since))

    async def _count_all(self, db: AsyncSession, model: type) -> int:
        return await self._count_statement(db, select(func.count()).select_from(model))

    async def _count_statement(self, db: AsyncSession, statement) -> int:
        result = await db.scalar(statement)
        return int(result or 0)

    def _bucket_start(self, value: datetime, *, bucket_minutes: int) -> datetime:
        epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        minutes_since_epoch = int((_as_utc(value) - epoch).total_seconds() // 60)
        bucket_minutes_since_epoch = (minutes_since_epoch // bucket_minutes) * bucket_minutes
        return epoch + timedelta(minutes=bucket_minutes_since_epoch)
