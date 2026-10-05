from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.models.incident import Incident, IncidentAlert
from app.models.threat_intel import AlertThreatIntel, ThreatIntelIndicator
from app.schemas.incident import CorrelationRunOut, CorrelationRunRequest, IncidentDetailOut, IncidentOut
from app.schemas.normalized_alert import NormalizedAlert
from app.services.threat_intel.service import ThreatIntelService
from app.services.wazuh import normalize_persisted_alert

_OPEN_STATUSES = {"NEW", "TRIAGED", "INVESTIGATING"}
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_PATTERN_RANK = {
    "generic": 0,
    "brute_force": 1,
    "powershell": 2,
    "persistence": 3,
    "malware": 4,
}


@dataclass(frozen=True)
class ThreatIntelSummary:
    verdict: str
    risk_score: int
    evidence_path: str
    indicator_type: str
    indicator: str


@dataclass(frozen=True)
class _Candidate:
    alert: Alert
    normalized: NormalizedAlert
    threat_intel: tuple[ThreatIntelSummary, ...]
    host_key: str | None
    primary_host: str | None
    src_ip: str | None
    user: str | None
    process: str | None
    file_hash: str | None


@dataclass(frozen=True)
class _IncidentDraft:
    title: str
    severity: str
    confidence: int
    first_seen: datetime
    last_seen: datetime
    primary_host: str | None
    primary_user: str | None
    primary_src_ip: str | None
    mitre_ids: list[str]
    alert_ids: list[UUID]
    pattern: str
    candidates: tuple[_Candidate, ...]


@dataclass(frozen=True)
class _UpsertResult:
    incident: Incident
    created: bool


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _first_text(*values: Any) -> str | None:
    for value in values:
        if value is None or isinstance(value, bool):
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def _contains_any(value: str | None, tokens: Iterable[str]) -> bool:
    if not value:
        return False
    normalized = value.casefold()
    return any(token in normalized for token in tokens)


def _dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    results: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            results.append(value)
    return results


class CorrelationService:
    """Rule-based alert correlation for Phase 6 incident creation."""

    def __init__(
        self,
        threat_intel_service: ThreatIntelService | None = None,
        *,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self.threat_intel_service = threat_intel_service or ThreatIntelService()
        self._clock = clock

    async def run(
        self,
        db: AsyncSession,
        request: CorrelationRunRequest,
    ) -> CorrelationRunOut:
        since = _as_utc(self._clock()) - timedelta(minutes=request.lookback_minutes)
        alerts = await self._load_alerts(db, since=since)
        alerts = [alert for alert in alerts if _as_utc(alert.timestamp) <= _as_utc(self._clock())]
        candidates: list[_Candidate] = []
        for alert in alerts:
            if request.refresh_threat_intel:
                await self.threat_intel_service.enrich_persisted_alert(db, alert, refresh=False)
            candidates.append(await self._candidate(db, alert))

        drafts = self._build_drafts(candidates, window=timedelta(minutes=request.window_minutes), min_alerts=request.min_alerts)
        await self._lock_writes(db)
        created_count = 0
        updated_count = 0
        incident_outputs: list[IncidentDetailOut] = []
        for draft in drafts:
            result = await self._upsert_incident(db, draft)
            if result.created:
                created_count += 1
            else:
                updated_count += 1
            alert_ids = await self._incident_alert_ids(db, result.incident.id)
            incident_outputs.append(self._incident_detail(result.incident, alert_ids))

        await self._finish_run(db)
        return CorrelationRunOut(created_count=created_count, updated_count=updated_count, incidents=incident_outputs)

    async def _lock_writes(self, db: AsyncSession) -> None:
        if db.bind.dialect.name == "postgresql":
            await db.execute(text("SELECT pg_advisory_xact_lock(746021)"))

    async def _finish_run(self, db: AsyncSession) -> None:
        await db.commit()

    async def list_incidents(
        self,
        db: AsyncSession,
        *,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[IncidentOut]:
        statement = select(Incident)
        if status is not None:
            statement = statement.where(Incident.status == status)
        result = await db.scalars(statement.order_by(Incident.last_seen.desc()).limit(limit).offset(offset))
        return [self._incident_out(row) for row in result.all()]

    async def get_incident(self, db: AsyncSession, incident_id: UUID) -> IncidentDetailOut | None:
        row = await db.get(Incident, incident_id)
        if row is None:
            return None
        return self._incident_detail(row, await self._incident_alert_ids(db, incident_id))

    async def _load_alerts(self, db: AsyncSession, *, since: datetime) -> list[Alert]:
        closed_alerts = select(IncidentAlert.alert_id).join(Incident, Incident.id == IncidentAlert.incident_id).where(
            Incident.status.in_(["FALSE_POSITIVE", "RESOLVED", "CONTAINED"]))
        result = await db.scalars(select(Alert).where(Alert.timestamp >= since, Alert.id.not_in(closed_alerts)).order_by(Alert.timestamp.asc()))
        return list(result.all())

    async def _candidate(self, db: AsyncSession, alert: Alert) -> _Candidate:
        normalized = normalize_persisted_alert(alert)
        return _Candidate(
            alert=alert,
            normalized=normalized,
            threat_intel=tuple(await self._threat_intel_summaries(db, alert.id)),
            host_key=_first_text(normalized.host.id, normalized.host.name, alert.agent_id, alert.agent_name, normalized.host.ip),
            primary_host=_first_text(normalized.host.name, normalized.host.id, alert.agent_name, alert.agent_id, normalized.host.ip),
            src_ip=_first_text(normalized.network.src_ip, alert.src_ip),
            user=_first_text(normalized.identity.username, normalized.identity.target, alert.username),
            process=_first_text(normalized.process.name, normalized.process.image, alert.process_name),
            file_hash=_first_text(normalized.file.hash, normalized.process.hash, alert.file_hash),
        )

    async def _threat_intel_summaries(self, db: AsyncSession, alert_id: UUID) -> list[ThreatIntelSummary]:
        result = await db.scalars(
            select(AlertThreatIntel).where(AlertThreatIntel.alert_id == alert_id).order_by(AlertThreatIntel.evidence_path)
        )
        summaries: list[ThreatIntelSummary] = []
        for association in result.all():
            row = await db.get(ThreatIntelIndicator, association.threat_intel_indicator_id)
            if row is None:
                continue
            summaries.append(
                ThreatIntelSummary(
                    verdict=row.verdict,
                    risk_score=row.risk_score,
                    evidence_path=association.evidence_path,
                    indicator_type=row.indicator_type,
                    indicator=row.indicator,
                )
            )
        return summaries

    def _build_drafts(
        self,
        candidates: list[_Candidate],
        *,
        window: timedelta,
        min_alerts: int,
    ) -> list[_IncidentDraft]:
        groups: dict[tuple[str, str], list[_Candidate]] = defaultdict(list)
        for candidate in sorted(candidates, key=lambda item: _as_utc(item.normalized.timestamp)):
            host = candidate.host_key or (f"source:{candidate.src_ip}" if candidate.src_ip else None)
            if host is None:
                host = f"identity:{candidate.user}" if candidate.user else f"alert:{candidate.alert.id}"
            pivot = candidate.src_ip or (f"identity:{candidate.user}" if candidate.user else "host_activity")
            groups[(host, pivot)].append(candidate)

        drafts: list[_IncidentDraft] = []
        used_alert_ids: set[UUID] = set()
        for grouped in groups.values():
            current: list[_Candidate] = []
            for candidate in grouped:
                if not current:
                    current = [candidate]
                    continue
                if _as_utc(candidate.normalized.timestamp) - _as_utc(current[0].normalized.timestamp) <= window:
                    current.append(candidate)
                    continue
                self._append_draft(drafts, current, min_alerts=min_alerts, used_alert_ids=used_alert_ids)
                current = [candidate]
            self._append_draft(drafts, current, min_alerts=min_alerts, used_alert_ids=used_alert_ids)

        return sorted(drafts, key=lambda draft: (draft.first_seen, draft.primary_host or "", draft.primary_src_ip or ""))

    def _append_draft(
        self,
        drafts: list[_IncidentDraft],
        candidates: list[_Candidate],
        *,
        min_alerts: int,
        used_alert_ids: set[UUID],
    ) -> None:
        unique = [candidate for candidate in candidates if candidate.alert.id not in used_alert_ids]
        # A single high-level detection must reach investigation even without an IP.
        high_signal = any((candidate.normalized.detection.level or candidate.alert.rule_level or 0) >= 10 for candidate in unique)
        if not unique or (len(unique) < min_alerts and not high_signal):
            return
        draft = self._draft_from_candidates(unique)
        drafts.append(draft)
        used_alert_ids.update(draft.alert_ids)

    def _draft_from_candidates(self, candidates: list[_Candidate]) -> _IncidentDraft:
        ordered = sorted(candidates, key=lambda item: _as_utc(item.normalized.timestamp))
        pattern = self._pattern(ordered)
        severity = self._severity(ordered, pattern)
        confidence = self._confidence(ordered, pattern)
        primary_host = self._dominant(candidate.primary_host for candidate in ordered)
        primary_user = self._dominant(candidate.user for candidate in ordered)
        primary_src_ip = self._dominant(candidate.src_ip for candidate in ordered)
        mitre_ids = _dedupe(mitre_id for candidate in ordered for mitre_id in candidate.normalized.detection.mitre_ids)
        title = self._title(pattern, primary_host=primary_host, primary_user=primary_user, primary_src_ip=primary_src_ip)
        alert_ids = _dedupe(str(candidate.alert.id) for candidate in ordered)
        return _IncidentDraft(
            title=title,
            severity=severity,
            confidence=confidence,
            first_seen=_as_utc(ordered[0].normalized.timestamp),
            last_seen=_as_utc(ordered[-1].normalized.timestamp),
            primary_host=primary_host,
            primary_user=primary_user,
            primary_src_ip=primary_src_ip,
            mitre_ids=mitre_ids,
            alert_ids=[UUID(value) for value in alert_ids],
            pattern=pattern,
            candidates=tuple(ordered),
        )

    def _pattern(self, candidates: list[_Candidate]) -> str:
        matches = ["generic"]
        if self._is_brute_force(candidates):
            matches.append("brute_force")
        if self._is_powershell_chain(candidates):
            matches.append("powershell")
        if self._is_persistence_chain(candidates):
            matches.append("persistence")
        if self._is_malware_chain(candidates):
            matches.append("malware")
        return max(matches, key=lambda value: _PATTERN_RANK[value])

    def _is_brute_force(self, candidates: list[_Candidate]) -> bool:
        failures = [candidate for candidate in candidates if candidate.normalized.identity.auth_outcome == "failure"]
        successes = [candidate for candidate in candidates if candidate.normalized.identity.auth_outcome == "success"]
        return bool(failures and successes and len(failures) >= 2)

    def _is_powershell_chain(self, candidates: list[_Candidate]) -> bool:
        has_powershell = any(self._has_powershell(candidate) for candidate in candidates)
        has_network = any(self._has_network(candidate) for candidate in candidates)
        return has_powershell and has_network

    def _is_persistence_chain(self, candidates: list[_Candidate]) -> bool:
        has_powershell = any(self._has_powershell(candidate) for candidate in candidates)
        has_persistence = any(self._has_persistence(candidate) for candidate in candidates)
        return has_powershell and has_persistence

    def _is_malware_chain(self, candidates: list[_Candidate]) -> bool:
        has_bad_ioc = any(
            summary.verdict in {"suspicious", "malicious"} or summary.risk_score >= 40
            for candidate in candidates
            for summary in candidate.threat_intel
        )
        has_execution = any(
            candidate.normalized.process.image
            or candidate.normalized.process.name
            or candidate.normalized.file.hash
            or candidate.normalized.process.hash
            or candidate.normalized.detection.event_kind in {"process", "file"}
            for candidate in candidates
        )
        return has_bad_ioc and has_execution

    def _has_powershell(self, candidate: _Candidate) -> bool:
        alert = candidate.normalized
        if alert.detection.event_family == "powershell":
            return True
        return any(
            _contains_any(value, ("powershell", "pwsh"))
            for value in (alert.process.name, alert.process.image, alert.process.command_line, alert.detection.description)
        )

    def _has_network(self, candidate: _Candidate) -> bool:
        alert = candidate.normalized
        return bool(
            alert.network.dst_ip
            or alert.network.dst_port
            or alert.network.domain
            or alert.network.url
            or alert.network.dns_query
            or alert.detection.event_kind in {"network", "dns", "web"}
        )

    def _has_persistence(self, candidate: _Candidate) -> bool:
        alert = candidate.normalized
        values = (
            alert.detection.description,
            " ".join(alert.detection.groups),
            alert.process.command_line,
            alert.process.image,
            alert.file.path,
        )
        return any(_contains_any(value, ("registry", "scheduled task", "schtasks", "task scheduler", "run key")) for value in values)

    def _severity(self, candidates: list[_Candidate], pattern: str) -> str:
        max_level = max((candidate.normalized.detection.level or candidate.alert.rule_level or 0 for candidate in candidates), default=0)
        max_ti_risk = max((summary.risk_score for candidate in candidates for summary in candidate.threat_intel), default=0)
        if pattern == "malware" or max_ti_risk >= 70 or max_level >= 14:
            return "critical"
        if pattern in {"persistence", "powershell", "brute_force"} or max_ti_risk >= 40 or max_level >= 10:
            return "high"
        if max_level >= 5 or len(candidates) >= 5:
            return "medium"
        return "low"

    def _confidence(self, candidates: list[_Candidate], pattern: str) -> int:
        confidence = 35 + min(30, len(candidates) * 3)
        if pattern != "generic":
            confidence += 20
        if any(candidate.normalized.detection.mitre_ids for candidate in candidates):
            confidence += 10
        if any(summary.verdict in {"suspicious", "malicious"} for candidate in candidates for summary in candidate.threat_intel):
            confidence += 15
        return min(100, confidence)

    def _title(self, pattern: str, *, primary_host: str | None, primary_user: str | None, primary_src_ip: str | None) -> str:
        pivot = primary_host or primary_src_ip or primary_user or "unknown asset"
        if pattern == "brute_force":
            user = f" for {primary_user}" if primary_user else ""
            return f"Possible brute-force authentication chain{user} on {pivot}"
        if pattern == "powershell":
            return f"PowerShell activity correlated on {pivot}"
        if pattern == "persistence":
            return f"Possible persistence chain on {pivot}"
        if pattern == "malware":
            return f"Possible malware execution chain on {pivot}"
        return f"Related alerts from {primary_src_ip or 'unknown source'} on {pivot}"

    def _dominant(self, values: Iterable[str | None]) -> str | None:
        clean = [value for value in values if value]
        if not clean:
            return None
        return Counter(clean).most_common(1)[0][0]

    async def _upsert_incident(self, db: AsyncSession, draft: _IncidentDraft) -> _UpsertResult:
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
            db.add(incident)
            await self._commit(db)
            await self._ensure_incident_alerts(db, incident.id, draft.alert_ids)
            await self._update_incident_fields(db, incident, draft)
            return _UpsertResult(incident=incident, created=True)

        await self._ensure_incident_alerts(db, existing.id, draft.alert_ids)
        await self._update_incident_fields(db, existing, draft)
        return _UpsertResult(incident=existing, created=False)

    async def _find_existing_incident(self, db: AsyncSession, draft: _IncidentDraft) -> Incident | None:
        result = await db.scalars(select(IncidentAlert).where(IncidentAlert.alert_id.in_(draft.alert_ids)))
        for association in result.all():
            incident = await db.get(Incident, association.incident_id)
            if incident is not None and incident.status in _OPEN_STATUSES:
                return incident

        statement = select(Incident).where(
            Incident.status.in_(_OPEN_STATUSES),
            Incident.primary_host == draft.primary_host,
            Incident.primary_src_ip == draft.primary_src_ip,
            Incident.first_seen <= draft.last_seen,
            Incident.last_seen >= draft.first_seen,
        )
        existing = await db.scalars(statement.order_by(Incident.last_seen.desc()))
        return next(iter(existing.all()), None)

    async def _ensure_incident_alerts(self, db: AsyncSession, incident_id: UUID, alert_ids: list[UUID]) -> None:
        existing = await self._incident_alert_ids(db, incident_id)
        existing_set = set(existing)
        for alert_id in alert_ids:
            if alert_id in existing_set:
                continue
            db.add(IncidentAlert(id=uuid4(), incident_id=incident_id, alert_id=alert_id))
        await self._commit(db)

    async def _update_incident_fields(self, db: AsyncSession, incident: Incident, draft: _IncidentDraft) -> None:
        alert_ids = await self._incident_alert_ids(db, incident.id)
        incident.title = draft.title
        incident.severity = self._max_severity(incident.severity, draft.severity)
        incident.confidence = max(incident.confidence or 0, draft.confidence)
        incident.first_seen = min(_as_utc(incident.first_seen), draft.first_seen)
        incident.last_seen = max(_as_utc(incident.last_seen), draft.last_seen)
        incident.primary_host = draft.primary_host or incident.primary_host
        incident.primary_user = draft.primary_user or incident.primary_user
        incident.primary_src_ip = draft.primary_src_ip or incident.primary_src_ip
        incident.mitre_ids = _dedupe([*(incident.mitre_ids or []), *draft.mitre_ids])
        incident.alert_count = len(alert_ids)
        await self._commit(db)
        await self._refresh(db, incident)

    def _max_severity(self, first: str, second: str) -> str:
        return first if _SEVERITY_RANK.get(first, 0) >= _SEVERITY_RANK.get(second, 0) else second

    async def _incident_alert_ids(self, db: AsyncSession, incident_id: UUID) -> list[UUID]:
        result = await db.scalars(select(IncidentAlert).where(IncidentAlert.incident_id == incident_id).order_by(IncidentAlert.created_at))
        return [association.alert_id for association in result.all()]

    async def _commit(self, db: AsyncSession) -> None:
        try:
            # Keep the correlation lock until all incident/link writes finish.
            await db.flush()
        except IntegrityError:
            await db.rollback()

    async def _refresh(self, db: AsyncSession, row: Any) -> None:
        try:
            await db.refresh(row)
        except AttributeError:
            return

    def _incident_out(self, incident: Incident) -> IncidentOut:
        return IncidentOut(
            id=incident.id,
            title=incident.title,
            status=incident.status,
            severity=incident.severity,
            confidence=incident.confidence,
            first_seen=incident.first_seen,
            last_seen=incident.last_seen,
            primary_host=incident.primary_host,
            primary_user=incident.primary_user,
            primary_src_ip=incident.primary_src_ip,
            mitre_ids=incident.mitre_ids or [],
            alert_count=incident.alert_count,
            ai_summary=incident.ai_summary,
            ai_analysis=incident.ai_analysis,
            created_at=incident.created_at,
            updated_at=incident.updated_at,
        )

    def _incident_detail(self, incident: Incident, alert_ids: list[UUID]) -> IncidentDetailOut:
        return IncidentDetailOut(**self._incident_out(incident).model_dump(), alert_ids=alert_ids)
