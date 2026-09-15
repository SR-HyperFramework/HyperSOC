from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.models.threat_intel import AlertThreatIntel, ThreatIntelIndicator
from app.schemas.normalized_alert import NormalizedAlert
from app.schemas.threat_intel import (
    AlertThreatIntelItemOut,
    AlertThreatIntelOut,
    ThreatIntelProviderResult,
    ThreatIntelResultOut,
)
from app.services.threat_intel.indicators import (
    ExtractedIndicator,
    IndicatorTypeName,
    canonicalize_indicator,
    extract_indicators,
)
from app.services.threat_intel.providers import OfflineThreatIntelProvider, ThreatIntelProvider
from app.services.threat_intel.scoring import aggregate_indicator_verdicts, aggregate_provider_results
from app.services.wazuh import normalize_persisted_alert

_CACHE_TTLS: dict[IndicatorTypeName, timedelta] = {
    "ip": timedelta(hours=6),
    "domain": timedelta(hours=12),
    "hash": timedelta(hours=24),
    "url": timedelta(hours=6),
}


@dataclass(frozen=True)
class _LookupResult:
    result: ThreatIntelResultOut
    row: ThreatIntelIndicator


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class ThreatIntelService:
    """Cache-backed IOC enrichment service for canonical SOC alerts."""

    def __init__(
        self,
        providers: Iterable[ThreatIntelProvider] | None = None,
        *,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self.providers = list(providers) if providers is not None else [OfflineThreatIntelProvider()]
        self._clock = clock

    async def lookup_ip(self, db: AsyncSession, indicator: Any, *, refresh: bool = False) -> ThreatIntelResultOut:
        return (await self._lookup_indicator(db, "ip", indicator, refresh=refresh)).result

    async def lookup_hash(self, db: AsyncSession, indicator: Any, *, refresh: bool = False) -> ThreatIntelResultOut:
        return (await self._lookup_indicator(db, "hash", indicator, refresh=refresh)).result

    async def lookup_domain(self, db: AsyncSession, indicator: Any, *, refresh: bool = False) -> ThreatIntelResultOut:
        return (await self._lookup_indicator(db, "domain", indicator, refresh=refresh)).result

    async def lookup_url(self, db: AsyncSession, indicator: Any, *, refresh: bool = False) -> ThreatIntelResultOut:
        return (await self._lookup_indicator(db, "url", indicator, refresh=refresh)).result

    async def lookup(
        self,
        db: AsyncSession,
        indicator_type: str,
        indicator: Any,
        *,
        refresh: bool = False,
    ) -> ThreatIntelResultOut:
        if indicator_type == "ip":
            return await self.lookup_ip(db, indicator, refresh=refresh)
        if indicator_type == "domain":
            return await self.lookup_domain(db, indicator, refresh=refresh)
        if indicator_type == "hash":
            return await self.lookup_hash(db, indicator, refresh=refresh)
        if indicator_type == "url":
            return await self.lookup_url(db, indicator, refresh=refresh)
        canonicalize_indicator(indicator_type, indicator)
        raise ValueError("unreachable")

    async def enrich_persisted_alert(
        self,
        db: AsyncSession,
        alert: Alert,
        *,
        refresh: bool = False,
    ) -> AlertThreatIntelOut:
        return await self.enrich_alert(db, normalize_persisted_alert(alert), refresh=refresh)

    async def enrich_alert(
        self,
        db: AsyncSession,
        alert: NormalizedAlert,
        *,
        refresh: bool = False,
    ) -> AlertThreatIntelOut:
        extracted = extract_indicators(alert)
        if not extracted:
            return AlertThreatIntelOut(alert_id=alert.id)

        grouped: dict[tuple[IndicatorTypeName, str], list[ExtractedIndicator]] = defaultdict(list)
        for item in extracted:
            grouped[(item.type, item.value)].append(item)

        response_items: list[AlertThreatIntelItemOut] = []
        for (indicator_type, indicator), evidence_items in grouped.items():
            lookup = await self._lookup_indicator(db, indicator_type, indicator, refresh=refresh)
            for evidence in evidence_items:
                await self._ensure_association(db, alert.id, lookup.row.id, evidence.evidence_path)
                response_items.append(self._item_out(lookup.result, evidence.evidence_path))

        return self._alert_out(alert.id, response_items)

    async def get_alert_enrichments(self, db: AsyncSession, alert_id: UUID) -> AlertThreatIntelOut:
        result = await db.scalars(
            select(AlertThreatIntel)
            .where(AlertThreatIntel.alert_id == alert_id)
            .order_by(AlertThreatIntel.evidence_path)
        )
        associations = list(result.all())
        response_items: list[AlertThreatIntelItemOut] = []
        for association in associations:
            row = await db.get(ThreatIntelIndicator, association.threat_intel_indicator_id)
            if row is None:
                continue
            response_items.append(self._item_out(self._row_to_result(row, cached=True), association.evidence_path))
        return self._alert_out(alert_id, response_items)

    async def _lookup_indicator(
        self,
        db: AsyncSession,
        indicator_type: IndicatorTypeName,
        indicator: Any,
        *,
        refresh: bool,
    ) -> _LookupResult:
        canonical = canonicalize_indicator(indicator_type, indicator)
        now = _as_utc(self._clock())
        row = await self._find_indicator(db, indicator_type, canonical)
        if row is not None and not refresh and _as_utc(row.cached_until) > now:
            return _LookupResult(result=self._row_to_result(row, cached=True), row=row)

        providers = await self._lookup_providers(indicator_type, canonical)
        risk_score, verdict = aggregate_provider_results(providers)
        cached_until = now + _CACHE_TTLS[indicator_type]
        row = await self._upsert_indicator(
            db,
            row=row,
            indicator_type=indicator_type,
            indicator=canonical,
            providers=providers,
            risk_score=risk_score,
            verdict=verdict,
            cached_until=cached_until,
            last_lookup_at=now,
        )
        return _LookupResult(result=self._row_to_result(row, cached=False), row=row)

    async def _lookup_providers(
        self,
        indicator_type: IndicatorTypeName,
        indicator: str,
    ) -> dict[str, ThreatIntelProviderResult]:
        results: dict[str, ThreatIntelProviderResult] = {}
        for provider in self.providers:
            if indicator_type not in provider.supported_types:
                continue
            result = await provider.lookup(indicator_type, indicator)
            results[result.provider] = result
        return results

    async def _find_indicator(
        self,
        db: AsyncSession,
        indicator_type: str,
        indicator: str,
    ) -> ThreatIntelIndicator | None:
        return await db.scalar(
            select(ThreatIntelIndicator).where(
                ThreatIntelIndicator.indicator_type == indicator_type,
                ThreatIntelIndicator.indicator == indicator,
            )
        )

    async def _upsert_indicator(
        self,
        db: AsyncSession,
        *,
        row: ThreatIntelIndicator | None,
        indicator_type: str,
        indicator: str,
        providers: dict[str, ThreatIntelProviderResult],
        risk_score: int,
        verdict: str,
        cached_until: datetime,
        last_lookup_at: datetime,
    ) -> ThreatIntelIndicator:
        provider_payload = {name: result.model_dump(mode="json") for name, result in providers.items()}
        if row is None:
            row = ThreatIntelIndicator(
                id=uuid4(),
                indicator_type=indicator_type,
                indicator=indicator,
                providers=provider_payload,
                risk_score=risk_score,
                verdict=verdict,
                cached_until=cached_until,
                last_lookup_at=last_lookup_at,
            )
            db.add(row)
        else:
            row.providers = provider_payload
            row.risk_score = risk_score
            row.verdict = verdict
            row.cached_until = cached_until
            row.last_lookup_at = last_lookup_at

        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()
            existing = await self._find_indicator(db, indicator_type, indicator)
            if existing is None:
                raise
            existing.providers = provider_payload
            existing.risk_score = risk_score
            existing.verdict = verdict
            existing.cached_until = cached_until
            existing.last_lookup_at = last_lookup_at
            await db.commit()
            row = existing
        return row

    async def _ensure_association(
        self,
        db: AsyncSession,
        alert_id: UUID,
        indicator_id: UUID,
        evidence_path: str,
    ) -> None:
        existing = await db.scalar(
            select(AlertThreatIntel).where(
                AlertThreatIntel.alert_id == alert_id,
                AlertThreatIntel.threat_intel_indicator_id == indicator_id,
                AlertThreatIntel.evidence_path == evidence_path,
            )
        )
        if existing is not None:
            return

        db.add(
            AlertThreatIntel(
                id=uuid4(),
                alert_id=alert_id,
                threat_intel_indicator_id=indicator_id,
                evidence_path=evidence_path,
            )
        )
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()

    def _row_to_result(self, row: ThreatIntelIndicator, *, cached: bool) -> ThreatIntelResultOut:
        providers: dict[str, ThreatIntelProviderResult] = {}
        for name, payload in (row.providers or {}).items():
            try:
                providers[name] = ThreatIntelProviderResult.model_validate(payload)
            except ValidationError:
                providers[name] = ThreatIntelProviderResult(
                    provider=name,
                    verdict="unknown",
                    risk_score=0,
                    confidence=0,
                    summary="Stored provider result could not be parsed",
                    error="invalid_stored_provider_result",
                )
        return ThreatIntelResultOut(
            indicator=row.indicator,
            type=row.indicator_type,
            providers=providers,
            risk_score=row.risk_score,
            verdict=row.verdict,
            cached=cached,
            cached_until=row.cached_until,
            last_lookup_at=row.last_lookup_at,
        )

    def _item_out(self, result: ThreatIntelResultOut, evidence_path: str) -> AlertThreatIntelItemOut:
        return AlertThreatIntelItemOut(evidence_path=evidence_path, **result.model_dump())

    def _alert_out(self, alert_id: UUID, items: list[AlertThreatIntelItemOut]) -> AlertThreatIntelOut:
        max_risk_score, verdict = aggregate_indicator_verdicts((item.verdict, item.risk_score) for item in items)
        return AlertThreatIntelOut(
            alert_id=alert_id,
            indicators=items,
            max_risk_score=max_risk_score,
            verdict=verdict,
        )
