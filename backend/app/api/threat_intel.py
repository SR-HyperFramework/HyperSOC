from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.alert import Alert
from app.schemas.threat_intel import AlertThreatIntelOut, IndicatorType, ThreatIntelResultOut
from app.services.threat_intel.indicators import InvalidIndicatorError
from app.services.threat_intel.service import ThreatIntelService

router = APIRouter(prefix="/api/v1", tags=["threat-intel"])
_threat_intel_service = ThreatIntelService()


def get_threat_intel_service() -> ThreatIntelService:
    return _threat_intel_service


@router.get("/threat-intel/lookup", response_model=ThreatIntelResultOut)
async def lookup_indicator(
    indicator_type: IndicatorType = Query(alias="type"),
    indicator: str = Query(min_length=1, max_length=2048),
    refresh: bool = False,
    db: AsyncSession = Depends(get_db),
    service: ThreatIntelService = Depends(get_threat_intel_service),
) -> ThreatIntelResultOut:
    try:
        return await service.lookup(db, indicator_type, indicator, refresh=refresh)
    except InvalidIndicatorError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc


@router.post("/alerts/{alert_id}/threat-intel", response_model=AlertThreatIntelOut)
async def enrich_alert(
    alert_id: UUID,
    refresh: bool = False,
    db: AsyncSession = Depends(get_db),
    service: ThreatIntelService = Depends(get_threat_intel_service),
) -> AlertThreatIntelOut:
    row = await db.get(Alert, alert_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    return await service.enrich_persisted_alert(db, row, refresh=refresh)


@router.get("/alerts/{alert_id}/threat-intel", response_model=AlertThreatIntelOut)
async def get_alert_threat_intel(
    alert_id: UUID,
    db: AsyncSession = Depends(get_db),
    service: ThreatIntelService = Depends(get_threat_intel_service),
) -> AlertThreatIntelOut:
    row = await db.get(Alert, alert_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    return await service.get_alert_enrichments(db, alert_id)
