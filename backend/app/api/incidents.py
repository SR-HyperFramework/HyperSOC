from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.schemas.incident import CorrelationRunOut, CorrelationRunRequest, IncidentDetailOut, IncidentOut, IncidentStatus
from app.services.correlation import CorrelationService

router = APIRouter(prefix="/api/v1", tags=["incidents"])
_correlation_service = CorrelationService()


def get_correlation_service() -> CorrelationService:
    return _correlation_service


@router.post("/correlation/run", response_model=CorrelationRunOut)
async def run_correlation(
    request: CorrelationRunRequest | None = None,
    db: AsyncSession = Depends(get_db),
    service: CorrelationService = Depends(get_correlation_service),
) -> CorrelationRunOut:
    return await service.run(db, request or CorrelationRunRequest())


@router.get("/incidents", response_model=list[IncidentOut])
async def list_incidents(
    status_filter: IncidentStatus | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=1_000_000),
    db: AsyncSession = Depends(get_db),
    service: CorrelationService = Depends(get_correlation_service),
) -> list[IncidentOut]:
    return await service.list_incidents(db, status=status_filter, limit=limit, offset=offset)


@router.get("/incidents/{incident_id}", response_model=IncidentDetailOut)
async def get_incident(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    service: CorrelationService = Depends(get_correlation_service),
) -> IncidentDetailOut:
    incident = await service.get_incident(db, incident_id)
    if incident is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    return incident
