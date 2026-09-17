from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.knowledge_base import get_knowledge_base_service
from app.core.database import get_db
from app.schemas.ai_triage import AITriageAnalysisOut, AITriageRunOut, AITriageRunRequest
from app.schemas.incident import CorrelationRunOut, CorrelationRunRequest, IncidentDetailOut, IncidentOut, IncidentStatus
from app.services.ai_triage import AITriageProviderUnavailable, AITriageService, AITriageValidationError
from app.services.correlation import CorrelationService

router = APIRouter(prefix="/api/v1", tags=["incidents"])
_correlation_service = CorrelationService()
_ai_triage_service = AITriageService(knowledge_base=get_knowledge_base_service())


def get_correlation_service() -> CorrelationService:
    return _correlation_service


def get_ai_triage_service() -> AITriageService:
    return _ai_triage_service


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


@router.post("/incidents/{incident_id}/triage", response_model=AITriageRunOut)
async def triage_incident(
    incident_id: UUID,
    request: AITriageRunRequest | None = None,
    db: AsyncSession = Depends(get_db),
    service: AITriageService = Depends(get_ai_triage_service),
) -> AITriageRunOut:
    return await _run_ai_triage(incident_id, request or AITriageRunRequest(), db, service)


@router.post("/incidents/{incident_id}/reanalyze", response_model=AITriageRunOut)
async def reanalyze_incident(
    incident_id: UUID,
    request: AITriageRunRequest | None = None,
    db: AsyncSession = Depends(get_db),
    service: AITriageService = Depends(get_ai_triage_service),
) -> AITriageRunOut:
    payload = (request or AITriageRunRequest()).model_copy(update={"force": True})
    return await _run_ai_triage(incident_id, payload, db, service)


@router.get("/incidents/{incident_id}/analysis", response_model=AITriageAnalysisOut)
async def get_incident_analysis(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    service: AITriageService = Depends(get_ai_triage_service),
) -> AITriageAnalysisOut:
    try:
        result = await service.stored_analysis(db, incident_id)
    except AITriageValidationError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    if result is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    return result


@router.post("/incidents/{incident_id}/ai-triage", response_model=AITriageRunOut)
async def run_ai_triage(
    incident_id: UUID,
    request: AITriageRunRequest | None = None,
    db: AsyncSession = Depends(get_db),
    service: AITriageService = Depends(get_ai_triage_service),
) -> AITriageRunOut:
    return await _run_ai_triage(incident_id, request or AITriageRunRequest(), db, service)


async def _run_ai_triage(
    incident_id: UUID,
    request: AITriageRunRequest,
    db: AsyncSession,
    service: AITriageService,
) -> AITriageRunOut:
    try:
        result = await service.run(db, incident_id, request)
    except AITriageProviderUnavailable as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc
    except AITriageValidationError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    if result is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    return result
