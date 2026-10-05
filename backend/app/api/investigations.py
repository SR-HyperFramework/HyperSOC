from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.knowledge_base import get_knowledge_base_service
from app.core.database import get_db
from app.schemas.investigation import InvestigationOut, InvestigationReviewRequest
from app.services.investigator import (
    InvestigationProviderError,
    InvestigationReviewConflict,
    InvestigationService,
    InvestigationValidationError,
)

router = APIRouter(prefix="/api/v1", tags=["investigations"])
_service = InvestigationService(knowledge_base=get_knowledge_base_service())


def get_investigation_service() -> InvestigationService:
    return _service


@router.post("/incidents/{incident_id}/investigations", response_model=InvestigationOut, status_code=201)
async def run_investigation(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    service: InvestigationService = Depends(get_investigation_service),
) -> InvestigationOut:
    try:
        result = await service.run(db, incident_id)
    except InvestigationProviderError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc
    except InvestigationValidationError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    if result is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    return result


@router.get("/incidents/{incident_id}/investigations", response_model=list[InvestigationOut])
async def list_investigations(
    incident_id: UUID,
    limit: int = Query(default=20, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    service: InvestigationService = Depends(get_investigation_service),
) -> list[InvestigationOut]:
    return await service.list_for_incident(db, incident_id, limit)


@router.get("/investigations/{investigation_id}", response_model=InvestigationOut)
async def get_investigation(
    investigation_id: UUID,
    db: AsyncSession = Depends(get_db),
    service: InvestigationService = Depends(get_investigation_service),
) -> InvestigationOut:
    result = await service.get(db, investigation_id)
    if result is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Investigation not found")
    return result


@router.post("/investigations/{investigation_id}/review", response_model=InvestigationOut)
async def review_investigation(
    investigation_id: UUID,
    request: InvestigationReviewRequest,
    http: Request,
    db: AsyncSession = Depends(get_db),
    service: InvestigationService = Depends(get_investigation_service),
) -> InvestigationOut:
    principal = getattr(http.state, "principal", None)
    if principal is not None:
        request = request.model_copy(update={"reviewed_by": principal.username})
    try:
        result = await service.review(db, investigation_id, request)
    except InvestigationReviewConflict as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    if result is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Investigation not found")
    return result
