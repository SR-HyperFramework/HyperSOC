from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.schemas.response_action import ResponseActionApprovalRequest, ResponseActionCreate, ResponseActionOut, ResponseActionRejectRequest
from app.schemas.response_action import ResponseVerificationRequest
from app.services.response import ResponseActionConflict, ResponseActionService

router = APIRouter(prefix="/api/v1", tags=["response"])
_response_service = ResponseActionService()


def get_response_action_service() -> ResponseActionService:
    return _response_service


@router.post("/incidents/{incident_id}/actions", response_model=ResponseActionOut, status_code=status.HTTP_201_CREATED)
async def create_response_action(
    incident_id: UUID,
    request: ResponseActionCreate,
    http: Request,
    db: AsyncSession = Depends(get_db),
    service: ResponseActionService = Depends(get_response_action_service),
) -> ResponseActionOut:
    principal = getattr(http.state, "principal", None)
    if principal is not None:
        request = request.model_copy(update={"requested_by": principal.username})
    try:
        result = await service.create_for_incident(db, incident_id, request)
    except ResponseActionConflict as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    if result is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    return result


@router.get("/incidents/{incident_id}/actions", response_model=list[ResponseActionOut])
async def list_response_actions(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    service: ResponseActionService = Depends(get_response_action_service),
) -> list[ResponseActionOut]:
    result = await service.list_for_incident(db, incident_id)
    if result is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    return result


@router.post("/actions/{action_id}/approve", response_model=ResponseActionOut)
async def approve_response_action(
    action_id: UUID,
    request: ResponseActionApprovalRequest,
    http: Request,
    db: AsyncSession = Depends(get_db),
    service: ResponseActionService = Depends(get_response_action_service),
) -> ResponseActionOut:
    principal = getattr(http.state, "principal", None)
    if principal is not None:
        request = request.model_copy(update={"approved_by": principal.username})
    try:
        result = await service.approve(db, action_id, request)
    except ResponseActionConflict as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    if result is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Response action not found")
    return result


@router.post("/actions/{action_id}/reject", response_model=ResponseActionOut)
async def reject_response_action(
    action_id: UUID,
    request: ResponseActionRejectRequest,
    http: Request,
    db: AsyncSession = Depends(get_db),
    service: ResponseActionService = Depends(get_response_action_service),
) -> ResponseActionOut:
    principal = getattr(http.state, "principal", None)
    if principal is not None:
        request = request.model_copy(update={"rejected_by": principal.username})
    try:
        result = await service.reject(db, action_id, request)
    except ResponseActionConflict as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    if result is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Response action not found")
    return result


@router.post("/actions/{action_id}/execute", response_model=ResponseActionOut)
async def execute_response_action(
    action_id: UUID,
    db: AsyncSession = Depends(get_db),
    service: ResponseActionService = Depends(get_response_action_service),
) -> ResponseActionOut:
    try:
        result = await service.execute(db, action_id)
    except ResponseActionConflict as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    if result is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Response action not found")
    return result


@router.post("/actions/{action_id}/verify", response_model=ResponseActionOut)
async def verify_response_action(action_id: UUID, request: ResponseVerificationRequest, db: AsyncSession = Depends(get_db), service: ResponseActionService = Depends(get_response_action_service)):
    try:
        evidence_ids = list(dict.fromkeys([*request.evidence_ids, *([request.evidence_id] if request.evidence_id else [])]))
        result = await service.verify(db, action_id, evidence_ids, request.notes)
    except ResponseActionConflict as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    if result is None:
        raise HTTPException(404, "Response action not found")
    return result
