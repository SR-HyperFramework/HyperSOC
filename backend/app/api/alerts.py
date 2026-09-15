from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import verify_wazuh_signature
from app.models.alert import Alert
from app.schemas.alert import AlertIngest, AlertOut
from app.services.wazuh import ingest_alert

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])


@router.post("", response_model=AlertOut)
async def create_alert(
    response: Response,
    raw_body: bytes = Depends(verify_wazuh_signature),
    db: AsyncSession = Depends(get_db),
) -> Alert:
    try:
        alert = AlertIngest.model_validate_json(raw_body)
    except (ValidationError, ValueError, TypeError) as exc:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Invalid alert payload",
        ) from exc

    row, created = await ingest_alert(db, alert)
    response.status_code = status.HTTP_201_CREATED if created else status.HTTP_200_OK
    return row


@router.get("", response_model=list[AlertOut])
async def list_alerts(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=1_000_000),
    db: AsyncSession = Depends(get_db),
) -> list[Alert]:
    result = await db.scalars(
        select(Alert).order_by(Alert.timestamp.desc()).limit(limit).offset(offset)
    )
    return list(result.all())


@router.get("/{alert_id}", response_model=AlertOut)
async def get_alert(alert_id: UUID, db: AsyncSession = Depends(get_db)) -> Alert:
    row = await db.get(Alert, alert_id)
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    return row
