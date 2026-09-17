from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.schemas.dashboard import DashboardMitreTechniqueOut, DashboardSummaryOut, DashboardTimelineOut
from app.services.dashboard import DashboardService

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])
_dashboard_service = DashboardService()


def get_dashboard_service() -> DashboardService:
    return _dashboard_service


@router.get("/summary", response_model=DashboardSummaryOut)
async def dashboard_summary(
    db: AsyncSession = Depends(get_db),
    service: DashboardService = Depends(get_dashboard_service),
) -> DashboardSummaryOut:
    return await service.summary(db)


@router.get("/mitre", response_model=list[DashboardMitreTechniqueOut])
async def dashboard_mitre(
    limit: int = Query(default=10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    service: DashboardService = Depends(get_dashboard_service),
) -> list[DashboardMitreTechniqueOut]:
    return await service.mitre(db, limit=limit)


@router.get("/timeline", response_model=DashboardTimelineOut)
async def dashboard_timeline(
    hours: int = Query(default=24, ge=1, le=168),
    bucket_minutes: int = Query(default=60, ge=5, le=1440),
    db: AsyncSession = Depends(get_db),
    service: DashboardService = Depends(get_dashboard_service),
) -> DashboardTimelineOut:
    return await service.timeline(db, hours=hours, bucket_minutes=bucket_minutes)
