"""Resolve review state without treating superseded reports as pending work."""
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.investigation import Investigation


async def workflow_review_status(db: AsyncSession, job_id: UUID) -> str:
    reports = (await db.scalars(select(Investigation).where(
        Investigation.workflow_key.startswith(f"{job_id}:"),
    ))).all()
    if not reports:
        return "COMPLETE"
    reviewed = False
    for report in reports:
        if report.status != "PENDING_REVIEW":
            reviewed = True
            continue
        latest_id = await db.scalar(select(Investigation.id).where(
            Investigation.incident_id == report.incident_id,
        ).order_by(Investigation.created_at.desc(), Investigation.id.desc()).limit(1))
        if latest_id == report.id:
            return "AWAITING_REVIEW"
    return "REVIEWED" if reviewed else "SUPERSEDED"
