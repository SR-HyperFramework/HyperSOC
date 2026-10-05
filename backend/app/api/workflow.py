from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.auth import audit
from app.models.workflow import WorkflowJob
from app.services.workflow import now

router = APIRouter(prefix="/api/v1/workflows", tags=["automation"])


def out(job):
    return {key: getattr(job, key) for key in ("id", "alert_id", "status", "stage", "attempts", "available_at", "lease_until", "output", "error", "created_at", "updated_at")}


@router.get("")
async def list_jobs(status: str | None = None, limit: int = Query(50, ge=1, le=200), db: AsyncSession = Depends(get_db)):
    query = select(WorkflowJob)
    if status:
        query = query.where(WorkflowJob.status == status)
    return [out(job) for job in (await db.scalars(query.order_by(WorkflowJob.created_at.desc()).limit(limit))).all()]


@router.get("/{job_id}")
async def get_job(job_id: UUID, db: AsyncSession = Depends(get_db)):
    job = await db.get(WorkflowJob, job_id)
    if job is None:
        raise HTTPException(404, "Workflow not found")
    return out(job)


@router.post("/{job_id}/retry")
async def retry_job(job_id: UUID, db: AsyncSession = Depends(get_db)):
    job = await db.scalar(select(WorkflowJob).where(WorkflowJob.id == job_id).with_for_update())
    if job is None:
        raise HTTPException(404, "Workflow not found")
    if job.status not in {"FAILED", "RETRY"}:
        raise HTTPException(409, "Only failed or retrying workflows can be retried")
    job.status, job.attempts, job.available_at = "PENDING", 0, now()
    job.error = None
    if db.info.get("soc_principal"):
        audit(db, "workflow.retry", str(job.id), details={"alert_id": str(job.alert_id)})
    await db.commit()
    # updated_at is server-generated and expires on UPDATE, even with
    # expire_on_commit=False. Load it before synchronous response serialization.
    await db.refresh(job)
    return out(job)
