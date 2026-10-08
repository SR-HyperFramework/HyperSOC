"""Durable automation: evidence first, human conclusion before containment."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from sqlalchemy import and_, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.workflow import WorkflowJob
from app.schemas.ai_triage import AITriageRunRequest
from app.schemas.incident import CorrelationRunRequest
from app.services.ai_triage import AITriageService
from app.services.correlation import CorrelationService
from app.services.hub import IntelligenceHub, utc
from app.services.investigator import InvestigationService
from app.services.knowledge_base import KnowledgeBaseService
from app.services.threat_intel.service import ThreatIntelService
from app.services.wazuh import normalize_persisted_alert
from app.services.understanding import AlertUnderstanding
from app.services.workflow_review import workflow_review_status


def now():
    return datetime.now(timezone.utc)


class WorkflowLeaseLost(RuntimeError):
    pass


class SOCWorkflow:
    def __init__(self, *, hub=None, threat_intel=None, knowledge_base=None, investigator=None):
        self.hub = hub or IntelligenceHub()
        self.threat_intel = threat_intel or ThreatIntelService()
        knowledge = knowledge_base or KnowledgeBaseService(root=settings.knowledge_base_path)
        self.triage = AITriageService(knowledge_base=knowledge)
        self.investigator = investigator or InvestigationService(knowledge_base=knowledge, hub=self.hub)
        self.understanding = AlertUnderstanding()

    async def claim(self, db: AsyncSession) -> WorkflowJob | None:
        clock = now()
        await db.execute(update(WorkflowJob).where(
            WorkflowJob.status == "PROCESSING", WorkflowJob.lease_until < clock,
            WorkflowJob.attempts >= settings.automation_max_attempts,
        ).values(status="FAILED", error="Worker lease expired after the maximum attempts", lease_token=None, lease_until=None))
        job = await db.scalar(select(WorkflowJob).where(
            or_(
                and_(WorkflowJob.status.in_(["PENDING", "RETRY"]), WorkflowJob.available_at <= clock),
                and_(WorkflowJob.status == "PROCESSING", WorkflowJob.lease_until < clock),
            ), WorkflowJob.attempts < settings.automation_max_attempts,
        ).order_by(WorkflowJob.available_at, WorkflowJob.id).with_for_update(skip_locked=True).limit(1))
        if job is None:
            await db.commit()
            return None
        job.status = "PROCESSING"
        job.attempts += 1
        job.lease_token = uuid4()
        job.lease_until = clock + timedelta(seconds=settings.automation_lease_seconds)
        job.error = None
        await db.commit()
        return job

    async def _checkpoint(self, db, job, token, stage, **output):
        owner = await db.scalar(select(WorkflowJob).where(
            WorkflowJob.id == job.id, WorkflowJob.status == "PROCESSING", WorkflowJob.lease_token == token,
            WorkflowJob.lease_until > now(),
        ).with_for_update())
        if owner is None:
            raise WorkflowLeaseLost("Workflow was claimed by another worker")
        job.stage = stage
        job.output = {**job.output, **output}
        job.lease_until = now() + timedelta(seconds=settings.automation_lease_seconds)
        await db.commit()

    async def renew(self, db: AsyncSession, job_id: UUID, token: UUID) -> bool:
        result = await db.execute(update(WorkflowJob).where(
            WorkflowJob.id == job_id, WorkflowJob.status == "PROCESSING",
            WorkflowJob.lease_token == token, WorkflowJob.lease_until > now(),
        ).values(lease_until=now() + timedelta(seconds=settings.automation_lease_seconds)))
        await db.commit()
        return result.rowcount == 1

    async def process(self, db: AsyncSession, job: WorkflowJob):
        token = job.lease_token
        job_id = job.id
        try:
            alert = await db.get(Alert, job.alert_id)
            if alert is None:
                raise ValueError("Workflow alert is missing")
            normalized = normalize_persisted_alert(alert)
            if "understanding" not in job.output:
                evidence = await self.hub.project_alert(db, alert)
                understanding = await self.understanding.analyze(normalized, f"hub_evidence:{evidence.id}")
                await self._checkpoint(db, job, token, "internal_context", understanding=understanding)
            if "internal_context" not in job.output:
                from app.services.behavior import BehaviorAnalytics
                await BehaviorAnalytics().ensure_baseline(db, host=normalized.host.name or normalized.host.id, before=normalized.timestamp)
                context = await self.hub.alert_context(db, alert)
                await self._checkpoint(db, job, token, "enrichment", internal_context={
                    "evidence_ids": [record["id"] for record in context.evidence],
                    "sources": sorted({record["source"] for record in context.evidence}),
                    "assets": [item.model_dump(mode="json") for item in context.assets],
                    "identities": [item.model_dump(mode="json") for item in context.identities],
                    "graph": context.graph.model_dump(mode="json"),
                    "historical_incidents": context.historical_incidents,
                    "analytics": context.analytics,
                    "gaps": context.gaps,
                })
            if "enrichment" not in job.output:
                enriched = await self.threat_intel.enrich_persisted_alert(db, alert)
                await self._checkpoint(db, job, token, "correlation", enrichment=enriched.model_dump(mode="json"))
            if "incident_ids" not in job.output:
                correlation = CorrelationService(self.threat_intel, clock=lambda: utc(alert.timestamp) + timedelta(microseconds=1))
                result = await correlation.run(db, CorrelationRunRequest(lookback_minutes=60, window_minutes=10, min_alerts=1))
                ids = [str(incident.id) for incident in result.incidents if alert.id in incident.alert_ids]
                await self._checkpoint(db, job, token, "conclusion", incident_ids=ids)
            investigations = dict(job.output.get("investigations", {}))
            coalesced = dict(job.output.get("coalesced", {}))
            for incident_id in job.output["incident_ids"]:
                if incident_id in investigations or incident_id in coalesced:
                    continue
                incident = await db.get(Incident, UUID(incident_id))
                if incident is None or incident.status in {"FALSE_POSITIVE", "RESOLVED", "CONTAINED"}:
                    continue
                # An alert that does not materially change the incident is covered by its
                # current report; re-running would cost model calls and reset analyst review.
                current = await self.investigator.current_for(db, incident)
                if current is not None:
                    coalesced[incident_id] = str(current.id)
                    await self._checkpoint(db, job, token, "conclusion", coalesced=coalesced)
                    continue
                context = await self.hub.context(db, incident)
                await self.triage.run(db, incident.id, AITriageRunRequest(force=True))
                run = await self.investigator.run(db, incident.id, workflow_key=f"{job.id}:{incident.id}")
                investigations[incident_id] = str(run.id)
                await self._checkpoint(db, job, token, "conclusion", investigations=investigations, context_gaps=context.gaps)
            await self._checkpoint(db, job, token, "analyst_review", investigations=investigations, coalesced=coalesced)
            owner = await db.scalar(select(WorkflowJob).where(
                WorkflowJob.id == job.id, WorkflowJob.status == "PROCESSING", WorkflowJob.lease_token == token,
                WorkflowJob.lease_until > now(),
            ).with_for_update())
            if owner is None:
                raise WorkflowLeaseLost("Workflow was claimed by another worker")
            job.status = await workflow_review_status(db, job.id, coalesced=bool(coalesced))
            job.lease_until = None
            job.lease_token = None
            await db.commit()
        except WorkflowLeaseLost:
            await db.rollback()
            raise
        except Exception as exc:
            await db.rollback()
            owner = await db.scalar(select(WorkflowJob).where(WorkflowJob.id == job_id, WorkflowJob.lease_token == token).with_for_update())
            if owner is not None:
                owner.status = "FAILED" if owner.attempts >= settings.automation_max_attempts else "RETRY"
                owner.available_at = now() + timedelta(seconds=min(300, 2 ** owner.attempts))
                owner.error = f"{type(exc).__name__}: processing failed at {owner.stage}"
                owner.lease_until = None
                owner.lease_token = None
                await db.commit()
            raise
