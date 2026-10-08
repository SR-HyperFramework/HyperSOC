"""Exercise the real persistence/services instead of mocked database results."""
import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi import Response
from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import event, func, select
from sqlalchemy.schema import CreateSchema, DropSchema
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import app.models  # register every table
from app.api.hub import ingest_event
from app.core.database import Base
from app.models.alert import Alert
from app.models.hub import HubEntity, HubEvidence, HubRelationship
from app.models.incident import Incident
from app.models.investigation import Investigation
from app.models.workflow import WorkflowJob
from app.schemas.hub import HubEntityWrite, HubEventIn, HubSearch
from app.schemas.investigation import InvestigationReviewRequest
from app.schemas.normalized_alert import NormalizedAlert, NormalizedDetection, NormalizedHost, NormalizedIdentity, NormalizedNetwork, NormalizedProcess
from app.services.hub import IntelligenceHub
from app.services.workflow import SOCWorkflow

NOW = datetime.now(timezone.utc)


def run(scenario):
    async def body():
        url = os.environ.get("SOC_TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
        schema = "soc_test_" + uuid4().hex
        engine = create_async_engine(url, execution_options={"schema_translate_map": {None: schema}} if url.startswith("postgresql") else {})
        if engine.dialect.name == "sqlite":
            @event.listens_for(engine.sync_engine, "connect")
            def enable_fk(connection, _record):
                connection.execute("PRAGMA foreign_keys=ON")
        async with engine.begin() as connection:
            if engine.dialect.name == "postgresql":
                await connection.execute(CreateSchema(schema))
            await connection.run_sync(Base.metadata.create_all)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        try:
            await scenario(factory)
        finally:
            if engine.dialect.name == "postgresql":
                async with engine.begin() as connection:
                    await connection.execute(DropSchema(schema, cascade=True))
            await engine.dispose()
    asyncio.run(body())


def detection(external_id="event-1", *, source="edr-test", category="detection", when=NOW, level=12):
    return HubEventIn(source=source, external_id=external_id, category=category, alert=NormalizedAlert(
        timestamp=when, host=NormalizedHost(id="001", name="SERVER-A", ip="192.168.1.8"),
        identity=NormalizedIdentity(username="alice"),
        process=NormalizedProcess(name="powershell.exe", image="C:\\powershell.exe", pid=123),
        network=NormalizedNetwork(dst_ip="8.8.8.8", domain="example.org"),
        detection=NormalizedDetection(source=source, event_family="powershell", event_kind="process", level=level, mitre_ids=["T1059.001"], description="Suspicious PowerShell"),
    ))


async def ingest(db, payload):
    return await ingest_event(Response(), payload.model_dump_json().encode(), db)


@pytest.mark.parametrize("replacement", ["manual", "workflow"])
def test_latest_review_resolves_superseded_workflow_reports(replacement):
    from app.services.investigator import InvestigationReviewConflict
    async def scenario(factory):
        async with factory() as db:
            workflow = SOCWorkflow()
            await ingest(db, detection("first", when=NOW - timedelta(minutes=2)))
            first_job = await workflow.claim(db)
            await workflow.process(db, first_job)
            first_report = await db.scalar(select(Investigation))
            second_job = None
            if replacement == "manual":
                latest = await workflow.investigator.run(db, first_report.incident_id)
            else:
                await ingest(db, detection("second", when=NOW - timedelta(minutes=1)))
                second_job = await workflow.claim(db)
                await workflow.process(db, second_job)
                latest = await db.scalar(select(Investigation).order_by(Investigation.created_at.desc()).limit(1))
                assert latest.incident_id == first_report.incident_id
            request = InvestigationReviewRequest(reviewed_by="analyst", classification="true_positive", notes="Reviewed latest evidence")
            with pytest.raises(InvestigationReviewConflict, match="newer investigation"):
                await workflow.investigator.review(db, first_report.id, request)
            await workflow.investigator.review(db, latest.id, request)
            await db.refresh(first_job)
            assert first_job.status == "SUPERSEDED"
            assert first_report.status == "PENDING_REVIEW"  # original report is preserved
            if second_job:
                await db.refresh(second_job)
                assert second_job.status == "REVIEWED"
    run(scenario)


def test_review_during_worker_publication_is_not_reset_to_pending():
    async def scenario(factory):
        async with factory() as db:
            workflow = SOCWorkflow()
            original = workflow.investigator.run
            async def publish_and_review(*args, **kwargs):
                report = await original(*args, **kwargs)
                await workflow.investigator.review(db, report.id, InvestigationReviewRequest(
                    reviewed_by="analyst", classification="true_positive", notes="Reviewed immediately after publication",
                ))
                return report
            workflow.investigator.run = publish_and_review
            await ingest(db, detection())
            job = await workflow.claim(db)
            await workflow.process(db, job)
            assert job.status == "REVIEWED"
    run(scenario)


def test_new_detection_after_false_positive_gets_new_review_and_prior_decision_context():
    async def scenario(factory):
        async with factory() as db:
            workflow = SOCWorkflow()
            await ingest(db, detection("first", when=NOW - timedelta(minutes=5)))
            first_job = await workflow.claim(db)
            await workflow.process(db, first_job)
            first_report = await db.scalar(select(Investigation))
            await workflow.investigator.review(db, first_report.id, InvestigationReviewRequest(reviewed_by="analyst", classification="false_positive", notes="Prior benign activity"))
            await ingest(db, detection("second", when=NOW - timedelta(minutes=1)))
            second_job = await workflow.claim(db)
            await workflow.process(db, second_job)
            assert second_job.status == "AWAITING_REVIEW"
            assert second_job.output["incident_ids"] != first_job.output["incident_ids"]
            assert second_job.output["internal_context"]["historical_incidents"][0]["analyst_classification"] == "false_positive"
            incidents = list((await db.scalars(select(Incident))).all())
            assert len(incidents) == 2
            new = next(item for item in incidents if str(item.id) in second_job.output["incident_ids"])
            assert new.alert_count == 1  # closed evidence is not replayed into new cases
    run(scenario)


def test_hub_projection_is_idempotent_and_preserves_inventory_provenance():
    async def scenario(factory):
        hub = IntelligenceHub()
        async with factory() as db:
            inventory = await hub.upsert_entity(db, HubEntityWrite(
                kind="asset", external_key="server-a", label="SERVER-A", source="cmdb",
                observed_at=NOW - timedelta(hours=1), attributes={"owner": "finance", "criticality": "critical"},
            ))
            await db.commit()
            first = await hub.record(db, detection())
            again = await hub.record(db, detection())
            await db.commit()
            assert first.id == again.id
            assert await db.scalar(select(func.count()).select_from(HubEvidence)) == 1
            asset = await db.get(HubEntity, inventory.id)
            assert asset.source == "cmdb" and asset.attributes["owner"] == "finance"
            graph = await hub.graph(db, asset.id)
            assert any(edge.relation == "executes" for edge in graph.edges)
            assert any(node.kind == "identity" for node in graph.nodes)
            assert all(edge.source_ref.startswith("hub_evidence:") for edge in graph.edges)
    run(scenario)


def test_search_is_bounded_by_time_host_and_source():
    async def scenario(factory):
        hub = IntelligenceHub()
        async with factory() as db:
            await hub.record(db, detection("recent", category="behavior"))
            await hub.record(db, detection("old", when=NOW - timedelta(days=2)))
            await db.commit()
            rows = await hub.search(db, HubSearch(host="SERVER-A", source="edr-test", since=NOW - timedelta(hours=1), until=NOW))
            assert [row.external_id for row in rows] == ["recent"]
            with pytest.raises(ValidationError):
                HubSearch(since=NOW - timedelta(days=100), until=NOW)
    run(scenario)


def test_detection_without_source_ip_reaches_review_and_updates_incident():
    async def scenario(factory):
        workflow = SOCWorkflow()
        async with factory() as db:
            payload = detection()
            received = await ingest(db, payload)
            repeated = await ingest(db, payload)
            assert received["alert_id"] == repeated["alert_id"]
            assert await db.scalar(select(func.count()).select_from(WorkflowJob)) == 1
            job = await workflow.claim(db)
            await workflow.process(db, job)
            assert job.status == "AWAITING_REVIEW"
            assert job.stage == "analyst_review"
            assert job.output["understanding"]["iocs"]
            assert job.output["internal_context"]["evidence_ids"]
            investigation = await db.scalar(select(Investigation))
            assert "internal_context" in investigation.plan["tools"]
            assert any(item["source"] == "hub_data_gaps" for item in investigation.evidence)
            result = await workflow.investigator.review(db, investigation.id, InvestigationReviewRequest(
                reviewed_by="analyst", classification="false_positive", notes="Authorized administration",
            ))
            incident = await db.get(Incident, investigation.incident_id)
            assert incident.status == "FALSE_POSITIVE"
            assert job.status == "REVIEWED"
            assert result.final_classification == "false_positive"
            assert await workflow.claim(db) is None
            assert await db.scalar(select(func.count()).select_from(Investigation)) == 1
    run(scenario)


def test_workflow_retry_reuses_checkpoints_and_expired_lease_is_reclaimed():
    class FailOnce:
        def __init__(self):
            from app.services.threat_intel.service import ThreatIntelService
            self.provider = ThreatIntelService()
            self.calls = 0
        async def enrich_persisted_alert(self, db, alert, **kwargs):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("transient error")
            return await self.provider.enrich_persisted_alert(db, alert, **kwargs)
    async def scenario(factory):
        provider = FailOnce()
        workflow = SOCWorkflow(threat_intel=provider)
        async with factory() as db:
            await ingest(db, detection())
            job = await workflow.claim(db)
            first_token = job.lease_token
            job_id = job.id
            with pytest.raises(RuntimeError):
                await workflow.process(db, job)
            job = await db.get(WorkflowJob, job_id)
            assert job.status == "RETRY" and "understanding" in job.output
            job.available_at = NOW - timedelta(seconds=1)
            await db.commit()
            job = await workflow.claim(db)
            assert job.lease_token != first_token and job.attempts == 2
            # Simulate termination after a worker claim; the next worker recovers it.
            job.lease_until = NOW - timedelta(seconds=1)
            await db.commit()
            job = await workflow.claim(db)
            assert job.attempts == 3
            await workflow.process(db, job)
            assert job.status == "AWAITING_REVIEW" and provider.calls == 2
            assert await db.scalar(select(func.count()).select_from(Investigation)) == 1
    run(scenario)


def test_posture_and_behavior_ingestion_do_not_create_response_incidents():
    async def scenario(factory):
        async with factory() as db:
            await ingest(db, detection(category="posture"))
            await ingest(db, detection("behavior", category="behavior", level=0))
            assert await db.scalar(select(func.count()).select_from(HubEvidence)) == 2
            assert await db.scalar(select(func.count()).select_from(Alert)) == 0
            assert await db.scalar(select(func.count()).select_from(WorkflowJob)) == 0
    run(scenario)


def test_same_external_id_with_changed_evidence_is_rejected():
    async def scenario(factory):
        async with factory() as db:
            await ingest(db, detection())
            changed = detection()
            changed.alert.process.name = "different.exe"
            with pytest.raises(HTTPException) as exc:
                await ingest(db, changed)
            assert exc.value.status_code == 409
            assert await db.scalar(select(func.count()).select_from(Alert)) == 1
            assert await db.scalar(select(func.count()).select_from(HubEvidence)) == 1
    run(scenario)


def test_exhausted_dead_worker_becomes_failed_instead_of_stuck_processing():
    async def scenario(factory):
        from app.core.config import settings
        async with factory() as db:
            await ingest(db, detection())
            workflow = SOCWorkflow()
            job = await workflow.claim(db)
            job_id = job.id
            job.attempts = settings.automation_max_attempts
            job.lease_until = NOW - timedelta(seconds=1)
            await db.commit()
            assert await workflow.claim(db) is None
            await db.refresh(job)
            assert job.status == "FAILED" and job.lease_token is None
    run(scenario)


def test_single_low_level_detection_still_reaches_analyst_review():
    async def scenario(factory):
        async with factory() as db:
            await ingest(db, detection(level=3))
            workflow = SOCWorkflow()
            job = await workflow.claim(db)
            await workflow.process(db, job)
            assert job.status == "AWAITING_REVIEW" and job.output["investigations"]
    run(scenario)


def test_wazuh_ingestion_persists_job_in_the_same_transaction():
    async def scenario(factory):
        from app.services.wazuh import ingest_alert
        from app.schemas.alert import AlertIngest, AgentIn, RuleIn
        async with factory() as db:
            alert, created = await ingest_alert(db, AlertIngest(
                timestamp=NOW, agent=AgentIn(id="003", name="wazuh-host"),
                rule=RuleIn(id="rule-1", level=10, description="Process detection"),
            ))
            assert created
            job = await db.scalar(select(WorkflowJob).where(WorkflowJob.alert_id == alert.id))
            assert job is not None
            workflow = SOCWorkflow()
            claimed = await workflow.claim(db)
            await workflow.process(db, claimed)
            assert claimed.status == "AWAITING_REVIEW"
    run(scenario)


def test_retry_after_report_commit_does_not_create_a_second_report():
    async def scenario(factory):
        async with factory() as db:
            await ingest(db, detection())
            workflow = SOCWorkflow()
            original = workflow.investigator.run
            async def commit_then_fail(*args, **kwargs):
                await original(*args, **kwargs)
                raise RuntimeError("Simulated interruption after report persistence")
            workflow.investigator.run = commit_then_fail
            job = await workflow.claim(db)
            with pytest.raises(RuntimeError):
                await workflow.process(db, job)
            assert await db.scalar(select(func.count()).select_from(Investigation)) == 1
            workflow.investigator.run = original
            job.available_at = NOW - timedelta(seconds=1)
            await db.commit()
            claimed = await workflow.claim(db)
            await workflow.process(db, claimed)
            assert claimed.status == "AWAITING_REVIEW"
            assert await db.scalar(select(func.count()).select_from(Investigation)) == 1
    run(scenario)


def test_retry_api_loads_server_updated_timestamp_before_serializing():
    async def scenario(factory):
        from app.api.workflow import retry_job
        async with factory() as db:
            await ingest(db, detection())
            job = await db.scalar(select(WorkflowJob))
            job.status = "FAILED"
            job.attempts = 5
            job.error = "provider unavailable"
            await db.commit()
            result = await retry_job(job.id, db)
            assert result["status"] == "PENDING"
            assert result["attempts"] == 0 and result["error"] is None
            assert result["updated_at"] is not None
    run(scenario)


def test_alert_burst_reinvestigates_only_on_material_change():
    async def scenario(factory):
        async with factory() as db:
            workflow = SOCWorkflow()
            triage_calls = []
            original = workflow.triage.run
            async def counted(*args, **kwargs):
                triage_calls.append(args[1])
                return await original(*args, **kwargs)
            workflow.triage.run = counted
            jobs = []
            for index in range(8):
                await ingest(db, detection(f"burst-{index}", when=NOW - timedelta(minutes=9) + timedelta(minutes=index)))
                job = await workflow.claim(db)
                await workflow.process(db, job)
                jobs.append(job)
            reports = (await db.scalars(select(Investigation))).all()
            assert len({report.incident_id for report in reports}) == 1
            # Alert volume is bucketed by powers of two: reports at 1, 2, 4 and 8 alerts.
            assert len(reports) == 4 and len(triage_calls) == 4
            assert [job.status for job in jobs].count("COALESCED") == 4
            coalesced = jobs[2]
            covered = coalesced.output["coalesced"][coalesced.output["incident_ids"][0]]
            assert covered in {str(report.id) for report in reports}
            assert not coalesced.output.get("investigations")
    run(scenario)


def test_new_technique_reinvestigates_without_volume_change():
    async def scenario(factory):
        async with factory() as db:
            workflow = SOCWorkflow()
            for index in range(2):
                await ingest(db, detection(f"same-{index}", when=NOW - timedelta(minutes=5 - index)))
                await workflow.process(db, await workflow.claim(db))
            same = detection("same-2", when=NOW - timedelta(minutes=3))
            await ingest(db, same)
            third = await workflow.claim(db)
            await workflow.process(db, third)
            assert third.status == "COALESCED"
            changed = detection("new-technique", when=NOW - timedelta(minutes=2))
            changed.alert.detection.mitre_ids = ["T1059.001", "T1105"]
            await ingest(db, changed)
            fourth = await workflow.claim(db)
            await workflow.process(db, fourth)
            assert fourth.status == "AWAITING_REVIEW"
            assert len((await db.scalars(select(Investigation))).all()) == 3
    run(scenario)


def test_sliding_correlation_window_links_each_alert_to_one_incident():
    from app.models.incident import IncidentAlert
    from app.schemas.incident import CorrelationRunRequest
    from app.services.correlation import CorrelationService
    async def scenario(factory):
        async with factory() as db:
            start = NOW - timedelta(minutes=100)
            for index in range(31):
                when = start + timedelta(minutes=3 * index)
                await ingest(db, detection(f"steady-{index}", when=when))
                # Per-alert runs as the worker does them: the 60-minute lookback slides each time.
                correlation = CorrelationService(clock=lambda when=when: when + timedelta(microseconds=1))
                result = await correlation.run(db, CorrelationRunRequest(lookback_minutes=60, window_minutes=10, min_alerts=1))
                assert result.incidents
            links = (await db.scalars(select(IncidentAlert))).all()
            assert len(links) == len({link.alert_id for link in links}) == 31
            incidents = (await db.scalars(select(Incident))).all()
            assert sum(incident.alert_count for incident in incidents) == 31
    run(scenario)


@pytest.mark.skipif(not os.environ.get("SOC_TEST_DATABASE_URL", "").startswith("postgresql"), reason="PostgreSQL row-lock test")
def test_concurrent_workers_claim_distinct_jobs():
    async def scenario(factory):
        async with factory() as db:
            for index in range(4):
                await ingest(db, detection(f"job-{index}"))
        async def claim():
            async with factory() as db:
                job = await SOCWorkflow().claim(db)
                return job.id if job else None
        results = await asyncio.gather(*(claim() for _ in range(4)))
        assert None not in results and len(set(results)) == 4
    run(scenario)
