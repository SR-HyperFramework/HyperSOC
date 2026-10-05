from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.models.incident import Incident
from app.models.investigation import Investigation
from app.schemas.response_action import ResponseActionCreate, ResponseActionApprovalRequest
from app.services.hub import IntelligenceHub
from app.services.response import ResponseActionService, ResponseActionConflict
from app.services.siem import SIEMExecutionResult
from app.services.workflow import SOCWorkflow
from tests.test_hub_workflow import NOW, detection, ingest, run


class AcceptedProvider:
    provider_mode = "wazuh"
    agents = ["001"]
    def __init__(self):
        self.calls = 0
    async def execute_response(self, action):
        self.calls += 1
        return SIEMExecutionResult(provider="wazuh", action=action.type, target=action.target, status="SUCCESS", message="Manager accepted request", metadata={"execution_mode": "wazuh", "agents_requested": self.agents, "containment_verified": False})


def test_containment_requires_matching_trusted_post_approval_evidence():
    async def scenario(factory):
        async with factory() as db:
            await ingest(db, detection())
            workflow = SOCWorkflow()
            job = await workflow.claim(db)
            await workflow.process(db, job)
            investigation = await db.scalar(select(Investigation))
            service = ResponseActionService(siem_provider=AcceptedProvider(), clock=lambda: NOW + timedelta(minutes=1))
            action = await service.create_for_incident(db, investigation.incident_id, ResponseActionCreate(type="BLOCK_IP", target="8.8.8.8", reason="Confirmed response"))
            await service.approve(db, action.id, ResponseActionApprovalRequest(approved_by="analyst"))
            await service.execute(db, action.id)
            incident = await db.get(Incident, investigation.incident_id)
            assert incident.status != "CONTAINED"
            telemetry = detection("response-1", source="wazuh", category="behavior", when=NOW + timedelta(minutes=1))
            telemetry.attributes = {"response_action_id": str(action.id), "response_effect": "blocked", "target": "8.8.8.8"}
            evidence = await IntelligenceHub().record(db, telemetry)
            await db.commit()
            wrong = detection("response-2", source="untrusted", category="behavior", when=NOW + timedelta(minutes=1))
            wrong.attributes = telemetry.attributes
            wrong_evidence = await IntelligenceHub().record(db, wrong)
            await db.commit()
            with pytest.raises(ResponseActionConflict, match="trusted"):
                await service.verify(db, action.id, wrong_evidence.id, "Confirm")
            verified = await service.verify(db, action.id, evidence.id, "Endpoint block log confirms the effect")
            assert incident.status == "CONTAINED"
            assert verified.execution_result["metadata"]["containment_verified"] is True
            assert verified.execution_result["metadata"]["verification"]["evidence_id"] == str(evidence.id)
    run(scenario)


def test_simulated_action_cannot_be_marked_contained():
    async def scenario(factory):
        async with factory() as db:
            await ingest(db, detection())
            workflow = SOCWorkflow()
            job = await workflow.claim(db)
            await workflow.process(db, job)
            investigation = await db.scalar(select(Investigation))
            service = ResponseActionService()
            action = await service.create_for_incident(db, investigation.incident_id, ResponseActionCreate(type="BLOCK_IP", target="8.8.8.8", reason="Lab response"))
            await service.approve(db, action.id, ResponseActionApprovalRequest(approved_by="analyst"))
            await service.execute(db, action.id)
            with pytest.raises(ResponseActionConflict, match="real Wazuh"):
                await service.verify(db, action.id, uuid4(), "Confirm")
    run(scenario)


def test_containment_rejects_partial_agent_evidence_and_reconciles_uncertain_dispatch():
    async def scenario(factory):
        from app.services.siem import SIEMResponseError
        class InterruptedProvider(AcceptedProvider):
            agents = ["001", "002"]
            async def execute_response(self, action):
                raise SIEMResponseError("Dispatch response was unavailable")
        async with factory() as db:
            await ingest(db, detection())
            workflow = SOCWorkflow()
            await workflow.process(db, await workflow.claim(db))
            report = await db.scalar(select(Investigation))
            service = ResponseActionService(siem_provider=InterruptedProvider(), clock=lambda: NOW + timedelta(minutes=1))
            action = await service.create_for_incident(db, report.incident_id, ResponseActionCreate(type="BLOCK_IP", target="8.8.8.8", reason="Confirmed scoped response"))
            await service.approve(db, action.id, ResponseActionApprovalRequest(approved_by="analyst"))
            with pytest.raises(ResponseActionConflict, match="unavailable"):
                await service.execute(db, action.id)
            evidence_ids = []
            for agent in ("001", "002"):
                telemetry = detection("verified-" + agent, source="wazuh", category="behavior", when=NOW + timedelta(minutes=1))
                telemetry.alert.host.id = agent
                telemetry.attributes = {"response_action_id": str(action.id), "response_effect": "blocked", "target": "8.8.8.8"}
                evidence_ids.append((await IntelligenceHub().record(db, telemetry)).id)
            await db.commit()
            with pytest.raises(ResponseActionConflict, match="every requested agent"):
                await service.verify(db, action.id, [evidence_ids[0]], "One endpoint confirmed")
            result = await service.verify(db, action.id, evidence_ids, "Both endpoint logs confirm the block despite missing API response")
            assert result.status == "SUCCESS"
            assert result.execution_result["metadata"]["verification"]["agents_verified"] == ["001", "002"]
    run(scenario)
