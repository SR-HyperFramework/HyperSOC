import asyncio
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import select

from app.core.auth import check_password, password_hash
from app.core.config import settings
from app.models.identity import AuditEvent, SOCUser
from app.models.investigation import Investigation
from app.services.workflow import SOCWorkflow
from tests.test_hub_workflow import detection, ingest, run


def test_password_storage_is_salted_and_verifies_without_plaintext():
    first = password_hash("example-test-password")
    second = password_hash("example-test-password")
    assert first != second and "example-test-password" not in first
    assert check_password("example-test-password", first)
    assert not check_password("wrong-password", first)


def test_authenticated_review_uses_account_identity_and_records_audit(monkeypatch):
    async def scenario(factory):
        import app.core.database as database
        monkeypatch.setattr(database, "async_session_factory", factory)
        monkeypatch.setattr(settings, "auth_enabled", True)
        from app.main import create_app
        application = create_app()
        async with factory() as db:
            user = SOCUser(id=uuid4(), username="alice", password_hash=password_hash("test-password-strong"), role="analyst", active=True)
            viewer = SOCUser(id=uuid4(), username="viewer", password_hash=password_hash("test-password-strong"), role="viewer", active=True)
            db.add_all([user, viewer])
            await db.commit()
            await ingest(db, detection())
            workflow = SOCWorkflow()
            job = await workflow.claim(db)
            await workflow.process(db, job)
            investigation = await db.scalar(select(Investigation))
            investigation_id = str(investigation.id)
            incident_id = str(investigation.incident_id)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=application), base_url="http://localhost:8000") as client:
            assert (await client.get("/api/v1/incidents")).status_code == 401
            login = await client.post("/api/v1/auth/login", json={"username": "alice", "password": "test-password-strong"})
            assert login.status_code == 200
            token = login.json()["access_token"]
            headers = {"Authorization": "Bearer " + token}
            assert (await client.get("/api/v1/incidents", headers=headers)).status_code == 200
            # A valid cookie does not grant cross-site mutation without its CSRF token.
            assert (await client.post(f"/api/v1/investigations/{investigation_id}/review", json={"reviewed_by": "forged-admin", "classification": "true_positive"})).status_code == 403
            review = await client.post(f"/api/v1/investigations/{investigation_id}/review", headers=headers, json={"reviewed_by": "forged-admin", "classification": "true_positive"})
            assert review.status_code == 200 and review.json()["reviewed_by"] == "alice"
            action = await client.post(f"/api/v1/incidents/{incident_id}/actions", headers=headers, json={"type": "BLOCK_IP", "target": "8.8.8.8", "reason": "Confirmed threat", "requested_by": "forged-admin"})
            assert action.status_code == 201 and action.json()["requested_by"] == "alice"
            approved = await client.post(f"/api/v1/actions/{action.json()['id']}/approve", headers=headers, json={"approved_by": "forged-admin"})
            assert approved.status_code == 200 and approved.json()["approved_by"] == "alice"
            denied = await client.put("/api/v1/hub/entities", headers=headers, json={})
            assert denied.status_code == 403  # inventory writes require administrator scope
            assert (await client.post("/api/v1/knowledge/index", headers=headers)).status_code == 403
            viewer_login = await client.post("/api/v1/auth/login", json={"username": "viewer", "password": "test-password-strong"})
            viewer_headers = {"Authorization": "Bearer " + viewer_login.json()["access_token"]}
            assert (await client.post("/api/v1/correlation/run", headers=viewer_headers)).status_code == 403
            observed = detection().alert.timestamp.isoformat()
            assert (await client.post("/api/v1/hub/search", headers=viewer_headers, json={"since": observed, "until": observed})).status_code == 200
        async with factory() as db:
            audits = (await db.scalars(select(AuditEvent).where(AuditEvent.operation == "response.approve"))).all()
            assert len(audits) == 1 and audits[0].actor == "alice" and audits[0].role == "analyst"
    run(scenario)


def test_stale_review_cannot_override_latest_report_or_approved_response(monkeypatch):
    async def scenario(factory):
        from app.models.incident import Incident
        from app.schemas.investigation import InvestigationReviewRequest
        from app.schemas.response_action import ResponseActionCreate, ResponseActionApprovalRequest
        from app.services.investigator import InvestigationService, InvestigationReviewConflict
        from app.services.knowledge_base import KnowledgeBaseService
        from app.services.response import ResponseActionService, ResponseActionConflict
        monkeypatch.setattr(settings, "auth_enabled", True)
        async with factory() as db:
            await ingest(db, detection())
            workflow = SOCWorkflow()
            job = await workflow.claim(db)
            await workflow.process(db, job)
            first = await db.scalar(select(Investigation))
            incident_id = first.incident_id
            investigator = InvestigationService(knowledge_base=KnowledgeBaseService())
            await investigator.review(db, first.id, InvestigationReviewRequest(reviewed_by="alice", classification="true_positive"))
            service = ResponseActionService()
            action = await service.create_for_incident(db, first.incident_id, ResponseActionCreate(type="BLOCK_IP", target="8.8.8.8", reason="Confirmed case"))
            await service.approve(db, action.id, ResponseActionApprovalRequest(approved_by="alice"))
            second = await investigator.run(db, first.incident_id)
            third = await investigator.run(db, first.incident_id)
            with pytest.raises(InvestigationReviewConflict, match="newer investigation"):
                await investigator.review(db, second.id, InvestigationReviewRequest(reviewed_by="alice", classification="false_positive"))
            await db.rollback()
            # A later analyst false-positive decision revokes the approved response.
            await investigator.review(db, third.id, InvestigationReviewRequest(reviewed_by="alice", classification="false_positive"))
            with pytest.raises(ResponseActionConflict, match="must still"):
                await service.execute(db, action.id)
            await db.rollback()
            incident = await db.get(Incident, incident_id)
            assert incident.status == "FALSE_POSITIVE"
    run(scenario)


def test_response_approval_requires_latest_reviewed_true_positive(monkeypatch):
    async def scenario(factory):
        from app.schemas.response_action import ResponseActionCreate, ResponseActionApprovalRequest
        from app.services.response import ResponseActionService, ResponseActionConflict
        async with factory() as db:
            await ingest(db, detection())
            workflow = SOCWorkflow()
            job = await workflow.claim(db)
            await workflow.process(db, job)
            investigation = await db.scalar(select(Investigation))
            service = ResponseActionService()
            action = await service.create_for_incident(db, investigation.incident_id, ResponseActionCreate(type="BLOCK_IP", target="8.8.8.8", reason="Draft response"))
            monkeypatch.setattr(settings, "auth_enabled", True)
            with pytest.raises(ResponseActionConflict, match="analyst-confirmed"):
                await service.approve(db, action.id, ResponseActionApprovalRequest(approved_by="alice"))
    run(scenario)


@pytest.mark.parametrize(("draft", "allowed"), [("true_positive", True), ("needs_investigation", True), ("false_positive", False)])
def test_newer_draft_blocks_containment_only_when_it_concludes_false_positive(monkeypatch, draft, allowed):
    async def scenario(factory):
        from datetime import timedelta
        from app.schemas.investigation import InvestigationReviewRequest
        from app.schemas.response_action import ResponseActionCreate, ResponseActionApprovalRequest
        from app.services.investigator import InvestigationService
        from app.services.knowledge_base import KnowledgeBaseService
        from app.services.response import ResponseActionService, ResponseActionConflict
        monkeypatch.setattr(settings, "auth_enabled", True)
        async with factory() as db:
            await ingest(db, detection())
            workflow = SOCWorkflow()
            await workflow.process(db, await workflow.claim(db))
            first = await db.scalar(select(Investigation))
            investigator = InvestigationService(knowledge_base=KnowledgeBaseService())
            await investigator.review(db, first.id, InvestigationReviewRequest(reviewed_by="alice", classification="true_positive"))
            # New evidence arrives during an active attack and produces an unreviewed draft.
            db.add(Investigation(
                id=uuid4(), incident_id=first.incident_id, provider_mode="offline", status="PENDING_REVIEW",
                plan={"tools": ["incident_alerts"]}, evidence=[],
                report={"classification": draft, "findings": [], "gaps": [], "next_steps": []},
                created_at=first.created_at + timedelta(seconds=1),
            ))
            await db.commit()
            service = ResponseActionService()
            action = await service.create_for_incident(db, first.incident_id, ResponseActionCreate(type="BLOCK_IP", target="8.8.8.8", reason="Confirmed case"))
            if allowed:
                await service.approve(db, action.id, ResponseActionApprovalRequest(approved_by="alice"))
                result = await service.execute(db, action.id)
                assert result.status == "SUCCESS"
            else:
                with pytest.raises(ResponseActionConflict, match="concludes false positive"):
                    await service.approve(db, action.id, ResponseActionApprovalRequest(approved_by="alice"))
    run(scenario)
