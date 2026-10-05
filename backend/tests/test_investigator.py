import asyncio
import json
from datetime import datetime, timezone
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import app
from app.core.config import Settings
from app.models.incident import Incident
from app.schemas.investigation import (
    EvidenceItem,
    InvestigationDraft,
    InvestigationFinding,
    InvestigationPlan,
    InvestigationReviewRequest,
)
from app.services.investigator import InvestigationReviewConflict, InvestigationService, InvestigationValidationError
from app.services.investigator import OpenRouterInvestigatorProvider, InvestigationProviderError
from app.services.knowledge_base import KnowledgeBaseService

INCIDENT_ID = UUID("00000000-0000-0000-0000-000000000200")
NOW = datetime(2026, 9, 27, 0, 0, tzinfo=timezone.utc)


class FakeDb:
    def __init__(self, incident):
        self.incident = incident
        self.row = None
        self.commits = 0

    async def get(self, model, item_id, **kwargs):
        return self.incident if model is Incident and item_id == INCIDENT_ID else None

    async def scalar(self, statement):
        return self.row

    async def scalars(self, statement):
        from types import SimpleNamespace
        return SimpleNamespace(all=lambda: [])

    async def flush(self):
        pass

    def add(self, row):
        self.row = row

    async def commit(self):
        self.commits += 1

    async def refresh(self, row):
        row.created_at = NOW


class FakeProvider:
    model = "test-model"

    def __init__(self, draft):
        self.draft = draft
        self.overviews = []
        self.evidence = []

    async def plan(self, overview):
        self.overviews.append(overview)
        return InvestigationPlan(tools=["incident_alerts"])

    async def report(self, overview, evidence):
        self.evidence = evidence
        return self.draft


def incident():
    return Incident(
        id=INCIDENT_ID, title="Repeated SSH failures", status="NEW", severity="high", confidence=60,
        first_seen=NOW, last_seen=NOW, alert_count=3, primary_host="server-a",
        primary_user="root", primary_src_ip="192.0.2.5", mitre_ids=["T1110"],
    )


def alert_evidence():
    return EvidenceItem(
        id="pending", tool="incident_alerts", source="wazuh_normalized_alert", source_ref="alert-1",
        observed_at=NOW, collected_at=NOW, content="Repeated SSH failures",
    )


def test_tool_allowlist_rejects_unapproved_and_duplicate_calls():
    with pytest.raises(ValidationError):
        InvestigationPlan(tools=["run_shell"])
    with pytest.raises(ValidationError):
        InvestigationPlan(tools=["incident_alerts", "incident_alerts"])


def test_run_persists_only_selected_tool_and_cited_finding():
    async def scenario():
        provider = FakeProvider(InvestigationDraft(
            classification="needs_investigation",
            findings=[InvestigationFinding(claim="SSH failures were observed", evidence_ids=["E01"])],
        ))
        service = InvestigationService(knowledge_base=KnowledgeBaseService(), provider=provider, provider_mode="openrouter")
        calls = []

        async def alerts(_db, incident_id):
            calls.append(incident_id)
            return [alert_evidence()]

        async def unexpected(*_args):
            raise AssertionError("Unselected tool was called")

        service._incident_alerts = alerts
        service._cached_intel = unexpected
        service._knowledge_search = unexpected
        db = FakeDb(incident())
        result = await service.run(db, INCIDENT_ID)

        assert calls == [INCIDENT_ID]
        assert db.commits == 1
        assert result.plan.tools == ["incident_alerts"]
        assert result.evidence[0].id == "E01"
        assert result.report.findings[0].evidence_ids == ["E01"]
        assert result.status == "PENDING_REVIEW"

    asyncio.run(scenario())


def test_unknown_citation_blocks_persistence():
    async def scenario():
        provider = FakeProvider(InvestigationDraft(
            classification="true_positive",
            findings=[InvestigationFinding(claim="Compromise confirmed", evidence_ids=["E99"])],
        ))
        service = InvestigationService(knowledge_base=KnowledgeBaseService(), provider=provider, provider_mode="openrouter")

        async def alerts(_db, _incident_id):
            return [alert_evidence()]

        service._incident_alerts = alerts
        db = FakeDb(incident())
        with pytest.raises(InvestigationValidationError, match="unknown evidence ID"):
            await service.run(db, INCIDENT_ID)
        assert db.row is None
        assert db.commits == 0

    asyncio.run(scenario())


def test_decisive_label_requires_incident_observation():
    service = InvestigationService(knowledge_base=KnowledgeBaseService())
    evidence = [EvidenceItem(
        id="E01", tool="knowledge_search", source="MITRE", source_ref="guide.md",
        collected_at=NOW, content="Generic guide",
    )]
    report = InvestigationDraft(
        classification="true_positive",
        findings=[InvestigationFinding(claim="Compromise", evidence_ids=["E01"])],
    )
    with pytest.raises(InvestigationValidationError, match="incident observation"):
        service._validate_report(report, evidence)


def test_review_is_one_time_and_preserves_machine_report():
    async def scenario():
        service = InvestigationService(knowledge_base=KnowledgeBaseService())
        db = FakeDb(incident())
        from app.models.investigation import Investigation
        db.row = Investigation(
            id=UUID("00000000-0000-0000-0000-000000000300"), incident_id=INCIDENT_ID,
            provider_mode="offline", model_name=None, status="PENDING_REVIEW",
            plan={"tools": ["incident_alerts"]}, evidence=[],
            report={"classification": "needs_investigation", "findings": [], "gaps": [], "next_steps": []},
            created_at=NOW,
        )
        review = InvestigationReviewRequest(reviewed_by="analyst", classification="false_positive", notes="Known test")
        result = await service.review(db, db.row.id, review)
        assert result.status == "CORRECTED"
        assert result.report.classification == "needs_investigation"
        assert result.final_classification == "false_positive"
        with pytest.raises(InvestigationReviewConflict):
            await service.review(db, db.row.id, review)

    asyncio.run(scenario())


def test_reviewer_name_cannot_be_blank():
    with pytest.raises(ValidationError):
        InvestigationReviewRequest(reviewed_by="  ", classification="unknown")


def test_openrouter_investigator_can_reuse_openrouter_jev_key():
    config = Settings(
        _env_file=None,
        app_secret_key="test-secret-at-least-16-chars",
        typesafe_base_url="https://openrouter.ai/api",
        typesafe_api_key="shared-test-key",
        investigator_provider_mode="openrouter",
        investigator_model="example/structured-model",
    )
    config.validate_runtime_settings()
    assert config.investigator_api_key() == "shared-test-key"


def test_console_is_served_from_backend():
    response = TestClient(app).get("/investigator")
    assert response.status_code == 200
    assert "Incident investigator" in response.text


def test_openrouter_plan_uses_strict_schema_and_bounded_output(monkeypatch):
    captured = {}

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"choices": [{"message": {"content": json.dumps({"tools": ["incident_alerts"]})}}]}

    class FakeClient:
        def __init__(self, **kwargs):
            captured["client"] = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            pass

        async def post(self, url, *, headers, json):
            captured.update({"url": url, "headers": headers, "payload": json})
            return FakeResponse()

    monkeypatch.setattr("app.services.investigator.httpx.AsyncClient", FakeClient)
    provider = OpenRouterInvestigatorProvider("test-key", "test-model", 12)
    plan = asyncio.run(provider.plan({"id": str(INCIDENT_ID)}))

    assert plan.tools == ["incident_alerts"]
    assert captured["url"] == "https://openrouter.ai/api/v1/chat/completions"
    assert captured["headers"]["Authorization"] == "Bearer test-key"
    assert captured["payload"]["provider"]["require_parameters"] is True
    assert captured["payload"]["response_format"]["json_schema"]["strict"] is True
    assert captured["payload"]["max_tokens"] <= 1600
    assert captured["payload"]["reasoning"] == {"effort": "none"}
    assert captured["client"]["timeout"] == 12


def test_openrouter_rejects_truncated_response_even_when_content_is_valid_json(monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"choices": [{"finish_reason": "length", "message": {"content": '{"tools":["incident_alerts"]}'}}]}

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            pass

        async def post(self, *_args, **_kwargs):
            return FakeResponse()

    monkeypatch.setattr("app.services.investigator.httpx.AsyncClient", FakeClient)
    provider = OpenRouterInvestigatorProvider("test-key", "test-model", 12)
    with pytest.raises(InvestigationProviderError, match="token budget"):
        asyncio.run(provider.plan({"id": str(INCIDENT_ID)}))
