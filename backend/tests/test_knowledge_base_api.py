from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.knowledge_base import get_knowledge_base_service
from app.core.database import get_db
from app.main import app
from app.services.knowledge_base.service import KnowledgeBaseService


@pytest.fixture
def api_client(tmp_path: Path):
    (tmp_path / "mitre").mkdir()
    (tmp_path / "mitre" / "T1110.md").write_text(
        "# Brute Force\n\n- source: MITRE\n- technique: T1110\n\nInvestigate ssh authentication.\n",
        encoding="utf-8",
    )
    previous = dict(app.dependency_overrides)
    service = KnowledgeBaseService(root=tmp_path)

    async def fake_db():
        yield object()

    def fake_service():
        return service

    app.dependency_overrides[get_db] = fake_db
    app.dependency_overrides[get_knowledge_base_service] = fake_service
    try:
        yield TestClient(app), service
    finally:
        app.dependency_overrides = previous


def test_index_endpoint_indexes_configured_root(api_client):
    client, _service = api_client

    response = client.post("/api/v1/knowledge/index")

    assert response.status_code == 200
    assert response.json()["indexed_documents"] == 1
    assert response.json()["indexed_chunks"] >= 1


def test_search_endpoint_returns_bounded_results(api_client):
    client, _service = api_client

    response = client.get("/api/v1/knowledge/search?mitre_ids=T1110&alert_types=ssh&top_k=1")

    assert response.status_code == 200
    body = response.json()
    assert body["query"]["top_k"] == 1
    assert body["results"][0]["technique"] == "T1110"


def test_search_endpoint_validates_top_k(api_client):
    client, _service = api_client

    assert client.get("/api/v1/knowledge/search?top_k=0").status_code == 422
    assert client.get("/api/v1/knowledge/search?top_k=21").status_code == 422
