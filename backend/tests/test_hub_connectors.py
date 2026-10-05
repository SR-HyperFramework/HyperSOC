import json
from datetime import timedelta
from types import SimpleNamespace

import httpx
import pytest
from fastapi import HTTPException, Response
from sqlalchemy import func, select

from app.api.hub import ingest_native_event, import_inventory
from app.core.config import settings
from app.models.alert import Alert
from app.models.hub import HubEvidence, HubRelationship
from app.models.workflow import WorkflowJob
from app.schemas.hub import HubInventoryBatch
from app.services.connectors import NativeEventRequest, adapt
from app.services.workflow import SOCWorkflow
from app.workers.import_hub import signed_headers
from tests.test_hub_workflow import NOW, run


def ecs_event():
    return {"@timestamp": NOW.isoformat(), "event": {"id": "edr-1", "kind": "alert", "category": ["process"], "severity": 80},
        "host": {"name": "SERVER-A", "ip": ["invalid", "192.168.1.8"]}, "user": {"name": "alice"},
        "process": {"name": "powershell.exe", "pid": 51, "executable": "C:\\Windows\\powershell.exe"},
        "destination": {"ip": "8.8.8.8", "port": 443}, "rule": {"id": "edr-rule", "name": "Observed script process"},
        "threat": {"technique": {"id": "T1059", "subtechnique": {"id": "T1059.001"}}}}


def test_ecs_adapter_retains_severity_units_source_and_native_identity():
    event = adapt(NativeEventRequest(format="ecs", source="edr-prod", event=ecs_event()))[0]
    assert event.category == "detection" and event.alert.detection.source == "edr-prod"
    assert event.external_id == "edr-1" and event.alert.host.ip == "192.168.1.8"
    assert event.alert.detection.level is None  # native severity 80 is not a Wazuh level
    assert event.attributes["native_severity"] == 80
    assert event.alert.detection.mitre_ids == ["T1059", "T1059.001"]
    flattened = {"@timestamp": NOW.isoformat(), "event.id": "flat-1", "event.kind": "alert", "host.name": "host-flat", "process.pid": "52"}
    assert adapt(NativeEventRequest(format="ecs", source="edr-prod", event=flattened))[0].alert.process.pid == 52


def test_osquery_batch_and_snapshot_are_behavior_and_replay_stably():
    payload = {"name": "processes", "hostIdentifier": "server-a", "unixTime": NOW.timestamp(), "epoch": "1", "counter": "2",
        "diffResults": {"added": [{"name": "backup", "path": "/usr/bin/backup", "pid": "123"}], "removed": [{"name": "old", "pid": "122"}]}}
    request = NativeEventRequest(format="osquery", source="osquery-prod", event=payload)
    first, second = adapt(request), adapt(request)
    assert [item.external_id for item in first] == [item.external_id for item in second]
    assert len({item.external_id for item in first}) == 2
    assert all(item.category == "behavior" for item in first)
    assert first[0].alert.process.pid == 123 and first[1].attributes["action"] == "removed"
    snapshot = {**payload, "snapshot": payload["diffResults"]["added"]}
    assert adapt(NativeEventRequest(format="osquery", source="osquery-prod", event=snapshot))[0].attributes["action"] == "snapshot"


def test_native_batch_uses_signed_http_contract_and_atomically_queues_detection(monkeypatch):
    async def scenario(factory):
        import app.core.database as database
        from app.main import create_app
        monkeypatch.setattr(database, "async_session_factory", factory)
        monkeypatch.setattr(settings, "auth_enabled", True)
        monkeypatch.setattr(settings, "hub_source_keys", json.dumps({"edr-prod": "dedicated-edr-source-key", "wazuh": "dedicated-wazuh-source-key"}))
        body = NativeEventRequest(format="ecs", source="edr-prod", event=ecs_event()).model_dump_json().encode()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app()), base_url="http://localhost:8000") as client:
            assert (await client.post("/api/v1/hub/native-events", content=body)).status_code == 401
            assert (await client.post("/api/v1/hub/native-events", content=body, headers=signed_headers(settings.app_secret_key, body))).status_code == 401
            first = await client.post("/api/v1/hub/native-events", content=body, headers=signed_headers("dedicated-edr-source-key", body))
            assert first.status_code == 201
            again = await client.post("/api/v1/hub/native-events", content=body, headers=signed_headers("dedicated-edr-source-key", body))
            assert again.status_code == 200 and again.json()["events"] == first.json()["events"]
            changed = ecs_event()
            changed["process"]["name"] = "changed.exe"
            altered = NativeEventRequest(format="ecs", source="edr-prod", event=changed).model_dump_json().encode()
            assert (await client.post("/api/v1/hub/native-events", content=altered, headers=signed_headers("dedicated-edr-source-key", altered))).status_code == 409
            spoofed = NativeEventRequest(format="ecs", source="wazuh", event=ecs_event()).model_dump_json().encode()
            assert (await client.post("/api/v1/hub/native-events", content=spoofed, headers=signed_headers("dedicated-edr-source-key", spoofed))).status_code == 401
        async with factory() as db:
            assert await db.scalar(select(func.count()).select_from(Alert)) == 1
            assert await db.scalar(select(func.count()).select_from(WorkflowJob)) == 1
            workflow = SOCWorkflow()
            job = await workflow.claim(db)
            await workflow.process(db, job)
            assert job.status == "AWAITING_REVIEW"
            assert "edr-prod" in job.output["internal_context"]["sources"]
    run(scenario)


def test_native_posture_and_behavior_do_not_create_incident_jobs():
    async def scenario(factory):
        async with factory() as db:
            payload = ecs_event()
            payload["event"] = {"id": "posture-1", "kind": "state", "category": ["vulnerability"]}
            payload["vulnerability"] = {"id": "CVE-2025-0000", "severity": "critical"}
            body = NativeEventRequest(format="ecs", source="posture-prod", event=payload).model_dump_json().encode()
            await ingest_native_event(Response(), body, db)
            assert (await db.scalar(select(HubEvidence))).category == "posture"
            assert await db.scalar(select(func.count()).select_from(WorkflowJob)) == 0
            assert await db.scalar(select(func.count()).select_from(Alert)) == 0
    run(scenario)


def test_inventory_batch_resolves_keys_idempotently_and_rejects_missing_endpoint():
    async def scenario(factory):
        async with factory() as db:
            batch = HubInventoryBatch.model_validate({"entities": [
                {"kind": "asset", "external_key": "SERVER-A", "label": "Server", "source": "cmdb", "observed_at": NOW.isoformat(), "attributes": {"owner": "finance"}},
                {"kind": "identity", "external_key": "alice", "label": "Alice", "source": "directory", "observed_at": NOW.isoformat(), "attributes": {"privileged": True}}],
                "relationships": [{"source_kind": "identity", "source_key": "alice", "target_kind": "asset", "target_key": "SERVER-A", "relation": "administers",
                    "source_ref": "directory:alice:server-a", "observed_at": NOW.isoformat()}]})
            first = await import_inventory(batch, db)
            assert await import_inventory(batch, db) == first
            assert await db.scalar(select(func.count()).select_from(HubRelationship)) == 1
            broken = batch.model_copy(deep=True)
            broken.relationships[0].target_key = "missing-host"
            with pytest.raises(HTTPException) as error:
                await import_inventory(broken, db)
            assert error.value.status_code == 422
    run(scenario)
