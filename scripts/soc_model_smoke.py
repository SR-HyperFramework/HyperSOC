"""Seed and verify a dedicated soc_model_test database for browser acceptance.

This deliberately refuses other database names. All telemetry is synthetic and
the provisioned account is for this disposable test database only.
"""
import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from sqlalchemy import select
from fastapi import Response

from app.api.hub import ingest_event
from app.core.auth import password_hash
from app.core.config import settings
from app.core.database import async_session_factory
from app.models.identity import SOCUser
from app.schemas.hub import HubEntityWrite, HubEventIn
from app.schemas.normalized_alert import NormalizedAlert, NormalizedHost, NormalizedIdentity, NormalizedNetwork, NormalizedProcess, NormalizedDetection
from app.services.behavior import BehaviorAnalytics
from app.services.hub import IntelligenceHub
from app.services.workflow import SOCWorkflow


async def main():
    if not settings.database_url.rstrip("/").endswith("/soc_model_test"):
        raise RuntimeError("This smoke fixture requires the dedicated soc_model_test database")
    if settings.ai_triage_provider_mode != "offline" or settings.investigator_provider_mode != "offline":
        raise RuntimeError("This smoke fixture requires offline AI providers")
    timestamp = datetime.now(timezone.utc)
    run_id = uuid4().hex[:12]
    hub = IntelligenceHub()
    async with async_session_factory() as db:
        user = await db.scalar(select(SOCUser).where(SOCUser.username == "smoke-admin"))
        if user is None:
            db.add(SOCUser(id=uuid4(), username="smoke-admin", role="admin", active=True, password_hash=password_hash("smoke-only-password-123")))
        asset = await hub.upsert_entity(db, HubEntityWrite(kind="asset", external_key="finance-lab-01", label="Finance lab endpoint", source="synthetic-smoke-inventory", observed_at=timestamp - timedelta(hours=1), attributes={"owner": "Finance lab", "criticality": "high", "environment": "synthetic verification"}))
        await hub.upsert_entity(db, HubEntityWrite(kind="identity", external_key="lab-analyst", label="lab-analyst", source="synthetic-smoke-directory", observed_at=timestamp - timedelta(hours=1), attributes={"department": "Finance lab", "privileged": False}))
        for index in range(25):
            await hub.record(db, HubEventIn(source="synthetic-smoke-logs", external_id=f"{run_id}-behavior-{index}", category="behavior", alert=NormalizedAlert(
                timestamp=timestamp - timedelta(days=2, minutes=index), host=NormalizedHost(name="finance-lab-01"),
                identity=NormalizedIdentity(username="lab-analyst"), process=NormalizedProcess(name="backup.exe", image="C:\\Lab\\backup.exe"),
                network=NormalizedNetwork(dst_ip="8.8.8.8"), detection=NormalizedDetection(event_family="process", level=1),
            )))
        await BehaviorAnalytics().train(db, host="finance-lab-01", since=timestamp - timedelta(days=3), until=timestamp - timedelta(days=1))
        await db.commit()
        event = HubEventIn(source="synthetic-smoke-edr", external_id=f"{run_id}-detection", alert=NormalizedAlert(
            timestamp=timestamp, host=NormalizedHost(id="001", name="finance-lab-01", ip="192.168.2.15"),
            identity=NormalizedIdentity(username="lab-analyst"), network=NormalizedNetwork(src_ip="8.8.8.8", dst_ip="9.9.9.9"),
            process=NormalizedProcess(name="powershell.exe", image="C:\\Windows\\powershell.exe", command_line="powershell.exe -NoProfile -Command Get-Date", pid=4200),
            detection=NormalizedDetection(event_family="powershell", event_kind="process", level=12, description="Synthetic verification: unusual PowerShell activity", mitre_ids=["T1059.001"]),
        ))
        received = await ingest_event(Response(), event.model_dump_json().encode(), db)
        workflow = SOCWorkflow()
        job = await workflow.claim(db)
        await workflow.process(db, job)
        assert job.status == "AWAITING_REVIEW"
        print(json.dumps({"alert_id": str(received["alert_id"]), "workflow_id": str(job.id), "investigations": job.output["investigations"], "source": "synthetic verification"}))


if __name__ == "__main__":
    asyncio.run(main())
