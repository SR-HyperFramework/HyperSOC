import hashlib
from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.config import settings
from app.core.auth import audit
from app.core.security import verify_hub_signature
from app.models.alert import Alert
from app.models.hub import HubEntity, HubEvidence
from app.models.incident import Incident
from app.models.workflow import WorkflowJob
from app.schemas.hub import BehaviorTrainingRequest, HubContext, HubEntityOut, HubEntityWrite, HubEventIn, HubGraph, HubInventoryBatch, HubRelationshipOut, HubRelationshipWrite, HubSearch
from app.services.connectors import NativeEventRequest, adapt
from app.services.hub import IntelligenceHub, insert_once

router = APIRouter(prefix="/api/v1/hub", tags=["intelligence-hub"])
hub = IntelligenceHub()


@router.post("/events")
async def ingest_event(response: Response, raw_body: bytes = Depends(verify_hub_signature), db: AsyncSession = Depends(get_db)):
    try:
        request = HubEventIn.model_validate_json(raw_body)
    except (ValidationError, ValueError) as exc:
        raise HTTPException(400, "Invalid canonical event") from exc
    result, created = await persist_event(db, request)
    await db.commit()
    response.status_code = 201 if created else 200
    return result


async def persist_event(db: AsyncSession, request: HubEventIn):
    alert_id = None
    created = False
    normalized = request.alert
    if request.category == "detection":
        fingerprint = hashlib.sha256(f"hub:{request.source}:{request.external_id}".encode()).hexdigest()
        candidate_id = uuid4()
        canonical = normalized.model_copy(update={"id": candidate_id})
        row, created = await insert_once(db, Alert, {
            "source": request.source, "external_id": request.external_id, "timestamp": normalized.timestamp,
            "agent_id": normalized.host.id, "agent_name": normalized.host.name,
            "rule_id": normalized.detection.rule_id, "rule_level": normalized.detection.level,
            "rule_description": normalized.detection.description, "groups": normalized.detection.groups,
            "mitre_ids": normalized.detection.mitre_ids, "src_ip": normalized.network.src_ip,
            "dst_ip": normalized.network.dst_ip, "src_port": normalized.network.src_port, "dst_port": normalized.network.dst_port,
            "username": normalized.identity.username, "process_name": normalized.process.name,
            "process_command_line": normalized.process.command_line, "file_path": normalized.file.path,
            "file_hash": normalized.file.hash or normalized.process.hash, "fingerprint": fingerprint,
            "raw_event": {"_canonical": canonical.model_dump(mode="json")}, "status": "received",
        }, [Alert.fingerprint == fingerprint])
        # insert_once supplies its own UUID; use the authoritative row ID throughout.
        alert_id = row.id
        if created:
            canonical = normalized.model_copy(update={"id": row.id})
            row.raw_event = {"_canonical": canonical.model_dump(mode="json")}
            if settings.automation_enabled:
                db.add(WorkflowJob(id=uuid4(), alert_id=row.id, status="PENDING", stage="understanding", attempts=0, available_at=datetime.now(timezone.utc), output={}))
    existing = await db.scalar(select(HubEvidence).where(HubEvidence.source == request.source, HubEvidence.external_id == request.external_id))
    try:
        evidence = await hub.record(db, request, alert_id=alert_id)
    except ValueError as exc:
        await db.rollback()
        raise HTTPException(409, str(exc)) from exc
    return {"evidence_id": evidence.id, "alert_id": alert_id, "automation_queued": bool(alert_id and settings.automation_enabled)}, existing is None


@router.post("/native-events")
async def ingest_native_event(response: Response, raw_body: bytes = Depends(verify_hub_signature), db: AsyncSession = Depends(get_db)):
    try:
        native = NativeEventRequest.model_validate_json(raw_body)
        events = adapt(native)
    except (ValidationError, ValueError, TypeError, KeyError, OverflowError) as exc:
        raise HTTPException(400, "Invalid native event") from exc
    results, created = [], False
    for event in events:
        result, inserted = await persist_event(db, event)
        results.append(result)
        created |= inserted
    await db.commit()
    response.status_code = 201 if created else 200
    return {"format": native.format, "source": native.source, "events": results}


@router.post("/inventory")
async def import_inventory(request: HubInventoryBatch, db: AsyncSession = Depends(get_db)):
    try:
        result = await hub.import_inventory(db, request)
    except ValueError as exc:
        await db.rollback()
        raise HTTPException(422, str(exc)) from exc
    audit(db, "hub.inventory_import", "inventory", details={"entities": len(result["entity_ids"]), "relationships": len(result["relationship_ids"])})
    await db.commit()
    return result


@router.put("/entities", response_model=HubEntityOut)
async def upsert_entity(request: HubEntityWrite, db: AsyncSession = Depends(get_db)):
    row = await hub.upsert_entity(db, request)
    audit(db, "hub.entity_upsert", str(row.id), details={"source": request.source, "kind": request.kind})
    await db.commit()
    return row


@router.get("/entities", response_model=list[HubEntityOut])
async def list_entities(kind: str | None = None, key: str | None = None, limit: int = Query(50, ge=1, le=200), db: AsyncSession = Depends(get_db)):
    statement = select(HubEntity)
    if kind:
        statement = statement.where(HubEntity.kind == kind)
    if key:
        statement = statement.where(HubEntity.external_key == key.casefold())
    return list((await db.scalars(statement.order_by(HubEntity.observed_at.desc()).limit(limit))).all())


@router.post("/relationships", response_model=HubRelationshipOut)
async def add_relationship(request: HubRelationshipWrite, db: AsyncSession = Depends(get_db)):
    try:
        row = await hub.add_relationship(db, request)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    audit(db, "hub.relationship_add", str(row.id), details={"source_ref": request.source_ref})
    await db.commit()
    return row


@router.get("/entities/{entity_id}/graph", response_model=HubGraph)
async def explore_graph(entity_id: UUID, hops: int = Query(2, ge=1, le=3), limit: int = Query(100, ge=1, le=200), db: AsyncSession = Depends(get_db)):
    try:
        return await hub.graph(db, entity_id, hops=hops, limit=limit)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.post("/search")
async def search_evidence(request: HubSearch, db: AsyncSession = Depends(get_db)):
    rows = await hub.search(db, request)
    return {"schema_version": "1.0", "evidence": [hub.evidence_out(row) for row in rows], "limit": request.limit, "possibly_truncated": len(rows) == request.limit}


@router.get("/incidents/{incident_id}/context", response_model=HubContext)
async def incident_context(incident_id: UUID, db: AsyncSession = Depends(get_db)):
    incident = await db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(404, "Incident not found")
    return await hub.context(db, incident)


@router.post("/models/train")
async def train_behavior(request: BehaviorTrainingRequest, db: AsyncSession = Depends(get_db)):
    from app.services.behavior import BehaviorAnalytics
    try:
        model = await BehaviorAnalytics().train(db, host=request.host, since=request.since, until=request.until)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    audit(db, "hub.model_train", str(model.id), details={"host": model.host_key, "sample_count": model.sample_count})
    await db.commit()
    return {"id": model.id, "algorithm": model.algorithm, "host": model.host_key, "sample_count": model.sample_count,
        "trained_since": model.trained_since, "trained_until": model.trained_until, "corpus_digest": model.corpus_digest}
