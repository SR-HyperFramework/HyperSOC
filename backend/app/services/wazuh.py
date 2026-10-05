import hashlib
import json
from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.schemas.alert import AlertIngest
from app.schemas.normalized_alert import NormalizedAlert
from app.services.normalization import normalize_wazuh_alert


def compute_fingerprint(alert: AlertIngest) -> str:
    important = "|".join(
        [
            alert.source,
            alert.agent.id or "",
            alert.rule.id or "",
            alert.timestamp.isoformat(),
            alert.event.src_ip or "",
            alert.event.dst_ip or "",
            str(alert.event.src_port) if alert.event.src_port is not None else "",
            str(alert.event.dst_port) if alert.event.dst_port is not None else "",
            alert.event.username or "",
            alert.event.process_name or "",
            alert.event.process_command_line or "",
            alert.event.file_path or "",
            alert.event.file_hash or "",
        ]
    )
    source_id = alert.raw.get("id")
    if isinstance(source_id, str) and source_id:
        important = json.dumps([important, source_id], separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(important.encode()).hexdigest()


async def _find_by_fingerprint(db: AsyncSession, fingerprint: str) -> Alert | None:
    return await db.scalar(select(Alert).where(Alert.fingerprint == fingerprint))


def normalize_ingested_alert(alert: AlertIngest, *, alert_id: UUID | None = None) -> NormalizedAlert:
    """Expose the Phase 4 contract without changing Phase 3 persistence."""
    return normalize_wazuh_alert(alert.model_dump(mode="json"), alert_id=alert_id)


def normalize_persisted_alert(alert: Alert) -> NormalizedAlert:
    """Convert a stored alert row to the Phase 4 contract for downstream services."""
    if isinstance(alert.raw_event, dict) and "_canonical" in alert.raw_event:
        return NormalizedAlert.model_validate(alert.raw_event["_canonical"])
    try:
        if isinstance(alert.raw_event, dict) and alert.raw_event:
            return normalize_wazuh_alert(alert.raw_event, alert_id=alert.id)
    except ValueError:
        pass

    envelope = {
        "source": alert.source,
        "timestamp": alert.timestamp,
        "agent": {"id": alert.agent_id, "name": alert.agent_name},
        "rule": {
            "id": alert.rule_id,
            "level": alert.rule_level,
            "description": alert.rule_description,
            "groups": alert.groups,
            "mitre_ids": alert.mitre_ids,
        },
        "event": {
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "src_port": alert.src_port,
            "dst_port": alert.dst_port,
            "username": alert.username,
            "process_name": alert.process_name,
            "process_command_line": alert.process_command_line,
            "file_path": alert.file_path,
            "file_hash": alert.file_hash,
        },
        "raw": {},
    }
    return normalize_wazuh_alert(envelope, alert_id=alert.id)


async def ingest_alert(db: AsyncSession, alert: AlertIngest) -> tuple[Alert, bool]:
    fingerprint = compute_fingerprint(alert)

    existing = await _find_by_fingerprint(db, fingerprint)
    if existing:
        return existing, False

    row = Alert(
        id=uuid4(),
        external_id=alert.raw.get("id") if isinstance(alert.raw, dict) else None,
        source=alert.source,
        timestamp=alert.timestamp,
        agent_id=alert.agent.id,
        agent_name=alert.agent.name,
        rule_id=alert.rule.id,
        rule_level=alert.rule.level,
        rule_description=alert.rule.description,
        mitre_ids=alert.rule.mitre_ids,
        groups=alert.rule.groups,
        src_ip=alert.event.src_ip,
        dst_ip=alert.event.dst_ip,
        src_port=alert.event.src_port,
        dst_port=alert.event.dst_port,
        username=alert.event.username,
        process_name=alert.event.process_name,
        process_command_line=alert.event.process_command_line,
        file_path=alert.event.file_path,
        file_hash=alert.event.file_hash,
        raw_event=alert.raw,
        fingerprint=fingerprint,
        status="received",
    )
    db.add(row)
    from app.core.config import settings
    if settings.automation_enabled:
        from app.models.workflow import WorkflowJob
        db.add(WorkflowJob(
            id=uuid4(), alert_id=row.id, status="PENDING", stage="understanding",
            attempts=0, available_at=datetime.now(timezone.utc), output={},
        ))
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        existing = await _find_by_fingerprint(db, fingerprint)
        if existing:
            return existing, False
        raise
    await db.refresh(row)
    return row, True
