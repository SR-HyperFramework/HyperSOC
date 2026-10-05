"""The single internal-context boundary used by SOC automation and LLM tools."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from uuid import UUID, uuid4

from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import aliased
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.models.hub import HubEntity, HubEvidence, HubRelationship
from app.models.incident import Incident, IncidentAlert
from app.models.investigation import Investigation
from app.schemas.hub import (
    HubContext, HubEntityOut, HubEntityWrite, HubEventIn, HubGraph,
    HubRelationshipOut, HubRelationshipWrite, HubSearch,
    HubInventoryBatch,
)
from app.services.threat_intel.indicators import extract_indicators
from app.services.wazuh import normalize_persisted_alert


def utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


async def insert_once(db: AsyncSession, model, values: dict, predicates: list):
    """Unique indexes arbitrate competing writers without rolling back the caller."""
    existing = await db.scalar(select(model).where(*predicates))
    if existing is not None:
        return existing, False
    row = model(id=uuid4(), **values)
    try:
        async with db.begin_nested():
            db.add(row)
            await db.flush()
        return row, True
    except IntegrityError:
        row = await db.scalar(select(model).where(*predicates))
        if row is None:
            raise
        return row, False


class IntelligenceHub:
    async def import_inventory(self, db: AsyncSession, batch: HubInventoryBatch) -> dict:
        entities = [await self.upsert_entity(db, item) for item in batch.entities]
        edges = []
        for item in batch.relationships:
            endpoints = []
            for kind, key in ((item.source_kind, item.source_key), (item.target_kind, item.target_key)):
                key = key.casefold() if kind in {"asset", "identity", "domain"} else key
                row = await db.scalar(select(HubEntity).where(HubEntity.kind == kind, HubEntity.external_key == key))
                if row is None:
                    raise ValueError(f"Inventory relationship endpoint does not exist: {kind}:{key}")
                endpoints.append(row.id)
            edges.append(await self.add_relationship(db, HubRelationshipWrite(
                source_id=endpoints[0], target_id=endpoints[1], **item.model_dump(exclude={"source_kind", "source_key", "target_kind", "target_key"}),
            )))
        return {"entity_ids": [str(row.id) for row in entities], "relationship_ids": [str(row.id) for row in edges]}

    async def upsert_entity(self, db: AsyncSession, request: HubEntityWrite) -> HubEntity:
        key = request.external_key.casefold() if request.kind in {"asset", "identity", "domain"} else request.external_key
        values = request.model_dump()
        values["external_key"] = key
        values["attributes"] = {**request.attributes, "inventory": request.kind in {"asset", "identity"}}
        row, created = await insert_once(db, HubEntity, values, [HubEntity.kind == request.kind, HubEntity.external_key == key])
        if not created:
            row = await db.scalar(select(HubEntity).where(HubEntity.id == row.id).with_for_update())
            if not row.attributes.get("inventory") or utc(request.observed_at) >= utc(row.observed_at):
                row.label = request.label
                row.attributes = {**row.attributes, **values["attributes"]}
                row.source = request.source
                row.observed_at = request.observed_at
        await db.flush()
        return row

    async def add_relationship(self, db: AsyncSession, request: HubRelationshipWrite) -> HubRelationship:
        if await db.get(HubEntity, request.source_id) is None or await db.get(HubEntity, request.target_id) is None:
            raise ValueError("Both relationship endpoints must exist")
        row, _ = await insert_once(db, HubRelationship, request.model_dump(), [
            HubRelationship.source_id == request.source_id, HubRelationship.target_id == request.target_id,
            HubRelationship.relation == request.relation, HubRelationship.source_ref == request.source_ref,
        ])
        return row

    async def project_alert(self, db: AsyncSession, alert: Alert) -> HubEvidence:
        existing = await db.scalar(select(HubEvidence).where(HubEvidence.alert_id == alert.id).limit(1))
        if existing is not None:
            return existing
        normalized = normalize_persisted_alert(alert)
        event = HubEventIn(
            source=alert.source, external_id=alert.external_id or str(alert.id), alert=normalized,
            category="detection", attributes={"native_ref": normalized.raw_ref},
        )
        return await self.record(db, event, alert_id=alert.id)

    async def record(self, db: AsyncSession, event: HubEventIn, *, alert_id: UUID | None = None) -> HubEvidence:
        normalized = event.alert
        host_key = (normalized.host.name or normalized.host.id or normalized.host.ip or "").casefold() or None
        user = normalized.identity.username or normalized.identity.actor or normalized.identity.target
        identity_key = (f"{normalized.identity.domain}\\{user}" if normalized.identity.domain and user else user)
        identity_key = identity_key.casefold() if identity_key else None
        canonical_content = event.model_dump(mode="json", exclude={"alert": {"id"}})
        digest = hashlib.sha256(json.dumps(canonical_content, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        row, created = await insert_once(db, HubEvidence, {
            "source": event.source, "external_id": event.external_id, "alert_id": alert_id,
            "category": event.category, "timestamp": normalized.timestamp, "host_key": host_key,
            "identity_key": identity_key, "normalized": normalized.model_dump(mode="json"),
            "attributes": {**event.attributes, "schema_version": event.schema_version, "content_digest": digest},
        }, [HubEvidence.source == event.source, HubEvidence.external_id == event.external_id])
        if not created and row.attributes.get("content_digest") != digest:
            raise ValueError("The source event ID already exists with different content")
        # Retrying a partially projected event reconstructs missing edges as well.
        source_ref = f"hub_evidence:{row.id}"

        async def entity(kind, key, label=None, attributes=None):
            key = str(key)[:512]
            if kind in {"asset", "identity", "domain"}:
                key = key.casefold()
            value, _ = await insert_once(db, HubEntity, {
                "kind": kind, "external_key": key, "label": (label or key)[:512],
                "attributes": attributes or {}, "source": event.source, "observed_at": normalized.timestamp,
            }, [HubEntity.kind == kind, HubEntity.external_key == key])
            return value

        async def edge(a, b, relation):
            if a is not None and b is not None:
                await self.add_relationship(db, HubRelationshipWrite(
                    source_id=a.id, target_id=b.id, relation=relation, source_ref=source_ref,
                    observed_at=normalized.timestamp,
                ))

        asset = await entity("asset", host_key, normalized.host.name, {"agent_id": normalized.host.id}) if host_key else None
        identity = await entity("identity", identity_key, user) if identity_key else None
        await edge(identity, asset, "observed_on")
        if asset and normalized.host.ip:
            await edge(asset, await entity("ip", normalized.host.ip), "has_ip")
        process_key = normalized.process.guid or (
            f"{host_key}:{normalized.process.pid}:{normalized.timestamp.isoformat()}" if normalized.process.pid
            else f"{host_key}:{normalized.process.image or normalized.process.name}"
        )
        process = await entity("process", process_key, normalized.process.image or normalized.process.name) if normalized.process.image or normalized.process.name else None
        await edge(asset, process, "executes")
        await edge(identity, process, "runs")
        for indicator in extract_indicators(normalized):
            if indicator.type == "url":
                continue  # URLs remain in canonical evidence, not an unbounded graph key.
            node = await entity(indicator.type, indicator.value)
            await edge(process or asset or identity, node, "observed_indicator")
        if normalized.network.dst_ip:
            await edge(process or asset, await entity("ip", normalized.network.dst_ip), "connects_to")
        if normalized.file.path:
            file = await entity("file", f"{host_key}:{normalized.file.path}", normalized.file.path)
            await edge(process or asset, file, "touches")
        for technique in normalized.detection.mitre_ids:
            await edge(process or asset or identity, await entity("technique", technique), "exhibits")
        await db.flush()
        return row

    async def search(self, db: AsyncSession, query: HubSearch) -> list[HubEvidence]:
        statement = select(HubEvidence).where(HubEvidence.timestamp >= query.since, HubEvidence.timestamp <= query.until)
        if query.host:
            statement = statement.where(HubEvidence.host_key == query.host.casefold())
        if query.identity:
            statement = statement.where(HubEvidence.identity_key == query.identity.casefold())
        if query.source:
            statement = statement.where(HubEvidence.source == query.source)
        if query.category:
            statement = statement.where(HubEvidence.category == query.category)
        result = await db.scalars(statement.order_by(HubEvidence.timestamp.desc(), HubEvidence.id).limit(query.limit))
        return list(result.all())

    async def graph(self, db: AsyncSession, root_id: UUID, *, hops: int = 2, limit: int = 100, until: datetime | None = None) -> HubGraph:
        if not 1 <= hops <= 3 or not 1 <= limit <= 200:
            raise ValueError("graph hops must be 1..3 and limit 1..200")
        root = await db.get(HubEntity, root_id)
        if root is None:
            raise ValueError("Entity not found")
        nodes = {root.id: root}
        edges = {}
        frontier = {root.id}
        truncated = False
        for _ in range(hops):
            if not frontier:
                break
            # Repeated logs retain every source edge in storage. Exploration uses
            # the latest representative per relation, so normal baseline traffic
            # cannot consume the entire graph budget with duplicate edges.
            conditions = [or_(
                HubRelationship.source_id.in_(frontier), HubRelationship.target_id.in_(frontier),
            )]
            if until:
                conditions.append(HubRelationship.observed_at <= until)
            ranked = select(HubRelationship, func.row_number().over(
                partition_by=(HubRelationship.source_id, HubRelationship.target_id, HubRelationship.relation),
                order_by=(HubRelationship.observed_at.desc(), HubRelationship.id),
            ).label("relation_rank")).where(*conditions).subquery()
            representative = aliased(HubRelationship, ranked)
            found = await db.scalars(select(representative).where(ranked.c.relation_rank == 1)
                .order_by(case((representative.source_ref.like("hub_evidence:%"), 1), else_=0),
                    representative.observed_at.desc(), representative.id).limit(limit + 1))
            found = list(found.all())
            truncated |= len(found) > limit
            next_frontier = set()
            for relationship in found[:limit]:
                if relationship.id in edges:
                    continue
                endpoints = {relationship.source_id, relationship.target_id}
                missing = endpoints - nodes.keys()
                if len(edges) >= limit or len(nodes) + len(missing) > limit + 1:
                    truncated = True
                    continue
                for node_id in missing:
                    node = await db.get(HubEntity, node_id)
                    if node is not None:
                        nodes[node_id] = node
                        next_frontier.add(node_id)
                if endpoints <= nodes.keys():
                    edges[relationship.id] = relationship
            frontier = next_frontier
        return HubGraph(
            nodes=[HubEntityOut.model_validate(row) for row in nodes.values()],
            edges=[HubRelationshipOut.model_validate(row) for row in edges.values()], truncated=truncated,
        )

    @staticmethod
    def evidence_out(row: HubEvidence) -> dict:
        return {
            "id": str(row.id), "alert_id": str(row.alert_id) if row.alert_id else None,
            "source": row.source, "source_ref": row.external_id, "category": row.category,
            "timestamp": utc(row.timestamp).isoformat(), "normalized": row.normalized,
            "attributes": row.attributes,
        }

    async def alert_context(self, db: AsyncSession, alert: Alert) -> HubContext:
        normalized = normalize_persisted_alert(alert)
        incident = Incident(
            id=alert.id, title=normalized.detection.description or "Alert context",
            status="NEW", severity=normalized.detection.severity or "medium", confidence=0,
            first_seen=normalized.timestamp, last_seen=normalized.timestamp,
            primary_host=normalized.host.name or normalized.host.id,
            primary_user=normalized.identity.username, primary_src_ip=normalized.network.src_ip,
            mitre_ids=normalized.detection.mitre_ids, alert_count=1,
        )
        context = await self.context(db, incident)
        context.incident_id, context.alert_id = None, alert.id
        return context

    async def context(self, db: AsyncSession, incident: Incident) -> HubContext:
        result = HubContext(incident_id=incident.id, collected_at=datetime.now(timezone.utc))
        identity_keys = {incident.primary_user.casefold()} if incident.primary_user else set()
        keys = {incident.primary_host.casefold()} if incident.primary_host else set()
        linked = await db.scalars(select(HubEvidence.identity_key).where(or_(
            HubEvidence.alert_id.in_(select(IncidentAlert.alert_id).where(IncidentAlert.incident_id == incident.id)),
            HubEvidence.alert_id == incident.id,
        ), HubEvidence.identity_key.is_not(None)).limit(20))
        identity_keys.update(linked.all())
        keys.update(identity_keys)
        entities = await db.scalars(select(HubEntity).where(
            HubEntity.kind.in_(["asset", "identity"]),
            or_(HubEntity.external_key.in_(keys), HubEntity.label.in_([incident.primary_host, incident.primary_user])),
        ).limit(20))
        for entity in entities.all():
            out = HubEntityOut.model_validate(entity)
            (result.assets if entity.kind == "asset" else result.identities).append(out)
        for kind, values in (("asset", result.assets), ("identity", result.identities)):
            if not any(value.attributes.get("inventory") for value in values):
                result.gaps.append(f"No authoritative {kind} inventory is available for this incident.")
            elif any(result.collected_at - utc(value.observed_at) > timedelta(days=30) for value in values if value.attributes.get("inventory")):
                result.gaps.append(f"{kind.capitalize()} inventory is older than 30 days.")

        pivots = []
        if incident.primary_host:
            pivots.append(HubEvidence.host_key == incident.primary_host.casefold())
        if incident.primary_user:
            pivots.append(HubEvidence.identity_key.in_(identity_keys))
        if pivots:
            records = await db.scalars(select(HubEvidence).where(
                or_(*pivots), HubEvidence.timestamp >= utc(incident.first_seen) - timedelta(hours=24),
                HubEvidence.timestamp <= utc(incident.last_seen),
            ).order_by(HubEvidence.timestamp.desc()).limit(30))
            result.evidence = [self.evidence_out(row) for row in records.all()]
            # Posture can predate the incident and is not implicitly considered current.
            posture = await db.scalars(select(HubEvidence).where(
                or_(*pivots), HubEvidence.category == "posture",
                HubEvidence.timestamp <= utc(incident.last_seen),
                HubEvidence.timestamp >= utc(incident.last_seen) - timedelta(days=90),
            ).order_by(HubEvidence.timestamp.desc()).limit(10))
            known = {item["id"] for item in result.evidence}
            result.evidence.extend(self.evidence_out(row) for row in posture.all() if str(row.id) not in known)
        for category in ("behavior", "posture"):
            if not any(item["category"] == category for item in result.evidence):
                result.gaps.append(f"No {category} evidence is available in the selected time window.")

        if result.assets or result.identities:
            root = (result.assets or result.identities)[0]
            result.graph = await self.graph(db, root.id, hops=3, limit=100, until=incident.last_seen)
        if result.graph.truncated:
            result.gaps.append("Entity graph was truncated to the query budget.")

        incident_pivots = []
        for column, value in ((Incident.primary_host, incident.primary_host), (Incident.primary_user, incident.primary_user), (Incident.primary_src_ip, incident.primary_src_ip)):
            if value:
                incident_pivots.append(column == value)
        if incident_pivots:
            history = await db.scalars(select(Incident).where(
                Incident.id != incident.id, or_(*incident_pivots), Incident.last_seen < incident.first_seen,
            ).order_by(Incident.last_seen.desc()).limit(5))
            for old in history.all():
                review = await db.scalar(select(Investigation).where(
                    Investigation.incident_id == old.id, Investigation.reviewed_at.is_not(None),
                ).order_by(Investigation.reviewed_at.desc()).limit(1))
                result.historical_incidents.append({
                    "id": str(old.id), "title": old.title, "status": old.status,
                    "last_seen": utc(old.last_seen).isoformat(), "mitre_ids": old.mitre_ids,
                    "analyst_classification": review.final_classification if review else None,
                    "analyst_notes": review.reviewer_notes if review else None,
                    "source_ref": f"investigation:{review.id}" if review else f"incident:{old.id}",
                })
        if not result.historical_incidents:
            result.gaps.append("No earlier incident with a matching entity was found.")
        from app.services.behavior import BehaviorAnalytics
        result.analytics = await BehaviorAnalytics().analyze(db, incident)
        from app.services.attack_paths import access_paths
        result.analytics["attack_paths"] = access_paths(result.graph, result.assets + result.identities, result.analytics.get("predictions", []))
        result.gaps.extend(result.analytics.get("gaps", []))
        return result
