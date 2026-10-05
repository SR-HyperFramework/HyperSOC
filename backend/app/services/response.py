from __future__ import annotations

import ipaddress
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.incident import Incident
from app.models.investigation import Investigation
from app.models.hub import HubEvidence
from app.core.auth import audit
from app.core.config import settings
from app.models.response_action import ResponseAction
from app.schemas.response_action import (
    ResponseActionApprovalRequest,
    ResponseActionCreate,
    ResponseActionOut,
    ResponseActionPolicyResult,
    ResponseActionRejectRequest,
)
from app.services.siem import SIEMProvider, SIEMResponseError, build_siem_provider

_ALLOWED_ACTION_TYPES = {"BLOCK_IP"}
_PROTECTED_IP_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("ff00::/8"),
]
_MANAGEMENT_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ResponseActionNotFound(Exception):
    pass


class ResponseActionConflict(Exception):
    pass


class ResponseActionPolicy:
    """Phase 11 containment policy validator. It validates but never executes."""

    def __init__(
        self,
        *,
        soc_allowlist: set[str] | None = None,
        denylist: set[str] | None = None,
        allow_private_targets: bool = False,
    ) -> None:
        self.soc_allowlist = soc_allowlist or set()
        self.denylist = denylist or set()
        self.allow_private_targets = allow_private_targets

    def validate(self, action: ResponseActionCreate) -> ResponseActionPolicyResult:
        reasons: list[str] = []
        normalized_target: str | None = None
        if action.type not in _ALLOWED_ACTION_TYPES:
            reasons.append(f"Action type {action.type} is not enabled in the Phase 11 MVP allowlist")
            return ResponseActionPolicyResult(allowed=False, reasons=reasons, normalized_target=normalized_target)

        if action.type == "BLOCK_IP":
            normalized_target, ip_reasons = self._validate_block_ip(action.target)
            reasons.extend(ip_reasons)

        return ResponseActionPolicyResult(
            allowed=not reasons,
            reasons=reasons,
            normalized_target=normalized_target,
        )

    def _validate_block_ip(self, target: str) -> tuple[str | None, list[str]]:
        reasons: list[str] = []
        try:
            address = ipaddress.ip_address(target.strip())
        except ValueError:
            return None, ["BLOCK_IP target must be a valid single IP address"]

        normalized = str(address)
        if normalized in self.soc_allowlist:
            reasons.append("Target is protected by the SOC infrastructure allowlist")
        if normalized in self.denylist:
            reasons.append("Target appears in the response denylist")
        if address.is_unspecified or any(address in network for network in _PROTECTED_IP_NETWORKS):
            reasons.append("Target is localhost, unspecified, link-local, or multicast and cannot be blocked")
        if not self.allow_private_targets and any(address in network for network in _MANAGEMENT_PRIVATE_NETWORKS):
            reasons.append("Target is in a private management subnet and requires a later hardening policy exception")
        return normalized, reasons


class ResponseActionService:
    """Human-in-the-loop response action service. Phase 11 stores approvals only."""

    def __init__(
        self,
        *,
        policy: ResponseActionPolicy | None = None,
        siem_provider: SIEMProvider | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self.policy = policy or ResponseActionPolicy()
        self.siem_provider = siem_provider or build_siem_provider()
        self._clock = clock

    async def create_for_incident(
        self,
        db: AsyncSession,
        incident_id: UUID,
        request: ResponseActionCreate,
    ) -> ResponseActionOut | None:
        incident = await db.get(Incident, incident_id)
        if incident is None:
            return None
        policy_result = self.policy.validate(request)
        if not policy_result.allowed:
            raise ResponseActionConflict("; ".join(policy_result.reasons))
        row = ResponseAction(
            id=uuid4(),
            incident_id=incident.id,
            type=request.type,
            target=policy_result.normalized_target or request.target.strip(),
            reason=request.reason,
            risk=request.risk,
            status="PENDING",
            requested_by=request.requested_by,
            duration_minutes=request.duration_minutes,
            policy_result=policy_result.model_dump(mode="json"),
            execution_result=None,
        )
        db.add(row)
        if getattr(db, "info", {}).get("soc_principal"):
            audit(db, "response.request", str(row.id), details={"incident_id": str(row.incident_id), "type": row.type, "target": row.target})
        await self._commit(db)
        await self._refresh(db, row)
        return self._out(row)

    async def list_for_incident(self, db: AsyncSession, incident_id: UUID) -> list[ResponseActionOut] | None:
        incident = await db.get(Incident, incident_id)
        if incident is None:
            return None
        result = await db.scalars(
            select(ResponseAction).where(ResponseAction.incident_id == incident_id).order_by(ResponseAction.created_at.desc())
        )
        return [self._out(row) for row in result.all()]

    async def approve(self, db: AsyncSession, action_id: UUID, request: ResponseActionApprovalRequest) -> ResponseActionOut | None:
        row = await db.get(ResponseAction, action_id, with_for_update=True)
        if row is None:
            return None
        if row.status != "PENDING":
            raise ResponseActionConflict("Only PENDING response actions can be approved")
        if settings.auth_enabled:
            await db.get(Incident, row.incident_id, with_for_update=True)
            latest = await db.scalar(select(Investigation).where(Investigation.incident_id == row.incident_id).order_by(Investigation.created_at.desc(), Investigation.id.desc()).limit(1))
            if latest is None or latest.final_classification != "true_positive" or latest.status == "PENDING_REVIEW":
                raise ResponseActionConflict("The latest investigation must have an analyst-confirmed true-positive conclusion")
        policy_result = self.policy.validate(
            ResponseActionCreate(
                type=row.type,
                target=row.target,
                reason=row.reason,
                risk=row.risk,
                requested_by=row.requested_by,
                duration_minutes=row.duration_minutes,
            )
        )
        if not policy_result.allowed:
            row.policy_result = policy_result.model_dump(mode="json")
            await self._commit(db)
            raise ResponseActionConflict("; ".join(policy_result.reasons))
        row.status = "APPROVED"
        row.approved_by = request.approved_by
        row.approved_at = self._clock()
        row.policy_result = policy_result.model_dump(mode="json")
        if getattr(db, "info", {}).get("soc_principal"):
            audit(db, "response.approve", str(row.id), details={"target": row.target, "incident_id": str(row.incident_id)})
        await self._commit(db)
        await self._refresh(db, row)
        return self._out(row)

    async def reject(self, db: AsyncSession, action_id: UUID, request: ResponseActionRejectRequest) -> ResponseActionOut | None:
        row = await db.get(ResponseAction, action_id, with_for_update=True)
        if row is None:
            return None
        if row.status != "PENDING":
            raise ResponseActionConflict("Only PENDING response actions can be rejected")
        row.status = "REJECTED"
        row.rejected_by = request.rejected_by
        row.rejected_at = self._clock()
        row.rejection_reason = request.reason
        if getattr(db, "info", {}).get("soc_principal"):
            audit(db, "response.reject", str(row.id), details={"reason": request.reason})
        await self._commit(db)
        await self._refresh(db, row)
        return self._out(row)

    async def execute(self, db: AsyncSession, action_id: UUID) -> ResponseActionOut | None:
        row = await db.get(ResponseAction, action_id, with_for_update=True)
        if row is None:
            return None
        if row.status != "APPROVED":
            raise ResponseActionConflict("Only APPROVED response actions can be executed")
        if settings.auth_enabled:
            await db.get(Incident, row.incident_id, with_for_update=True)
            latest = await db.scalar(select(Investigation).where(Investigation.incident_id == row.incident_id).order_by(Investigation.created_at.desc(), Investigation.id.desc()).limit(1))
            if latest is None or latest.final_classification != "true_positive" or latest.status == "PENDING_REVIEW":
                raise ResponseActionConflict("The latest investigation must still have an analyst-confirmed true-positive conclusion")
        validated = self.policy.validate(ResponseActionCreate(type=row.type, target=row.target, reason=row.reason, risk=row.risk, requested_by=row.requested_by, duration_minutes=row.duration_minutes))
        if not validated.allowed:
            raise ResponseActionConflict("; ".join(validated.reasons))
        row.status = "EXECUTING"
        row.execution_result = {"status": "EXECUTING", "metadata": {
            "execution_mode": self.siem_provider.provider_mode,
            "agents_requested": list(getattr(self.siem_provider, "agents", [])),
            "containment_verified": False,
        }}
        if getattr(db, "info", {}).get("soc_principal"):
            audit(db, "response.execute", str(row.id), details={"target": row.target, "provider": self.siem_provider.provider_mode})
        await self._commit(db)
        await self._refresh(db, row)
        try:
            result = await self.siem_provider.execute_response(row)
        except SIEMResponseError as exc:
            row.status = "FAILED"
            row.execution_result = {**row.execution_result, "status": "FAILED", "error": str(exc), "provider": getattr(self.siem_provider, "provider_mode", "unknown")}
            if getattr(db, "info", {}).get("soc_principal"):
                audit(db, "response.result", str(row.id), details={"status": "FAILED", "error_type": type(exc).__name__})
            await self._commit(db)
            await self._refresh(db, row)
            raise ResponseActionConflict(str(exc)) from exc
        row.status = result.status
        row.execution_result = result.as_dict()
        # Manager delivery and offline simulation do not establish endpoint containment.
        if getattr(db, "info", {}).get("soc_principal"):
            audit(db, "response.result", str(row.id), details={"status": result.status, "execution_mode": result.metadata.get("execution_mode")})
        await self._commit(db)
        await self._refresh(db, row)
        return self._out(row)

    async def verify(self, db: AsyncSession, action_id: UUID, evidence_id: UUID | list[UUID], notes: str) -> ResponseActionOut | None:
        row = await db.get(ResponseAction, action_id, with_for_update=True)
        if row is None:
            return None
        result = row.execution_result or {}
        mode = result.get("metadata", {}).get("execution_mode", self.siem_provider.provider_mode)
        if mode != "wazuh" or row.status not in {"SUCCESS", "EXECUTING", "FAILED"}:
            raise ResponseActionConflict("Only a dispatched real Wazuh action can be verified")
        identifiers = list(dict.fromkeys(evidence_id if isinstance(evidence_id, list) else [evidence_id]))
        if not identifiers or len(identifiers) > 50:
            raise ResponseActionConflict("Provide one or more response evidence IDs")
        requested_agents = set(result.get("metadata", {}).get("agents_requested", []))
        if not requested_agents:
            raise ResponseActionConflict("The stored execution must identify its requested agent scope")
        confirmed_agents = set()
        trusted_sources = {value.strip() for value in settings.response_evidence_sources.split(",") if value.strip()}
        approved = row.approved_at.replace(tzinfo=timezone.utc) if row.approved_at and row.approved_at.tzinfo is None else row.approved_at
        for identifier in identifiers:
            evidence = await db.get(HubEvidence, identifier)
            attributes = evidence.attributes if evidence else {}
            if evidence is None or evidence.source not in trusted_sources:
                raise ResponseActionConflict("Verification needs evidence from a trusted response telemetry source")
            if attributes.get("response_action_id") != str(row.id) or attributes.get("response_effect") != "blocked" or attributes.get("target") != row.target:
                raise ResponseActionConflict("Response evidence must identify this action, blocked effect, and target")
            observed = evidence.timestamp.replace(tzinfo=timezone.utc) if evidence.timestamp.tzinfo is None else evidence.timestamp
            if approved is None or observed < approved or observed > self._clock():
                raise ResponseActionConflict("Response evidence must be observed after approval and no later than now")
            agent = evidence.normalized.get("host", {}).get("id")
            if agent:
                confirmed_agents.add(str(agent))
        if not requested_agents <= confirmed_agents:
            raise ResponseActionConflict("Endpoint block evidence is required for every requested agent")
        incident = await db.get(Incident, row.incident_id, with_for_update=True)
        if incident.status == "FALSE_POSITIVE":
            raise ResponseActionConflict("False-positive incidents cannot be marked contained")
        principal = getattr(db, "info", {}).get("soc_principal")
        metadata = {**result.get("metadata", {}), "execution_mode": "wazuh", "containment_verified": True,
            "verification": {"evidence_id": str(identifiers[0]), "evidence_ids": [str(value) for value in identifiers], "agents_verified": sorted(confirmed_agents), "verified_by": principal.username if principal else "lab-analyst", "verified_at": self._clock().isoformat(), "notes": notes}}
        row.execution_result = {**result, "status": "SUCCESS", "metadata": metadata}
        row.status = "SUCCESS"
        incident.status = "CONTAINED"
        audit(db, "response.verify", str(row.id), details={"evidence_ids": [str(value) for value in identifiers], "target": row.target})
        await self._commit(db)
        await self._refresh(db, row)
        return self._out(row)

    async def _commit(self, db: AsyncSession) -> None:
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()
            raise

    async def _refresh(self, db: AsyncSession, row: Any) -> None:
        try:
            await db.refresh(row)
        except AttributeError:
            return

    def _out(self, row: ResponseAction) -> ResponseActionOut:
        return ResponseActionOut.model_validate(row)
