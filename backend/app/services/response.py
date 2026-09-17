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
        if any(address in network for network in _PROTECTED_IP_NETWORKS):
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
        row = await db.get(ResponseAction, action_id)
        if row is None:
            return None
        if row.status != "PENDING":
            raise ResponseActionConflict("Only PENDING response actions can be approved")
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
        await self._commit(db)
        await self._refresh(db, row)
        return self._out(row)

    async def reject(self, db: AsyncSession, action_id: UUID, request: ResponseActionRejectRequest) -> ResponseActionOut | None:
        row = await db.get(ResponseAction, action_id)
        if row is None:
            return None
        if row.status != "PENDING":
            raise ResponseActionConflict("Only PENDING response actions can be rejected")
        row.status = "REJECTED"
        row.rejected_by = request.rejected_by
        row.rejected_at = self._clock()
        row.rejection_reason = request.reason
        await self._commit(db)
        await self._refresh(db, row)
        return self._out(row)

    async def execute(self, db: AsyncSession, action_id: UUID) -> ResponseActionOut | None:
        row = await db.get(ResponseAction, action_id)
        if row is None:
            return None
        if row.status != "APPROVED":
            raise ResponseActionConflict("Only APPROVED response actions can be executed")
        row.status = "EXECUTING"
        await self._commit(db)
        await self._refresh(db, row)
        try:
            result = await self.siem_provider.execute_response(row)
        except SIEMResponseError as exc:
            row.status = "FAILED"
            row.execution_result = {"status": "FAILED", "error": str(exc), "provider": getattr(self.siem_provider, "provider_mode", "unknown")}
            await self._commit(db)
            await self._refresh(db, row)
            raise ResponseActionConflict(str(exc)) from exc
        row.status = result.status
        row.execution_result = result.as_dict()
        if result.status == "SUCCESS":
            incident = await db.get(Incident, row.incident_id)
            if incident is not None:
                incident.status = "CONTAINED"
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
