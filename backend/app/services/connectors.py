"""Pure native adapters. Source payloads are evidence, never executable instructions."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas.hub import EvidenceCategory, HubEventIn
from app.schemas.normalized_alert import NormalizedAlert
from app.services.normalization import normalize_wazuh_alert


class NativeEventRequest(BaseModel):
    model_config = {"extra": "forbid"}
    format: Literal["ecs", "osquery", "wazuh"]
    source: str = Field(min_length=1, max_length=128)
    category: EvidenceCategory | None = None
    event: dict[str, Any]


def digest(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def scalar(value) -> str | None:
    if value is None or isinstance(value, (dict, list, bool)):
        return None
    return str(value).strip() or None


def number(value, maximum=2**31 - 1) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        parsed = float(value)
        return int(parsed) if math.isfinite(parsed) and 0 <= parsed <= maximum and parsed.is_integer() else None
    except (TypeError, ValueError, OverflowError):
        return None


def timestamp(value) -> datetime:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return datetime.fromtimestamp(value, timezone.utc)
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Native event timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def ip(value) -> str | None:
    try:
        return str(ipaddress.ip_address(value))
    except (TypeError, ValueError):
        return None


def field(payload: dict, path: str):
    if path in payload:
        return payload[path]
    current = payload
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def strings(value) -> list[str]:
    values = value if isinstance(value, list) else [value]
    return list(dict.fromkeys(text for value in values[:100] if (text := scalar(value))))


def response_attributes(payload: dict) -> dict:
    """Explicit endpoint response telemetry contract; do not infer from alert wording."""
    if not isinstance(payload, dict) or payload.get("effect") != "blocked":
        return {}
    action_id = str(UUID(str(payload.get("action_id"))))
    target = ip(payload.get("target"))
    if target is None:
        raise ValueError("Response telemetry needs a valid target IP")
    return {"response_action_id": action_id, "response_effect": "blocked", "target": target}


def ecs(request: NativeEventRequest) -> list[HubEventIn]:
    native = request.event
    payload = native.get("_source", native)
    if not isinstance(payload, dict):
        raise ValueError("ECS _source must be an object")
    get = lambda path: field(payload, path)
    kind = scalar(get("event.kind"))
    categories = strings(get("event.category"))
    category = request.category or ("detection" if kind in {"alert", "signal"} else "posture" if "vulnerability" in categories else "behavior")
    event_id = scalar(get("event.id")) or scalar(native.get("_id")) or digest(payload)
    if native.get("_index"):
        event_id = str(native["_index"]) + ":" + event_id
    alert = NormalizedAlert(timestamp=timestamp(payload.get("@timestamp")), raw_ref=event_id)
    alert.host.id, alert.host.name = scalar(get("host.id")), scalar(get("host.name"))
    addresses = strings(get("host.ip"))
    alert.host.ip = next((address for value in addresses if (address := ip(value))), None)
    alert.identity.username, alert.identity.domain = scalar(get("user.name")), scalar(get("user.domain"))
    alert.identity.target = scalar(get("user.target.name"))
    alert.identity.auth_outcome = scalar(get("event.outcome")) if "authentication" in categories else None
    for canonical, native_name in (("src_ip", "source.ip"), ("dst_ip", "destination.ip")):
        setattr(alert.network, canonical, ip(get(native_name)))
    alert.network.src_port, alert.network.dst_port = number(get("source.port"), 65535), number(get("destination.port"), 65535)
    alert.network.protocol = scalar(get("network.transport"))
    alert.network.domain = scalar(get("destination.domain")) or scalar(get("dns.question.name"))
    alert.network.dns_query, alert.network.url = scalar(get("dns.question.name")), scalar(get("url.full"))
    for canonical, native_name in (("name", "name"), ("image", "executable"), ("command_line", "command_line"), ("guid", "entity_id"),
                                   ("parent_name", "parent.name"), ("parent_image", "parent.executable"), ("parent_command_line", "parent.command_line")):
        setattr(alert.process, canonical, scalar(get("process." + native_name)))
    alert.process.pid, alert.process.parent_pid = number(get("process.pid")), number(get("process.parent.pid"))
    alert.file.path, alert.file.name = scalar(get("file.path")), scalar(get("file.name"))
    for scope in ("process", "file"):
        target = getattr(alert, scope)
        for algorithm in ("sha256", "sha1", "md5"):
            value = scalar(get(f"{scope}.hash.{algorithm}"))
            if value:
                target.hash, target.hash_algorithm = value, algorithm.upper()
                break
    alert.detection.source, alert.detection.event_family = request.source, categories[0] if categories else "ecs"
    alert.detection.event_kind, alert.detection.event_id = kind, scalar(get("event.code"))
    alert.detection.rule_id = scalar(get("rule.id")) or scalar(get("kibana.alert.rule.uuid"))
    alert.detection.description = scalar(get("rule.name")) or scalar(get("message")) or scalar(get("event.action"))
    alert.detection.groups = categories
    techniques = strings(get("threat.technique.id")) + strings(get("threat.technique.subtechnique.id"))
    for threat in (get("kibana.alert.rule.threat") or [])[:30]:
        if isinstance(threat, dict):
            for technique in threat.get("technique", [])[:30]:
                if isinstance(technique, dict):
                    techniques += strings(technique.get("id"))
                    for sub in technique.get("subtechnique", [])[:30]:
                        if isinstance(sub, dict):
                            techniques += strings(sub.get("id"))
    alert.detection.mitre_ids = list(dict.fromkeys(t.upper() for t in techniques if re.fullmatch(r"T\d{4}(?:\.\d{3})?", t.upper())))[:30]
    severity = scalar(get("kibana.alert.severity"))
    if severity in {"low", "medium", "high", "critical"}:
        alert.detection.severity = severity
        alert.detection.level = {"low": 3, "medium": 7, "high": 12, "critical": 15}[severity]
    # ECS event.severity has source-specific units; preserve rather than mis-scale.
    attributes = {"adapter": "ecs-v1", "native_digest": digest(payload), "native_severity": get("event.severity"),
        "dataset": get("event.dataset"), "event_action": get("event.action"), "vulnerability": get("vulnerability")}
    return [HubEventIn(source=request.source, external_id=event_id, category=category, alert=alert, attributes=attributes)]


def osquery(request: NativeEventRequest) -> list[HubEventIn]:
    payload = request.event
    host = scalar(payload.get("hostIdentifier")) or scalar(payload.get("hostname"))
    query = scalar(payload.get("name"))
    if not host or not query:
        raise ValueError("osquery needs a host identifier and query name")
    raw_time = float(payload["unixTime"])
    observed = timestamp(raw_time)
    if isinstance(payload.get("columns"), dict):
        records = [(payload.get("action", "added"), payload["columns"])]
    elif isinstance(payload.get("snapshot"), list):
        records = [("snapshot", value) for value in payload["snapshot"]]
    elif isinstance(payload.get("diffResults"), dict):
        records = [(action, value) for action in ("added", "removed") for value in payload["diffResults"].get(action, [])]
    else:
        raise ValueError("Unsupported osquery result shape")
    if len(records) > 200 or any(not isinstance(row, dict) for _, row in records):
        raise ValueError("osquery event must contain at most 200 object rows")
    events = []
    for action, row in records:
        alert = NormalizedAlert(timestamp=observed)
        alert.host.name = host
        alert.identity.username = scalar(row.get("username")) or scalar(row.get("user"))
        alert.network.dst_ip, alert.network.dst_port = ip(row.get("remote_address")), number(row.get("remote_port"), 65535)
        alert.network.src_ip, alert.network.src_port = ip(row.get("local_address")), number(row.get("local_port"), 65535)
        alert.network.protocol = scalar(row.get("protocol"))
        alert.process.pid, alert.process.parent_pid = number(row.get("pid")), number(row.get("parent"))
        if alert.process.pid is not None:
            alert.process.name, alert.process.image = scalar(row.get("name")), scalar(row.get("path"))
            alert.process.command_line = scalar(row.get("cmdline"))
            if row.get("start_time"):
                alert.process.guid = f"{host}:{alert.process.pid}:{row['start_time']}"
        elif row.get("path"):
            alert.file.path = scalar(row.get("path"))
        if row.get("sha256"):
            alert.file.hash, alert.file.hash_algorithm = scalar(row["sha256"]), "SHA256"
        alert.detection.source, alert.detection.event_family = request.source, query
        alert.detection.event_kind, alert.detection.description = "event", f"{query}: {action}"
        native_ref = {"host": host, "query": query, "timestamp": observed.isoformat(), "epoch": payload.get("epoch"),
            "counter": payload.get("counter"), "action": action, "columns": row}
        external_id = digest(native_ref)
        alert.raw_ref = external_id
        events.append(HubEventIn(source=request.source, external_id=external_id, category=request.category or "behavior", alert=alert,
            attributes={"adapter": "osquery-v1", "query": query, "action": action, "columns": row,
                "epoch": payload.get("epoch"), "counter": payload.get("counter")}))
    return events


def adapt(request: NativeEventRequest) -> list[HubEventIn]:
    if request.format == "ecs":
        return ecs(request)
    if request.format == "osquery":
        return osquery(request)
    payload = request.event
    normalized = normalize_wazuh_alert(payload)
    data = payload.get("data") or {}
    category = request.category or ("posture" if data.get("sca") or data.get("vulnerability") else "detection" if payload.get("rule") else "behavior")
    return [HubEventIn(source=request.source, external_id=str(payload.get("id") or digest(payload)), category=category, alert=normalized,
        attributes={"adapter": "wazuh-v1", "posture": data.get("sca") or data.get("vulnerability"),
            **response_attributes(data.get("hypersoc_response") or {})})]
