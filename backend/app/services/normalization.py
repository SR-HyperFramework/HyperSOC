"""Pure Wazuh-to-domain normalization for downstream SOC services.

This module deliberately has no FastAPI, database, or manager-integration
imports. The manager adapter retains its Phase 3 wire envelope; this service
converts native Wazuh evidence (or that envelope's ``raw`` event) to the
provider-neutral Phase 4 contract.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from pathlib import PurePath
from typing import Any
from uuid import UUID, uuid4

from app.schemas.normalized_alert import (
    NormalizedAlert,
    NormalizedDetection,
    NormalizedFile,
    NormalizedHost,
    NormalizedIdentity,
    NormalizedNetwork,
    NormalizedProcess,
)

_HASH_LENGTHS = {32: "MD5", 40: "SHA1", 64: "SHA256"}
_MITRE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_HTTP_METHODS = {"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"}
_SUCCESS_VALUES = {"0", "0x0", "success", "successful", "succeeded", "true", "yes"}
_FAILURE_VALUES = {"denied", "fail", "failed", "failure", "false", "invalid", "no"}


def _as_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _text(value: Any) -> str | None:
    if value is None or isinstance(value, (Mapping, list, tuple, set, bool)):
        return None
    text = str(value).strip()
    return text or None


def _pick(*values: Any) -> str | None:
    for value in values:
        text = _text(value)
        if text is not None and text != "-":
            return text
    return None


def _first_present(*values: Any) -> Any:
    for value in values:
        if value is not None:
            return value
    return None


def _scalar_items(value: Any) -> Iterable[Any]:
    if isinstance(value, set):
        return sorted(value, key=str)
    if isinstance(value, (list, tuple)):
        return value
    return (value,)


def _strings(value: Any, *, uppercase: bool = False, split_commas: bool = True) -> list[str]:
    """Return trimmed unique scalar strings while preserving source order."""
    normalized: list[str] = []
    for item in _scalar_items(value):
        text = _text(item)
        if text is None:
            continue
        candidates = text.split(",") if split_commas else [text]
        for candidate in candidates:
            candidate = candidate.strip()
            if not candidate or candidate == "-":
                continue
            if uppercase:
                candidate = candidate.upper()
            if candidate not in normalized:
                normalized.append(candidate)
    return normalized


def _safe_int(value: Any, *, minimum: int, maximum: int) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    text = _text(value)
    if text is None or not text.isdecimal():
        return None
    number = int(text)
    return number if minimum <= number <= maximum else None


def _pick_int(*values: Any, minimum: int, maximum: int) -> int | None:
    for value in values:
        number = _safe_int(value, minimum=minimum, maximum=maximum)
        if number is not None:
            return number
    return None


def _timestamp(value: Any) -> datetime:
    if isinstance(value, bool) or value is None:
        raise ValueError("Wazuh alert has no valid timestamp")

    if isinstance(value, (int, float)):
        if not math.isfinite(value):
            raise ValueError("Wazuh alert has no valid timestamp")
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OverflowError, OSError, ValueError) as exc:
            raise ValueError("Wazuh alert has no valid timestamp") from exc

    text = _text(value)
    if text is None:
        raise ValueError("Wazuh alert has no valid timestamp")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Wazuh alert has no valid timestamp") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _ip(value: Any) -> str | None:
    text = _text(value)
    if text is None:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _pick_ip(*values: Any) -> str | None:
    for value in values:
        parsed = _ip(value)
        if parsed is not None:
            return parsed
    return None


def _path_name(path: str | None) -> str | None:
    if not path:
        return None
    # PurePath on POSIX does not split Windows separators, so handle both.
    candidate = path.replace("\\", "/").rstrip("/")
    return PurePath(candidate).name or None


def _hash_text(value: Any) -> str | None:
    text = _text(value)
    if text is None:
        return None
    candidate = text.upper()
    if len(candidate) not in _HASH_LENGTHS or not all(char in "0123456789ABCDEF" for char in candidate):
        return None
    return candidate


def _hash_algorithm(value: str | None) -> str | None:
    return _HASH_LENGTHS.get(len(value or ""))


def _hash_result_from_value(value: Any) -> tuple[str, str] | None:
    text = _text(value)
    if text is None:
        return None

    if "=" not in text:
        parsed = _hash_text(text)
        algorithm = _hash_algorithm(parsed)
        return (parsed, algorithm) if parsed and algorithm else None

    parsed_values: dict[str, str] = {}
    for item in re.split(r"[,;]", text):
        name, separator, hash_value = item.partition("=")
        if not separator:
            continue
        parsed = _hash_text(hash_value)
        if parsed:
            parsed_values[name.strip().upper()] = parsed
    for algorithm in ("SHA256", "SHA1", "MD5"):
        if algorithm in parsed_values:
            return parsed_values[algorithm], algorithm
    return None


def _hash_result_from(*containers: Mapping[str, Any]) -> tuple[str, str] | None:
    """Choose the strongest usable hash, then the first container carrying it."""
    for algorithm, keys in (
        ("SHA256", ("sha256_after", "sha256", "SHA256")),
        ("SHA1", ("sha1_after", "sha1", "SHA1")),
        ("MD5", ("md5_after", "md5", "MD5")),
    ):
        for container in containers:
            for key in keys:
                parsed = _hash_text(container.get(key))
                if parsed:
                    return parsed, algorithm

    generic: dict[str, str] = {}
    for container in containers:
        for key in ("hash", "Hash", "hashes", "Hashes"):
            parsed = _hash_result_from_value(container.get(key))
            if parsed:
                value, algorithm = parsed
                generic.setdefault(algorithm, value)
    for algorithm in ("SHA256", "SHA1", "MD5"):
        if algorithm in generic:
            return generic[algorithm], algorithm
    return None


def _hash_from(*containers: Mapping[str, Any]) -> str | None:
    result = _hash_result_from(*containers)
    return result[0] if result else None


def _event_parts(alert: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    data = _as_dict(alert.get("data"))
    win = _as_dict(data.get("win"))
    return {
        "data": data,
        "win": win,
        "eventdata": _as_dict(win.get("eventdata")),
        "system": _as_dict(win.get("system")),
        "audit": _as_dict(data.get("audit")),
        "network": _as_dict(data.get("network")),
        "process": _as_dict(data.get("process")),
        "file": _as_dict(data.get("file")),
        "syscheck": _as_dict(alert.get("syscheck")) or _as_dict(data.get("syscheck")),
        "nginx": _as_dict(data.get("nginx")),
        "ssh": _as_dict(data.get("ssh")),
        "decoder": _as_dict(alert.get("decoder")),
    }


def _http_request_parts(request: Any) -> tuple[str | None, str | None, str | None]:
    text = _text(request)
    if text is None:
        return None, None, None
    parts = text.split()
    if len(parts) >= 2 and parts[0].upper() in _HTTP_METHODS:
        return parts[0].upper(), parts[1], parts[2] if len(parts) >= 3 else None
    return None, text, None


def extract_network_fields(alert: Mapping[str, Any]) -> NormalizedNetwork:
    """Extract network evidence from common Wazuh decoder layouts."""
    parts = _event_parts(alert)
    data = parts["data"]
    event = parts["eventdata"]
    network = parts["network"]
    nginx = parts["nginx"]
    request_method, request_url, request_protocol = _http_request_parts(
        _first_present(nginx.get("request"), data.get("request"))
    )
    dns_query = _pick(
        event.get("queryName"),
        event.get("query"),
        data.get("dns_query"),
        data.get("query"),
        network.get("dns_query"),
    )

    return NormalizedNetwork(
        src_ip=_pick_ip(
            data.get("srcip"),
            data.get("src_ip"),
            data.get("clientip"),
            data.get("client_ip"),
            data.get("remote_addr"),
            network.get("srcip"),
            network.get("src_ip"),
            nginx.get("srcip"),
            nginx.get("remote_addr"),
            nginx.get("client_ip"),
            event.get("sourceIp"),
            event.get("sourceIP"),
            event.get("sourceIPAddress"),
            event.get("ipAddress"),
        ),
        dst_ip=_pick_ip(
            data.get("dstip"),
            data.get("dst_ip"),
            network.get("dstip"),
            network.get("dst_ip"),
            nginx.get("dstip"),
            event.get("destinationIp"),
            event.get("destinationIP"),
            event.get("destinationIPAddress"),
        ),
        src_port=_pick_int(
            data.get("srcport"),
            data.get("src_port"),
            network.get("srcport"),
            network.get("src_port"),
            event.get("sourcePort"),
            event.get("sourcePortName"),
            minimum=1,
            maximum=65535,
        ),
        dst_port=_pick_int(
            data.get("dstport"),
            data.get("dst_port"),
            network.get("dstport"),
            network.get("dst_port"),
            event.get("destinationPort"),
            event.get("destinationPortName"),
            minimum=1,
            maximum=65535,
        ),
        protocol=_pick(data.get("protocol"), network.get("protocol"), event.get("protocol"), request_protocol),
        domain=_pick(
            data.get("domain"),
            data.get("hostname"),
            network.get("domain"),
            event.get("destinationHostname"),
            nginx.get("host"),
            dns_query,
        ),
        url=_pick(data.get("url"), data.get("full_url"), nginx.get("url"), nginx.get("request_uri"), request_url),
        dns_query=dns_query,
        http_method=_pick(data.get("method"), data.get("http_method"), nginx.get("method"), request_method),
        http_status=_pick_int(
            nginx.get("status"),
            data.get("status"),
            data.get("http_status"),
            minimum=100,
            maximum=599,
        ),
        user_agent=_pick(data.get("user_agent"), data.get("useragent"), nginx.get("user_agent"), nginx.get("agent")),
        referrer=_pick(data.get("referrer"), data.get("referer"), nginx.get("referrer"), nginx.get("referer")),
    )


def extract_process_fields(alert: Mapping[str, Any]) -> NormalizedProcess:
    """Extract Windows, Sysmon, PowerShell, and auditd process evidence."""
    parts = _event_parts(alert)
    data = parts["data"]
    event = parts["eventdata"]
    process = parts["process"]
    audit = parts["audit"]
    image = _pick(
        event.get("newProcessName"),
        event.get("image"),
        event.get("Image"),
        data.get("process_name"),
        data.get("process"),
        process.get("image"),
        process.get("name"),
        audit.get("exe"),
    )
    command_line = _pick(
        event.get("commandLine"),
        event.get("commandline"),
        event.get("CommandLine"),
        data.get("command"),
        data.get("command_line"),
        process.get("command_line"),
        process.get("commandLine"),
        audit.get("command"),
        audit.get("proctitle"),
    )
    parent_image = _pick(
        event.get("parentImage"),
        event.get("ParentImage"),
        event.get("parentProcessName"),
        event.get("parentProcess"),
        process.get("parent_image"),
        process.get("parent_name"),
    )
    hash_result = _hash_result_from(event, process, audit)
    return NormalizedProcess(
        name=_path_name(image),
        image=image,
        command_line=command_line,
        parent_name=_path_name(parent_image),
        parent_image=parent_image,
        parent_command_line=_pick(event.get("parentCommandLine"), event.get("ParentCommandLine"), process.get("parent_command_line")),
        current_directory=_pick(event.get("currentDirectory"), event.get("CurrentDirectory"), process.get("current_directory")),
        pid=_pick_int(
            event.get("processId"),
            event.get("processID"),
            event.get("ProcessId"),
            process.get("pid"),
            audit.get("pid"),
            minimum=1,
            maximum=2**31 - 1,
        ),
        parent_pid=_pick_int(
            event.get("parentProcessId"),
            event.get("parentProcessID"),
            event.get("ParentProcessId"),
            process.get("parent_pid"),
            minimum=1,
            maximum=2**31 - 1,
        ),
        guid=_pick(event.get("processGuid"), event.get("ProcessGuid"), process.get("guid")),
        hash=hash_result[0] if hash_result else None,
        hash_algorithm=hash_result[1] if hash_result else None,
        script_block=_pick(
            event.get("scriptBlockText"),
            event.get("ScriptBlockText"),
            data.get("script_block_text"),
            data.get("powershell_script"),
        ),
    )


def extract_file_fields(alert: Mapping[str, Any]) -> NormalizedFile:
    """Extract FIM, Sysmon, and auditd file evidence."""
    parts = _event_parts(alert)
    data = parts["data"]
    event = parts["eventdata"]
    file_data = parts["file"]
    syscheck = parts["syscheck"]
    audit = parts["audit"]
    path = _pick(
        syscheck.get("path"),
        syscheck.get("name"),
        data.get("path"),
        file_data.get("path"),
        file_data.get("name"),
        event.get("targetFilename"),
        event.get("TargetFilename"),
        audit.get("path"),
        audit.get("name"),
    )
    hash_result = _hash_result_from(syscheck, data, file_data, event, audit)
    return NormalizedFile(
        path=path,
        name=_path_name(path),
        hash=hash_result[0] if hash_result else None,
        hash_algorithm=hash_result[1] if hash_result else None,
        action=_pick(syscheck.get("event"), syscheck.get("action"), data.get("action"), event.get("eventType")),
    )


def _event_id(parts: Mapping[str, Mapping[str, Any]]) -> str | None:
    data = parts["data"]
    system = parts["system"]
    event = parts["eventdata"]
    return _pick(
        system.get("eventID"),
        system.get("eventId"),
        system.get("EventID"),
        event.get("eventID"),
        event.get("eventId"),
        event.get("EventID"),
        data.get("event_id"),
        data.get("eventID"),
    )


def _auth_outcome(*values: Any, event_id: str | None = None, description: str | None = None) -> str | None:
    if event_id == "4624":
        return "success"
    if event_id in {"4625", "4771"}:
        return "failure"

    for value in values:
        text = _text(value)
        if text is None:
            continue
        normalized = text.casefold()
        if normalized in _SUCCESS_VALUES:
            return "success"
        if normalized in _FAILURE_VALUES or "fail" in normalized:
            return "failure"
        if normalized.startswith("0x") and normalized != "0x0":
            return "failure"
    if description and "fail" in description.casefold():
        return "failure"
    return None


def extract_identity_fields(alert: Mapping[str, Any]) -> NormalizedIdentity:
    """Extract actor/target identities and authentication context."""
    parts = _event_parts(alert)
    data = parts["data"]
    event = parts["eventdata"]
    audit = parts["audit"]
    ssh = parts["ssh"]
    rule = _as_dict(alert.get("rule"))
    event_id = _event_id(parts)
    description = _text(rule.get("description"))
    actor = _pick(data.get("srcuser"), event.get("subjectUserName"), audit.get("auid"), ssh.get("user"))
    target = _pick(data.get("dstuser"), event.get("targetUserName"), ssh.get("target_user"))
    username = _pick(
        data.get("srcuser"),
        data.get("dstuser"),
        event.get("targetUserName"),
        data.get("user"),
        data.get("username"),
        audit.get("auid"),
        audit.get("uid"),
        event.get("subjectUserName"),
        event.get("user"),
        ssh.get("user"),
    )
    auth_status = _pick(
        data.get("status"),
        data.get("result"),
        event.get("status"),
        event.get("subStatus"),
        audit.get("success"),
        audit.get("result"),
        ssh.get("status"),
    )
    return NormalizedIdentity(
        username=username,
        actor=actor,
        target=target,
        domain=_pick(event.get("subjectDomainName"), event.get("targetDomainName"), data.get("domain")),
        auth_outcome=_auth_outcome(
            data.get("success"),
            data.get("status"),
            data.get("result"),
            event.get("status"),
            event.get("subStatus"),
            event.get("failureReason"),
            audit.get("success"),
            audit.get("result"),
            ssh.get("success"),
            ssh.get("status"),
            event_id=event_id,
            description=description,
        ),
        auth_status=auth_status,
        auth_method=_pick(data.get("method"), ssh.get("method"), event.get("authenticationPackageName")),
        logon_type=_pick(event.get("logonType"), data.get("logon_type")),
        failure_reason=_pick(data.get("failure_reason"), ssh.get("failure_reason"), event.get("failureReason")),
        attempt_count=_pick_int(
            data.get("failed_attempt_count"),
            data.get("attempt_count"),
            data.get("attempts"),
            minimum=0,
            maximum=1_000_000,
        ),
    )


def extract_mitre(alert: Mapping[str, Any]) -> list[str]:
    """Extract valid ATT&CK IDs from common Wazuh rule representations."""
    rule = _as_dict(alert.get("rule"))
    mitre = rule.get("mitre")
    candidates: Any
    if isinstance(mitre, Mapping):
        candidates = _first_present(mitre.get("id"), mitre.get("technique"), mitre.get("techniques"))
    else:
        candidates = mitre
    return [item for item in _strings(candidates, uppercase=True) if _MITRE_ID.fullmatch(item)]


def _provider(parts: Mapping[str, Mapping[str, Any]]) -> str | None:
    return _pick(parts["system"].get("providerName"), parts["system"].get("provider"), parts["system"].get("ProviderName"))


def _decoder(alert: Mapping[str, Any]) -> str | None:
    decoder = alert.get("decoder")
    if isinstance(decoder, Mapping):
        return _pick(decoder.get("name"), decoder.get("decoder"))
    return _pick(decoder)


def _classify_event(alert: Mapping[str, Any], process: NormalizedProcess) -> str:
    parts = _event_parts(alert)
    rule = _as_dict(alert.get("rule"))
    groups = " ".join(_strings(rule.get("groups"))).casefold()
    description = (_text(rule.get("description")) or "").casefold()
    provider = (_provider(parts) or "").casefold()
    event_id = _event_id(parts)

    if parts["syscheck"] or "syscheck" in groups or "file_integrity" in groups:
        return "fim"
    if parts["nginx"] or "nginx" in groups:
        return "nginx"
    if parts["audit"] or "audit" in groups:
        return "auditd"
    if "ssh" in groups or "sshd" in description or parts["ssh"]:
        return "linux_ssh"
    if "sysmon" in groups or "sysmon" in provider:
        return "sysmon"
    if "powershell" in groups or "powershell" in description or "powershell" in (process.image or "").casefold():
        return "powershell"
    if (
        event_id in {"4624", "4625", "4771", "4776"}
        or "windows" in groups
        or "authentication" in groups
        or any(key in parts["eventdata"] for key in ("subjectUserName", "targetUserName", "logonType"))
    ):
        return "windows_authentication"
    return "wazuh"


def _event_kind(event_family: str, event_id: str | None, process: NormalizedProcess, file_data: NormalizedFile) -> str | None:
    if event_family in {"windows_authentication", "linux_ssh"}:
        return "authentication"
    if event_family == "fim":
        return "file"
    if event_family == "nginx":
        return "web"
    if event_family == "auditd":
        return "audit"
    if event_family == "powershell":
        return "script" if process.script_block else "process"
    if event_family == "sysmon":
        return {
            "1": "process",
            "3": "network",
            "7": "image_load",
            "10": "process_access",
            "11": "file",
            "12": "registry",
            "13": "registry",
            "22": "dns",
        }.get(event_id) or ("file" if file_data.path else "process" if process.image else None)
    return None


def _detection(
    alert: Mapping[str, Any],
    event_family: str,
    *,
    identity: NormalizedIdentity,
    process: NormalizedProcess,
    file_data: NormalizedFile,
) -> NormalizedDetection:
    rule = _as_dict(alert.get("rule"))
    parts = _event_parts(alert)
    groups = _strings(rule.get("groups"))
    level = _safe_int(rule.get("level"), minimum=0, maximum=100)
    event_id = _event_id(parts)
    return NormalizedDetection(
        event_family=event_family,
        event_kind=_event_kind(event_family, event_id, process, file_data),
        event_id=event_id,
        rule_id=_pick(rule.get("id")),
        level=level,
        severity=_pick(rule.get("severity")),
        description=_pick(rule.get("description")),
        groups=groups,
        mitre_ids=extract_mitre(alert),
        status=identity.auth_status,
        outcome=identity.auth_outcome,
        provider=_provider(parts),
        decoder=_decoder(alert),
    )


def _is_transport_envelope(alert: Mapping[str, Any]) -> bool:
    return alert.get("source") == "wazuh" and any(key in alert for key in ("event", "raw"))


def _normalize_transport_envelope(alert: Mapping[str, Any], *, alert_id: UUID | None) -> NormalizedAlert:
    raw = _as_dict(alert.get("raw"))
    if raw:
        return normalize_wazuh_alert(raw, alert_id=alert_id)

    agent = _as_dict(alert.get("agent"))
    event = _as_dict(alert.get("event"))
    rule = _as_dict(alert.get("rule"))
    timestamp = _timestamp(alert.get("timestamp"))
    normalized_id = alert_id or uuid4()
    groups = _strings(rule.get("groups"))
    mitre_ids = [item for item in _strings(rule.get("mitre_ids"), uppercase=True) if _MITRE_ID.fullmatch(item)]
    file_hash = _hash_result_from_value(event.get("file_hash"))
    process_hash = _hash_result_from_value(event.get("process_hash"))
    identity = NormalizedIdentity(username=_pick(event.get("username")))
    process = NormalizedProcess(
        name=_path_name(_pick(event.get("process_name"))),
        image=_pick(event.get("process_name")),
        command_line=_pick(event.get("process_command_line")),
        hash=process_hash[0] if process_hash else None,
        hash_algorithm=process_hash[1] if process_hash else None,
    )
    file_data = NormalizedFile(
        path=_pick(event.get("file_path")),
        name=_path_name(_pick(event.get("file_path"))),
        hash=file_hash[0] if file_hash else None,
        hash_algorithm=file_hash[1] if file_hash else None,
    )
    return NormalizedAlert(
        id=normalized_id,
        timestamp=timestamp,
        host=NormalizedHost(id=_pick(agent.get("id")), name=_pick(agent.get("name")), ip=_pick_ip(agent.get("ip"))),
        identity=identity,
        network=NormalizedNetwork(
            src_ip=_pick_ip(event.get("src_ip")),
            dst_ip=_pick_ip(event.get("dst_ip")),
            src_port=_safe_int(event.get("src_port"), minimum=1, maximum=65535),
            dst_port=_safe_int(event.get("dst_port"), minimum=1, maximum=65535),
        ),
        process=process,
        file=file_data,
        detection=NormalizedDetection(
            event_family="wazuh",
            event_kind=None,
            rule_id=_pick(rule.get("id")),
            level=_safe_int(rule.get("level"), minimum=0, maximum=100),
            description=_pick(rule.get("description")),
            groups=groups,
            mitre_ids=mitre_ids,
        ),
        raw_ref=None,
    )


def normalize_wazuh_alert(alert: Mapping[str, Any], *, alert_id: UUID | None = None) -> NormalizedAlert:
    """Return canonical evidence from native Wazuh JSON or a Phase 3 envelope.

    The input is never modified. `alert_id` should be the persisted alert UUID
    when this function is called after storage; otherwise a new canonical UUID
    is generated by :class:`NormalizedAlert`.
    """
    if not isinstance(alert, Mapping):
        raise ValueError("Wazuh alert must be a JSON object")
    if _is_transport_envelope(alert):
        return _normalize_transport_envelope(alert, alert_id=alert_id)

    native = _as_dict(alert)
    timestamp = _timestamp(native.get("timestamp"))
    agent = _as_dict(native.get("agent"))
    identity = extract_identity_fields(native)
    network = extract_network_fields(native)
    process = extract_process_fields(native)
    file_data = extract_file_fields(native)
    event_family = _classify_event(native, process)
    normalized_id = alert_id or uuid4()
    return NormalizedAlert(
        id=normalized_id,
        timestamp=timestamp,
        host=NormalizedHost(
            id=_pick(agent.get("id")),
            name=_pick(agent.get("name")),
            ip=_pick_ip(agent.get("ip")),
        ),
        identity=identity,
        network=network,
        process=process,
        file=file_data,
        detection=_detection(native, event_family, identity=identity, process=process, file_data=file_data),
        raw_ref=_pick(native.get("id")),
    )
