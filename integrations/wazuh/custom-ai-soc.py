#!/usr/bin/env python3
"""Forward Wazuh alerts to the AI SOC backend.

Wazuh invokes a custom integration with:
    custom-ai-soc.py <alert_file> <api_key> <hook_url>

The first argument is the alert JSON file, the second is the value from
``<api_key>``, and the third is the value from ``<hook_url>``.  The adapter
keeps the original Wazuh alert in ``raw`` and sends a small, stable envelope
that the backend can validate independently of Wazuh decoder details.
"""

import hashlib
import hmac
import json
import logging
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

LOG_FILE = "/var/ossec/logs/integrations.log"
DEFAULT_HOOK_URL = "http://localhost:8000/api/v1/alerts"
DELIVERY_ATTEMPTS = 3
DELIVERY_TIMEOUT_SECONDS = 10

try:
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s custom-ai-soc %(levelname)s: %(message)s",
    )
except OSError:
    # Permit local contract tests to import the adapter outside a Wazuh host.
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s custom-ai-soc %(levelname)s: %(message)s",
    )


logger = logging.getLogger("custom-ai-soc")


def sign(secret: str, timestamp: str, body: bytes) -> str:
    """Return the signature expected by the backend verifier."""
    message = timestamp.encode("utf-8") + b"." + body
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text(value: Any) -> str | None:
    if value is None or isinstance(value, (dict, list, tuple, set)):
        return None
    text = str(value).strip()
    return text or None


def _pick(*values: Any) -> str | None:
    for value in values:
        result = _text(value)
        if result is not None:
            return result
    return None


def _values(value: Any) -> list[str]:
    if value is None:
        return []
    candidates = value if isinstance(value, (list, tuple, set)) else [value]
    return [item for item in (_text(candidate) for candidate in candidates) if item]


def _safe_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _nested_value(container: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in container:
            return container[key]
    return None


def _first_present(*values: Any) -> Any:
    for value in values:
        if value is not None:
            return value
    return None


def _timestamp(value: Any) -> str:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError) as exc:
            raise ValueError("Wazuh alert has an invalid timestamp") from exc
    result = _text(value)
    if result is None:
        raise ValueError("Wazuh alert has no timestamp")
    return result


def _hash_from(*containers: dict[str, Any]) -> str | None:
    # Prefer the strongest hash and handle both FIM (_after) and decoder keys.
    for key in (
        "sha256_after",
        "sha256",
        "sha1_after",
        "sha1",
        "md5_after",
        "md5",
        "hash",
    ):
        for container in containers:
            result = _text(container.get(key))
            if result:
                return result
    return None


def extract_event_fields(alert: dict[str, Any]) -> dict[str, Any]:
    """Extract common network, identity, process, and FIM fields safely."""
    data = _as_dict(alert.get("data"))
    win = _as_dict(data.get("win"))
    eventdata = _as_dict(win.get("eventdata"))
    event_system = _as_dict(win.get("system"))
    audit = _as_dict(data.get("audit"))
    network = _as_dict(data.get("network"))
    process = _as_dict(data.get("process"))
    file_data = _as_dict(data.get("file"))
    syscheck = _as_dict(alert.get("syscheck"))
    if not syscheck:
        syscheck = _as_dict(data.get("syscheck"))

    src_ip = _pick(
        data.get("srcip"),
        data.get("src_ip"),
        network.get("srcip"),
        network.get("src_ip"),
        eventdata.get("sourceIp"),
        eventdata.get("sourceIPAddress"),
    )
    dst_ip = _pick(
        data.get("dstip"),
        data.get("dst_ip"),
        network.get("dstip"),
        network.get("dst_ip"),
        eventdata.get("destinationIp"),
        eventdata.get("destinationIPAddress"),
    )

    username = _pick(
        data.get("srcuser"),
        data.get("dstuser"),
        data.get("user"),
        data.get("username"),
        audit.get("auid"),
        audit.get("uid"),
        eventdata.get("subjectUserName"),
        eventdata.get("targetUserName"),
        eventdata.get("user"),
    )
    process_name = _pick(
        eventdata.get("newProcessName"),
        eventdata.get("image"),
        data.get("process_name"),
        process.get("name"),
        process.get("image"),
        audit.get("exe"),
    )
    process_command_line = _pick(
        eventdata.get("commandLine"),
        eventdata.get("commandline"),
        data.get("command"),
        process.get("command_line"),
        process.get("commandLine"),
        audit.get("command"),
    )
    file_path = _pick(
        syscheck.get("path"),
        syscheck.get("name"),
        data.get("path"),
        file_data.get("path"),
        file_data.get("name"),
        eventdata.get("targetFilename"),
    )

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": _safe_int(
            _first_present(
                _nested_value(data, "srcport", "src_port"),
                _nested_value(network, "srcport", "src_port"),
            )
        ),
        "dst_port": _safe_int(
            _first_present(
                _nested_value(data, "dstport", "dst_port"),
                _nested_value(network, "dstport", "dst_port"),
            )
        ),
        "username": username,
        "process_name": process_name,
        "process_command_line": process_command_line,
        "file_path": file_path,
        "file_hash": _hash_from(syscheck, data, file_data, eventdata),
        # Keep these local variables intentionally unused; they document that
        # Windows system metadata is accepted without putting raw fields in the
        # normalized contract.
        "_event_system_present": bool(event_system),
    }


def normalize(alert: dict[str, Any]) -> dict[str, Any]:
    """Convert a native Wazuh alert to the backend's normalized envelope."""
    if not isinstance(alert, dict):
        raise ValueError("Wazuh alert must be a JSON object")

    rule = _as_dict(alert.get("rule"))
    agent = _as_dict(alert.get("agent"))
    mitre = rule.get("mitre")
    mitre_ids = mitre.get("id") if isinstance(mitre, dict) else mitre

    event = extract_event_fields(alert)
    event.pop("_event_system_present", None)
    return {
        "source": "wazuh",
        "timestamp": _timestamp(alert.get("timestamp")),
        "agent": {
            "id": _pick(agent.get("id")),
            "name": _pick(agent.get("name")),
            "ip": _pick(agent.get("ip")),
        },
        "rule": {
            "id": _pick(rule.get("id")),
            "level": _safe_int(rule.get("level")),
            "description": _pick(rule.get("description")),
            "groups": _values(rule.get("groups")),
            "mitre_ids": _values(mitre_ids),
        },
        "event": event,
        "raw": alert,
    }


def _delivery_once(hook_url: str, secret: str, body: bytes) -> None:
    timestamp = str(time.time())
    request = urllib.request.Request(
        hook_url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-SOC-Timestamp": timestamp,
            "X-SOC-Signature": sign(secret, timestamp, body),
        },
    )
    with urllib.request.urlopen(request, timeout=DELIVERY_TIMEOUT_SECONDS) as response:
        code = response.getcode()
        if code < 200 or code >= 300:
            raise RuntimeError(f"backend returned HTTP {code}")
        response.read()


def send(hook_url: str, secret: str, payload: dict[str, Any]) -> None:
    """Deliver an alert, retrying transient network/server failures briefly."""
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    last_error: Exception | None = None

    for attempt in range(DELIVERY_ATTEMPTS):
        try:
            _delivery_once(hook_url, secret, body)
            return
        except urllib.error.HTTPError as exc:
            last_error = exc
            # A bad secret or malformed request will not become valid on retry.
            if 400 <= exc.code < 500:
                break
        except (urllib.error.URLError, OSError, RuntimeError, TimeoutError) as exc:
            last_error = exc

        if attempt < DELIVERY_ATTEMPTS - 1:
            time.sleep(0.25 * (2**attempt))

    raise RuntimeError("unable to deliver alert") from last_error


def main() -> int:
    if len(sys.argv) < 3:
        logger.error("Usage: custom-ai-soc.py <alert_file> <api_key> [hook_url]")
        return 1

    alert_file, api_key = sys.argv[1], sys.argv[2]
    hook_url = (sys.argv[3] if len(sys.argv) > 3 else "") or DEFAULT_HOOK_URL
    if not api_key:
        logger.error("Wazuh integration API key is empty")
        return 1

    try:
        with open(alert_file, encoding="utf-8") as file_handle:
            alert = json.load(file_handle)
        payload = normalize(alert)
        send(hook_url, api_key, payload)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        logger.error("Failed to read or normalize Wazuh alert: %s", exc)
        return 1
    except Exception as exc:  # noqa: BLE001 - never emit a traceback from Integrator
        logger.error("Failed to deliver Wazuh alert: %s", exc)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
