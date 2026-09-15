from copy import deepcopy
from datetime import timezone
from uuid import UUID

import pytest

from app.schemas.alert import AlertIngest
from app.services.normalization import (
    extract_file_fields,
    extract_identity_fields,
    extract_mitre,
    extract_network_fields,
    extract_process_fields,
    normalize_wazuh_alert,
)
from app.services.wazuh import normalize_ingested_alert


def _alert(**overrides):
    alert = {
        "id": "1700000000.1",
        "timestamp": "2026-09-12T12:00:00.000+0000",
        "agent": {"id": "001", "name": "win-endpoint", "ip": "192.0.2.10"},
        "rule": {"id": "61603", "level": "10", "description": "Sysmon process created"},
        "data": {},
    }
    alert.update(overrides)
    return alert


def test_normalize_sysmon_process_network_and_file_without_mutating_input():
    alert = _alert(
        rule={
            "id": "61603",
            "level": "10",
            "description": "Sysmon process created",
            "groups": ["sysmon", "sysmon", "windows"],
            "mitre": {"id": ["T1059.001", "T1059.001", "not-mitre"]},
        },
        data={
            "win": {
                "system": {"providerName": "Microsoft-Windows-Sysmon", "eventID": "1"},
                "eventdata": {
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "commandLine": "powershell.exe -NoProfile -Command whoami",
                    "parentImage": "C:\\Windows\\explorer.exe",
                    "processId": "4242",
                    "sourceIp": "198.51.100.20",
                    "destinationIPAddress": "203.0.113.10",
                    "sourcePort": "49152",
                    "destinationPort": "443",
                    "targetFilename": "C:\\Temp\\dropped.exe",
                    "hashes": "SHA1=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,SHA256=" + "a" * 64,
                },
            }
        },
    )
    original = deepcopy(alert)

    normalized = normalize_wazuh_alert(alert)

    assert alert == original
    assert normalized.timestamp.tzinfo == timezone.utc
    assert normalized.host.model_dump() == {"id": "001", "name": "win-endpoint", "ip": "192.0.2.10"}
    assert normalized.detection.event_family == "sysmon"
    assert normalized.detection.event_id == "1"
    assert normalized.detection.groups == ["sysmon", "windows"]
    assert normalized.detection.mitre_ids == ["T1059.001"]
    assert normalized.network.src_ip == "198.51.100.20"
    assert normalized.network.dst_ip == "203.0.113.10"
    assert normalized.network.src_port == 49152
    assert normalized.network.dst_port == 443
    assert normalized.process.name == "powershell.exe"
    assert normalized.process.parent_name == "explorer.exe"
    assert normalized.process.pid == 4242
    assert normalized.file.path == "C:\\Temp\\dropped.exe"
    assert normalized.file.hash == "A" * 64
    assert normalized.file.hash_algorithm == "SHA256"
    assert normalized.process.hash == "A" * 64
    assert normalized.process.hash_algorithm == "SHA256"
    assert normalized.detection.event_kind == "process"
    assert normalized.raw_ref == "1700000000.1"


def test_normalize_windows_authentication():
    alert = _alert(
        rule={"groups": "windows authentication", "description": "Failed logon", "mitre": {"id": "T1110"}},
        data={
            "win": {
                "system": {"eventID": 4625},
                "eventdata": {
                    "subjectUserName": "SYSTEM",
                    "targetUserName": "alice",
                    "targetDomainName": "EXAMPLE",
                    "ipAddress": "203.0.113.99",
                    "logonType": "3",
                    "failureReason": "Unknown user name or bad password",
                    "status": "0xC000006D",
                    "authenticationPackageName": "NTLM",
                },
            }
        },
    )

    normalized = normalize_wazuh_alert(alert)

    assert normalized.detection.event_family == "windows_authentication"
    assert normalized.detection.event_id == "4625"
    assert normalized.identity.username == "alice"
    assert normalized.identity.actor == "SYSTEM"
    assert normalized.identity.target == "alice"
    assert normalized.identity.domain == "EXAMPLE"
    assert normalized.identity.auth_outcome == "failure"
    assert normalized.identity.auth_status == "0xC000006D"
    assert normalized.identity.logon_type == "3"
    assert normalized.identity.auth_method == "NTLM"
    assert normalized.identity.failure_reason == "Unknown user name or bad password"
    assert normalized.network.src_ip == "203.0.113.99"
    assert normalized.detection.event_kind == "authentication"
    assert normalized.detection.outcome == "failure"
    assert normalized.detection.status == "0xC000006D"


def test_normalize_powershell_from_image_when_rule_group_is_missing():
    alert = _alert(
        data={
            "win": {
                "eventdata": {
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "commandline": "powershell -EncodedCommand ZQBjAGgAbwA=",
                    "scriptBlockText": "Write-Host 'hello'",
                }
            }
        }
    )

    normalized = normalize_wazuh_alert(alert)

    assert normalized.detection.event_family == "powershell"
    assert normalized.detection.event_kind == "script"
    assert normalized.process.command_line == "powershell -EncodedCommand ZQBjAGgAbwA="
    assert normalized.process.script_block == "Write-Host 'hello'"


def test_normalize_linux_ssh_authentication():
    alert = _alert(
        rule={"groups": ["sshd", "authentication_failed"], "description": "sshd: authentication failed"},
        data={
            "srcip": "2001:db8::7",
            "srcuser": "root",
            "dstuser": "deploy",
            "srcport": "54123",
            "dstport": "22",
            "ssh": {"method": "password", "status": "failed", "failure_reason": "Invalid user"},
        },
    )

    normalized = normalize_wazuh_alert(alert)

    assert normalized.detection.event_family == "linux_ssh"
    assert normalized.identity.username == "root"
    assert normalized.identity.actor == "root"
    assert normalized.identity.target == "deploy"
    assert normalized.identity.auth_outcome == "failure"
    assert normalized.identity.auth_method == "password"
    assert normalized.network.src_ip == "2001:db8::7"
    assert normalized.network.dst_port == 22


def test_normalize_auditd_process_identity_and_file():
    alert = _alert(
        rule={"groups": ["audit", "auditd"], "description": "Audit event"},
        data={
            "audit": {
                "auid": "1000",
                "uid": "0",
                "exe": "/usr/bin/sudo",
                "command": "sudo cat /etc/shadow",
                "pid": "1234",
                "path": "/etc/shadow",
                "success": "yes",
            }
        },
    )

    normalized = normalize_wazuh_alert(alert)

    assert normalized.detection.event_family == "auditd"
    assert normalized.identity.username == "1000"
    assert normalized.identity.auth_outcome == "success"
    assert normalized.process.image == "/usr/bin/sudo"
    assert normalized.process.name == "sudo"
    assert normalized.process.pid == 1234
    assert normalized.file.path == "/etc/shadow"


def test_normalize_fim_prefers_strongest_hash_and_supports_data_syscheck():
    alert = _alert(
        rule={"groups": ["syscheck", "file_integrity"]},
        data={
            "syscheck": {"name": "/etc/ssh/sshd_config", "sha1_after": "b" * 40},
            "file": {"sha256": "a" * 64},
        },
    )

    normalized = normalize_wazuh_alert(alert)

    assert normalized.detection.event_family == "fim"
    assert normalized.file.path == "/etc/ssh/sshd_config"
    assert normalized.file.name == "sshd_config"
    assert normalized.file.hash == "A" * 64


def test_normalize_nginx_request_fields():
    alert = _alert(
        rule={"groups": ["nginx", "web"]},
        data={
            "nginx": {"srcip": "198.51.100.7", "host": "example.test", "url": "/../../etc/passwd", "method": "GET", "status": "404"},
            "dstport": "443",
        },
    )

    normalized = normalize_wazuh_alert(alert)

    assert normalized.detection.event_family == "nginx"
    assert normalized.network.src_ip == "198.51.100.7"
    assert normalized.network.domain == "example.test"
    assert normalized.network.url == "/../../etc/passwd"
    assert normalized.network.http_method == "GET"
    assert normalized.network.http_status == 404
    assert normalized.network.dst_port == 443
    assert normalized.detection.event_kind == "web"


@pytest.mark.parametrize(
    ("groups", "mitre", "expected_groups", "expected_mitre"),
    [
        ("sysmon", {"id": "T1059.001"}, ["sysmon"], ["T1059.001"]),
        (["sysmon", " sysmon ", ""], {"id": ["t1110", None, "T1110"]}, ["sysmon"], ["T1110"]),
        (None, None, [], []),
    ],
)
def test_collection_normalization(groups, mitre, expected_groups, expected_mitre):
    alert = _alert(rule={"groups": groups, "mitre": mitre})

    normalized = normalize_wazuh_alert(alert)

    assert normalized.detection.groups == expected_groups
    assert normalized.detection.mitre_ids == expected_mitre
    assert extract_mitre(alert) == expected_mitre


def test_phase_three_envelope_prefers_native_raw_and_compatibility_accessor():
    raw = _alert(data={"srcip": "198.51.100.20", "user": "operator"})
    envelope = {
        "source": "wazuh",
        "timestamp": "2026-09-12T12:00:00Z",
        "agent": {"id": "ignored"},
        "event": {"src_ip": "192.0.2.99"},
        "raw": raw,
    }

    normalized = normalize_wazuh_alert(envelope)
    from_ingest = normalize_ingested_alert(AlertIngest.model_validate(envelope))

    assert normalized.network.src_ip == "198.51.100.20"
    assert normalized.identity.username == "operator"
    assert from_ingest.model_dump(exclude={"id"}) == normalized.model_dump(exclude={"id"})


def test_phase_three_envelope_without_raw_uses_flat_fields_and_supplied_canonical_id():
    persisted_id = UUID("00000000-0000-0000-0000-000000000001")
    normalized = normalize_wazuh_alert(
        {
            "source": "wazuh",
            "timestamp": "2026-09-12T12:00:00Z",
            "agent": {"id": "001", "name": "host", "ip": "192.0.2.10"},
            "rule": {"id": "100", "level": "3", "groups": "test", "mitre_ids": "T1110"},
            "event": {"src_ip": "198.51.100.20", "src_port": "22", "file_hash": "a" * 64},
        },
        alert_id=persisted_id,
    )

    assert normalized.id == persisted_id
    assert normalized.host.ip == "192.0.2.10"
    assert normalized.network.src_port == 22
    assert normalized.file.hash == "A" * 64
    assert normalized.file.hash_algorithm == "SHA256"
    assert normalized.detection.mitre_ids == ["T1110"]
    assert normalized.raw_ref is None


@pytest.mark.parametrize(
    "value",
    [None, [], "not-an-object", 12],
)
def test_normalize_rejects_non_mapping_top_level(value):
    with pytest.raises(ValueError, match="JSON object"):
        normalize_wazuh_alert(value)


@pytest.mark.parametrize("timestamp", [None, True, float("nan"), float("inf"), "not-a-timestamp"])
def test_normalize_rejects_invalid_timestamp(timestamp):
    with pytest.raises(ValueError, match="valid timestamp"):
        normalize_wazuh_alert(_alert(timestamp=timestamp))


def test_malformed_optional_values_become_absent_not_evidence():
    alert = _alert(
        agent=[],
        rule={"level": "-1", "mitre": {"id": ["T1110", {"bad": "value"}]}},
        data={
            "srcip": "not-an-ip",
            "srcport": "-1",
            "dstport": 70000,
            "audit": [],
            "network": "bad",
            "win": {"eventdata": []},
            "file": {"hash": "not-a-hash"},
        },
    )

    normalized = normalize_wazuh_alert(alert)

    assert normalized.host.model_dump() == {"id": None, "name": None, "ip": None}
    assert normalized.network.src_ip is None
    assert normalized.network.src_port is None
    assert normalized.network.dst_port is None
    assert normalized.file.hash is None
    assert normalized.detection.level is None
    assert normalized.detection.mitre_ids == ["T1110"]
    assert extract_network_fields(alert).src_ip is None
    assert extract_process_fields(alert).image is None
    assert extract_file_fields(alert).hash is None
    assert extract_identity_fields(alert).username is None
