import importlib.util
from pathlib import Path


SCRIPT_PATH = Path(__file__).parents[2] / "integrations" / "wazuh" / "custom-ai-soc.py"
if not SCRIPT_PATH.exists():
    SCRIPT_PATH = Path(__file__).parents[1] / "integrations" / "wazuh" / "custom-ai-soc.py"
_spec = importlib.util.spec_from_file_location("custom_ai_soc", SCRIPT_PATH)
assert _spec and _spec.loader
custom_ai_soc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(custom_ai_soc)


def test_native_hook_preserves_native_event_while_legacy_hook_keeps_envelope(tmp_path, monkeypatch):
    import json
    alert = {"id": "native-event-1", "timestamp": "2026-10-05T12:00:00Z", "agent": {"id": "000", "name": "manager"}, "rule": {"id": "110901", "level": 5}}
    path = tmp_path / 'alert.json'
    path.write_text(json.dumps(alert))
    deliveries = []
    monkeypatch.setattr(custom_ai_soc, 'send', lambda url, key, payload: deliveries.append(payload))
    monkeypatch.setattr(custom_ai_soc.sys, 'argv', ['custom-ai-soc', str(path), 'test-secret', 'http://backend:8000/api/v1/hub/native-events'])
    assert custom_ai_soc.main() == 0
    assert deliveries[-1] == {"format": "wazuh", "source": "wazuh", "event": alert}
    monkeypatch.setattr(custom_ai_soc.sys, 'argv', ['custom-ai-soc', str(path), 'test-secret', 'http://backend:8000/api/v1/alerts'])
    assert custom_ai_soc.main() == 0
    assert deliveries[-1]['raw'] == alert and deliveries[-1]['source'] == 'wazuh'


def test_normalize_sysmon_alert():
    alert = {
        "id": "1700000000.1",
        "timestamp": "2026-09-12T12:00:00.000+0000",
        "agent": {"id": "001", "name": "win-endpoint", "ip": "192.0.2.10"},
        "rule": {
            "id": "61603",
            "level": "10",
            "description": "Sysmon - process created",
            "groups": "sysmon",
            "mitre": {"id": "T1059.001"},
        },
        "data": {
            "win": {
                "eventdata": {
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "commandLine": "powershell.exe -NoProfile -Command whoami",
                }
            },
        },
    }

    normalized = custom_ai_soc.normalize(alert)

    assert normalized["timestamp"] == alert["timestamp"]
    assert normalized["rule"]["level"] == 10
    assert normalized["rule"]["groups"] == ["sysmon"]
    assert normalized["rule"]["mitre_ids"] == ["T1059.001"]
    assert normalized["event"]["process_name"].endswith("powershell.exe")
    assert normalized["raw"] is alert


def test_normalize_fim_alert_and_numeric_ports():
    alert = {
        "timestamp": "2026-09-12T12:00:00Z",
        "agent": None,
        "rule": {"groups": ["syscheck", "file_integrity"], "mitre": {"id": []}},
        "syscheck": {
            "path": "/etc/ssh/sshd_config",
            "sha256_after": "a" * 64,
        },
        "data": {
            "srcip": "198.51.100.20",
            "dstport": "22",
            "srcport": "54321",
        },
    }

    normalized = custom_ai_soc.normalize(alert)

    assert normalized["agent"] == {"id": None, "name": None, "ip": None}
    assert normalized["event"]["src_port"] == 54321
    assert normalized["event"]["dst_port"] == 22
    assert normalized["event"]["file_path"] == "/etc/ssh/sshd_config"
    assert normalized["event"]["file_hash"] == "a" * 64


def test_signature_matches_backend_contract():
    from app.core.security import sign_payload

    body = b'{"source":"wazuh"}'
    assert custom_ai_soc.sign("secret", "1000", body) == sign_payload("secret", "1000", body)


def test_normalize_keeps_epoch_timestamp_parseable():
    normalized = custom_ai_soc.normalize({"timestamp": 0})
    assert normalized["timestamp"].startswith("1970-01-01T00:00:00")


def test_normalize_rejects_missing_timestamp():
    try:
        custom_ai_soc.normalize({})
    except ValueError as exc:
        assert "timestamp" in str(exc)
    else:
        raise AssertionError("missing timestamp should be rejected")
