from datetime import datetime, timezone

import pytest

from app.core.security import sign_payload
from app.schemas.alert import AgentIn, AlertIngest, EventIn, RuleIn
from app.services.wazuh import compute_fingerprint


def test_sign_payload_is_deterministic():
    body = b'{"hello":"world"}'
    sig1 = sign_payload("secret", "1000", body)
    sig2 = sign_payload("secret", "1000", body)
    assert sig1 == sig2


def test_sign_payload_changes_with_body():
    sig1 = sign_payload("secret", "1000", b"a")
    sig2 = sign_payload("secret", "1000", b"b")
    assert sig1 != sig2


def _sample_alert(src_ip: str = "10.10.10.50") -> AlertIngest:
    return AlertIngest(
        source="wazuh",
        timestamp=datetime(2026, 9, 11, tzinfo=timezone.utc),
        agent=AgentIn(id="001", name="Win10-Endpoint", ip="192.168.121.131"),
        rule=RuleIn(id="5710", level=5, description="sshd auth failed", mitre_ids=["T1110"]),
        event=EventIn(src_ip=src_ip, username="root"),
        raw={"id": "1234567890"},
    )


def test_fingerprint_is_stable_for_same_alert():
    alert = _sample_alert()
    assert compute_fingerprint(alert) == compute_fingerprint(alert)


def test_fingerprint_differs_for_different_source_ip():
    assert compute_fingerprint(_sample_alert("10.10.10.50")) != compute_fingerprint(
        _sample_alert("10.10.10.51")
    )


def test_fingerprint_differs_for_different_ports():
    first = _sample_alert()
    second = _sample_alert()
    first.event.src_port = 22
    second.event.src_port = 23
    assert compute_fingerprint(first) != compute_fingerprint(second)


def test_fingerprint_differs_for_different_file_paths():
    first = _sample_alert()
    second = _sample_alert()
    first.event.file_path = "/tmp/one"
    second.event.file_path = "/tmp/two"
    assert compute_fingerprint(first) != compute_fingerprint(second)


@pytest.mark.parametrize(
    ("rule_id", "first_log", "second_log"),
    [
        ("5710", "Invalid user from source", "Disconnected from invalid user"),
        ("591", "File rotated: access.log", "File rotated: error.log"),
        ("5501", "sshd session opened", "systemd session opened"),
    ],
)
def test_fingerprint_keeps_distinct_wazuh_alert_ids(rule_id, first_log, second_log):
    first = _sample_alert()
    second = _sample_alert()
    first.rule.id = second.rule.id = rule_id
    first.raw = {"id": "1741132834.383", "full_log": first_log}
    second.raw = {"id": "1741132834.761", "full_log": second_log}
    assert compute_fingerprint(first) != compute_fingerprint(second)


def test_fingerprint_without_source_id_preserves_content_fallback():
    first = _sample_alert()
    second = _sample_alert()
    first.raw = second.raw = {}
    assert compute_fingerprint(first) == compute_fingerprint(second)
    second.event.src_ip = "10.10.10.51"
    assert compute_fingerprint(first) != compute_fingerprint(second)
