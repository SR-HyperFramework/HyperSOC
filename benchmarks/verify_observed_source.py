#!/usr/bin/env python3
"""Verify observed benchmark projections against a pinned public Wazuh dataset.

Read-only: downloads the pinned source into memory, checks its SHA-256, then
checks source IDs, event timing, behavior fields, and documented redactions.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.request
from datetime import datetime
from pathlib import Path

CATALOG = Path(__file__).with_name("cases.json")
SOURCE = "https://huggingface.co/datasets/kholil-lil/wazuh-alerts/resolve/{revision}/wazuh_formatted_alerts.json"
EXPECTED_AUTHOR_LABELS = {"C09": "True Positive", "C10": "True Positive", "C11": "False Positive"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def verify_case(case: dict, source_by_id: dict[str, dict]) -> None:
    original_alerts = [source_by_id[source_id]["input"] for source_id in case["source_alert_ids"]]
    origin_start = datetime.fromisoformat(original_alerts[0]["timestamp"])
    for source_row, original, curated in zip(
        (source_by_id[source_id] for source_id in case["source_alert_ids"]),
        original_alerts,
        case["alerts"],
        strict=True,
    ):
        require(source_row["output"] == EXPECTED_AUTHOR_LABELS[case["id"]], f"{curated['key']}: source author label mismatch")
        require(round((datetime.fromisoformat(original["timestamp"]) - origin_start).total_seconds()) == curated["offset_seconds"], f"{curated['key']}: offset mismatch")
        for key in ("id", "level", "description", "groups"):
            require(curated["rule"][key] == original["rule"][key], f"{curated['key']}: rule.{key} mismatch")
        if "mitre" in curated["rule"]:
            require(curated["rule"]["mitre"]["id"] == original["rule"]["mitre"]["id"], f"{curated['key']}: MITRE mismatch")
        require(curated["decoder"]["name"] == original["decoder"]["name"], f"{curated['key']}: decoder mismatch")
        require(curated["location"] == original["location"], f"{curated['key']}: location mismatch")

        original_data = original.get("data") or {}
        curated_data = curated.get("data") or {}
        require(set(original_data) == set(curated_data), f"{curated['key']}: data fields mismatch")
        original_ip = original_data.get("srcip")
        curated_ip = curated_data.get("srcip")
        for key, value in original_data.items():
            if key != "srcip":
                expected_value = {"me": "candidate-a", "yuan": "candidate-b"}.get(value, value) if key == "srcuser" and case["id"] == "C09" else value
                require(curated_data[key] == expected_value, f"{curated['key']}: data.{key} mismatch")
        if original_ip:
            require(original_ip != curated_ip, f"{curated['key']}: IP not redacted")
        expected_log = original["full_log"]
        if original_ip:
            expected_log = expected_log.replace(original_ip, curated_ip)
        if case["id"] == "C09":
            expected_log = expected_log.replace("wazuh-server", "observed-ssh-host")
            expected_log = re.sub(r"\bme\b", "candidate-a", expected_log)
            expected_log = re.sub(r"\byuan\b", "candidate-b", expected_log)
        require(curated["full_log"] == expected_log, f"{curated['key']}: full_log mismatch")


def main() -> None:
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    cases = [case for case in catalog["cases"] if case.get("origin") == "public_observed_wazuh_redacted_projection"]
    if not cases:
        raise SystemExit("no observed cases to verify")
    revisions = {case["source_revision"] for case in cases}
    digests = {case["source_sha256"] for case in cases}
    if len(revisions) != 1 or len(digests) != 1:
        raise ValueError("observed cases must pin one source revision and digest")
    revision = next(iter(revisions))
    url = SOURCE.format(revision=revision)
    with urllib.request.urlopen(url, timeout=30) as response:
        body = response.read()
    actual_digest = hashlib.sha256(body).hexdigest()
    if actual_digest != next(iter(digests)):
        raise ValueError(f"source SHA-256 mismatch: {actual_digest}")
    rows = json.loads(body)
    source_by_id = {}
    for row in rows:
        alert = json.loads(row["input"])
        source_by_id[alert["id"]] = {"input": alert, "output": row["output"]}
    for case in cases:
        verify_case(case, source_by_id)
    print(f"Verified {len(cases)} observed cases / {sum(len(case['alerts']) for case in cases)} alerts against pinned source {revision} ({actual_digest})")


if __name__ == "__main__":
    main()
