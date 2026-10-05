#!/usr/bin/env python3
"""Pair two triage workload runs by source-alert membership, not database UUID."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from batch_replay import SOURCE_REVISION, SOURCE_SHA256

DECISION_FIELDS = ("classification", "severity", "confidence", "false_positive_probability", "latency_seconds")
RESULT_FIELDS = set(DECISION_FIELDS) | {"incident_key", "source_alert_count", "status", "provider_mode"}


def _records(run: dict[str, Any]) -> tuple[str, dict[str, dict[str, Any]]]:
    triage = run.get("triage", {})
    results = triage.get("results")
    count = run.get("correlation", {}).get("incidents")
    modes = triage.get("provider_modes")
    if (
        run.get("kind") != "full_dataset_workload_not_accuracy"
        or run.get("status") != "completed"
        or run.get("source_alert_count") != 738
        or run.get("replay_alert_count") != 738
        or run.get("ingest", {}).get("unique_persisted_alerts") != 738
        or run.get("ingest", {}).get("deduplicated_requests") != 0
        or run.get("triage_requested") is not True
        or triage.get("result_schema") != "triage_decisions.v1"
        or not isinstance(results, list)
        or not isinstance(count, int)
        or len(results) != count
        or triage.get("requests") != count
        or not isinstance(modes, list)
        or len(modes) != 1
        or modes[0] not in {"offline", "jev"}
    ):
        raise ValueError("triage run is incomplete or lacks structured decisions")
    by_key = {}
    for record in results:
        if not isinstance(record, dict) or set(record) != RESULT_FIELDS:
            raise ValueError("triage run contains an incomplete or unexpected decision")
        if record["status"] != "completed" or record["provider_mode"] != modes[0]:
            raise ValueError("triage run contains an incomplete or mixed-provider decision")
        key = record.get("incident_key")
        if not isinstance(key, str) or key in by_key:
            raise ValueError("triage run contains an invalid or duplicate incident key")
        by_key[key] = record
    return modes[0], by_key


def compare(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    if (
        left.get("source_revision") != SOURCE_REVISION
        or right.get("source_revision") != SOURCE_REVISION
        or left.get("source_sha256") != SOURCE_SHA256
        or right.get("source_sha256") != SOURCE_SHA256
    ):
        raise ValueError("triage runs must use the same pinned source")
    left_mode, left_rows = _records(left)
    right_mode, right_rows = _records(right)
    shared = sorted(left_rows.keys() & right_rows.keys())
    pairs = []
    for key in shared:
        left_row = left_rows[key]
        right_row = right_rows[key]
        if left_row["source_alert_count"] != right_row["source_alert_count"]:
            raise ValueError("paired incident source-alert counts differ")
        pairs.append({
            "incident_key": key,
            "source_alert_count": left_row["source_alert_count"],
            "left": {field: left_row[field] for field in DECISION_FIELDS},
            "right": {field: right_row[field] for field in DECISION_FIELDS},
        })
    return {
        "kind": "triage_run_comparison_not_accuracy",
        "source_revision": SOURCE_REVISION,
        "left_provider_mode": left_mode,
        "right_provider_mode": right_mode,
        "left_incidents": len(left_rows),
        "right_incidents": len(right_rows),
        "paired_incidents": len(shared),
        "left_only_keys": sorted(left_rows.keys() - right_rows.keys()),
        "right_only_keys": sorted(right_rows.keys() - left_rows.keys()),
        "classification_agreement": round(sum(pair["left"]["classification"] == pair["right"]["classification"] for pair in pairs) / len(pairs), 4) if pairs else None,
        "severity_agreement": round(sum(pair["left"]["severity"] == pair["right"]["severity"] for pair in pairs) / len(pairs), 4) if pairs else None,
        "pairs": pairs,
        "note": "Agreement is not accuracy; incident-level ground truth and analyst review are still required.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("left", type=Path)
    parser.add_argument("right", type=Path)
    args = parser.parse_args()
    left = json.loads(args.left.read_text(encoding="utf-8"))
    right = json.loads(args.right.read_text(encoding="utf-8"))
    print(json.dumps(compare(left, right), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
