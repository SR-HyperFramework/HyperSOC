#!/usr/bin/env python3
"""Validate structural benchmark invariants without machine-specific timing gates."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from batch_replay import SOURCE_REVISION, SOURCE_SHA256


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("pilot", "workload"))
    parser.add_argument("result", type=Path)
    args = parser.parse_args()
    payload = json.loads(args.result.read_text(encoding="utf-8"))
    if payload.get("status") != "completed":
        raise SystemExit("benchmark did not complete")
    serialized = json.dumps(payload, sort_keys=True)
    if "benchmark-only-secret-value" in serialized:
        raise SystemExit("benchmark output leaked its signing secret")
    if args.kind == "pilot":
        system = payload.get("system", {})
        if system.get("automation_status") != "triaged" or system.get("provider_mode") != "offline":
            raise SystemExit("pilot did not complete offline triage")
        return
    if payload.get("kind") != "full_dataset_workload_not_accuracy":
        raise SystemExit("unexpected workload result kind")
    if payload.get("source_revision") != SOURCE_REVISION or payload.get("source_sha256") != SOURCE_SHA256:
        raise SystemExit("workload source pin does not match")
    if payload.get("source_alert_count") != 738 or payload.get("replay_alert_count") != 738:
        raise SystemExit("workload did not replay all 738 source alerts")
    ingest = payload.get("ingest", {})
    if ingest.get("unique_persisted_alerts") != 738 or ingest.get("deduplicated_requests") != 0:
        raise SystemExit("workload lost distinct source alerts during ingest")
    if payload.get("triage_requested"):
        triage = payload.get("triage", {})
        results = triage.get("results")
        incident_count = payload.get("correlation", {}).get("incidents")
        if (
            set(triage) != {"result_schema", "requests", "provider_modes", "latency_seconds", "results"}
            or triage.get("result_schema") != "triage_decisions.v1"
            or type(incident_count) is not int
            or type(results) is not list
            or triage.get("requests") != incident_count
            or len(results) != incident_count
        ):
            raise SystemExit("workload triage decisions are incomplete")
        fields = {
            "incident_key", "source_alert_count", "status", "provider_mode", "latency_seconds",
            "classification", "severity", "confidence", "false_positive_probability",
        }
        keys = set()
        modes = set()
        for result in results:
            if not isinstance(result, dict) or set(result) != fields:
                raise SystemExit("workload triage decision has unexpected fields")
            key = result["incident_key"]
            if not isinstance(key, str) or len(key) != 64 or any(char not in "0123456789abcdef" for char in key):
                raise SystemExit("workload triage incident key is invalid")
            keys.add(key)
            modes.add(result["provider_mode"])
            if (
                result["status"] != "completed"
                or type(result["source_alert_count"]) is not int or result["source_alert_count"] < 1
                or result["provider_mode"] not in {"offline", "jev"}
                or result["classification"] not in {"true_positive", "false_positive", "needs_investigation", "unknown"}
                or result["severity"] not in {"low", "medium", "high", "critical"}
                or type(result["confidence"]) is not int or not 0 <= result["confidence"] <= 100
                or type(result["false_positive_probability"]) is not int or not 0 <= result["false_positive_probability"] <= 100
            ):
                raise SystemExit("workload triage decision is invalid")
        if len(keys) != incident_count or len(modes) > 1 or triage["provider_modes"] != sorted(modes):
            raise SystemExit("workload triage decisions cannot be paired consistently")


if __name__ == "__main__":
    main()
