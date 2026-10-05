#!/usr/bin/env python3
"""Replay the pinned public Wazuh dataset as a HyperSOC workload benchmark.

This measures pipeline work and coverage, not incident-label accuracy or
analyst time saved. Source alert labels are never sent to the backend.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
import re
import statistics
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from soc_benchmark import _load_wazuh_adapter, api_json, percentile95, require_local_url

SOURCE_REVISION = "13cc552c9de42eecee22f6e4c2fe34c80ae3f5d8"
SOURCE_SHA256 = "487bc73ace742995e5e09622494c0b750f513c3a9328dd2276c50444ab0df532"
SOURCE_URL = f"https://huggingface.co/datasets/kholil-lil/wazuh-alerts/resolve/{SOURCE_REVISION}/wazuh_formatted_alerts.json"
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
TEST_NETS = ("192.0.2", "198.51.100", "203.0.113")
CLASSIFICATIONS = {"true_positive", "false_positive", "needs_investigation", "unknown"}
SEVERITIES = {"low", "medium", "high", "critical"}


def fetch_source() -> list[dict[str, Any]]:
    with urllib.request.urlopen(SOURCE_URL, timeout=60) as response:
        body = response.read()
    digest = hashlib.sha256(body).hexdigest()
    if digest != SOURCE_SHA256:
        raise ValueError(f"source SHA-256 mismatch: {digest}")
    rows = json.loads(body)
    if not isinstance(rows, list) or not rows:
        raise ValueError("source dataset is empty or malformed")
    # Deliberately discard the author's per-alert output labels.
    return [json.loads(row["input"]) for row in rows]


def _test_net_address(index: int) -> str:
    if index >= len(TEST_NETS) * 254:
        raise ValueError("too many distinct IP addresses for deterministic redaction")
    return f"{TEST_NETS[index // 254]}.{index % 254 + 1}"


def redact_ips(value: Any, mapping: dict[str, str]) -> Any:
    if isinstance(value, str):
        def replace(match: re.Match[str]) -> str:
            candidate = match.group()
            try:
                ipaddress.IPv4Address(candidate)
            except ipaddress.AddressValueError:
                return candidate
            if candidate not in mapping:
                mapping[candidate] = _test_net_address(len(mapping))
            return mapping[candidate]

        return IPV4.sub(replace, value)
    if isinstance(value, list):
        return [redact_ips(item, mapping) for item in value]
    if isinstance(value, dict):
        return {key: redact_ips(item, mapping) for key, item in value.items()}
    return value


def prepare_replay(alerts: list[dict[str, Any]], *, now: datetime) -> tuple[list[dict[str, Any]], int, int]:
    if not alerts:
        raise ValueError("no alerts to replay")
    ordered = sorted(alerts, key=lambda alert: datetime.fromisoformat(alert["timestamp"]))
    original_times = [datetime.fromisoformat(alert["timestamp"]).astimezone(timezone.utc) for alert in ordered]
    span = original_times[-1] - original_times[0]
    shift = now.astimezone(timezone.utc) - timedelta(minutes=2) - original_times[-1]
    mapping: dict[str, str] = {}
    replay = []
    for alert, original_time in zip(ordered, original_times, strict=True):
        redacted = redact_ips(alert, mapping)
        redacted["timestamp"] = (original_time + shift).isoformat()
        replay.append(redacted)
    return replay, max(60, math.ceil(span.total_seconds() / 60) + 10), len(mapping)


def duration_stats(values: list[float]) -> dict[str, float | None]:
    if not values:
        return {"total": 0.0, "median": None, "p95": None}
    return {
        "total": round(sum(values), 4),
        "median": round(statistics.median(values), 4),
        "p95": round(percentile95(values), 4),
    }


def incident_key(source_ids: set[str]) -> str:
    if not source_ids:
        raise ValueError("correlated incident has no source alert IDs")
    encoded = json.dumps(sorted(source_ids), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def triage_decision(payload: dict[str, Any]) -> dict[str, str | int]:
    result = payload["result"]
    classification = result["classification"]
    severity = result["severity"]
    confidence = result["confidence"]
    false_positive_probability = result["false_positive_probability"]
    if classification not in CLASSIFICATIONS or severity not in SEVERITIES:
        raise ValueError("triage returned an invalid decision")
    if type(confidence) is not int or not 0 <= confidence <= 100:
        raise ValueError("triage returned invalid confidence")
    if type(false_positive_probability) is not int or not 0 <= false_positive_probability <= 100:
        raise ValueError("triage returned invalid false-positive probability")
    return {
        "classification": classification,
        "severity": severity,
        "confidence": confidence,
        "false_positive_probability": false_positive_probability,
    }


def replay(args: argparse.Namespace) -> dict[str, Any]:
    require_local_url(args.base_url)
    if not args.isolated_db:
        raise ValueError("--isolated-db is required to confirm a disposable benchmark stack")
    secret = os.getenv("APP_SECRET_KEY")
    if not secret:
        raise ValueError("APP_SECRET_KEY must be set in the environment")
    if args.output.exists():
        raise FileExistsError(f"refusing to overwrite result: {args.output}")
    summary: dict[str, Any] = {
        "kind": "full_dataset_workload_not_accuracy",
        "status": "failed",
        "source_revision": SOURCE_REVISION,
        "source_sha256": SOURCE_SHA256,
        "ip_redaction": "deterministic_TEST_NET",
        "triage_requested": args.triage,
    }
    pipeline_started: float | None = None
    stage = "preflight"
    try:
        if api_json(args.base_url, "GET", "/api/v1/alerts?limit=1"):
            raise RuntimeError("benchmark database is not empty; use a fresh isolated database")
        if api_json(args.base_url, "GET", "/api/v1/incidents?limit=1"):
            raise RuntimeError("benchmark database already contains incidents; use a fresh isolated database")
        stage = "source_download"
        download_started = time.perf_counter()
        source_alerts = fetch_source()
        summary["source_download_seconds"] = round(time.perf_counter() - download_started, 4)
        stage = "preparation"
        replay_alerts, lookback_minutes, redacted_ip_count = prepare_replay(source_alerts, now=datetime.now(timezone.utc))
        summary.update({
            "source_alert_count": len(source_alerts),
            "replay_alert_count": len(replay_alerts),
            "lookback_minutes": lookback_minutes,
            "redacted_ip_count": redacted_ip_count,
            "replay_first_timestamp": replay_alerts[0]["timestamp"],
            "replay_last_timestamp": replay_alerts[-1]["timestamp"],
        })
        adapter = _load_wazuh_adapter()
        pipeline_started = time.perf_counter()
        stage = "ingest"
        ingest_times: list[float] = []
        alert_ids: list[str] = []
        source_ids_by_alert_id: dict[str, set[str]] = {}
        for index, raw in enumerate(replay_alerts, start=1):
            summary["last_attempted_alert_index"] = index
            started = time.perf_counter()
            ingested = api_json(args.base_url, "POST", "/api/v1/alerts", adapter.normalize(raw), secret=secret)
            ingest_times.append(time.perf_counter() - started)
            alert_ids.append(ingested["id"])
            source_id = raw.get("id")
            if isinstance(source_id, str) and source_id:
                source_ids_by_alert_id.setdefault(ingested["id"], set()).add(source_id)
            summary["ingest_completed_requests"] = len(alert_ids)
        unique_ids = list(dict.fromkeys(alert_ids))
        summary["ingest"] = {
            "requests": len(alert_ids),
            "unique_persisted_alerts": len(unique_ids),
            "deduplicated_requests": len(alert_ids) - len(unique_ids),
            "latency_seconds": duration_stats(ingest_times),
            "requests_per_second": round(len(alert_ids) / sum(ingest_times), 3) if sum(ingest_times) else None,
        }
        stage = "enrichment"
        enrichment_times: list[float] = []
        for alert_id in unique_ids:
            started = time.perf_counter()
            api_json(args.base_url, "POST", f"/api/v1/alerts/{alert_id}/threat-intel", {})
            enrichment_times.append(time.perf_counter() - started)
            summary["enrichment_completed_requests"] = len(enrichment_times)
        summary["enrichment"] = {"requests": len(enrichment_times), "latency_seconds": duration_stats(enrichment_times)}
        stage = "correlation"
        earliest_replay = datetime.fromisoformat(replay_alerts[0]["timestamp"])
        elapsed_lookback = math.ceil((datetime.now(timezone.utc) - earliest_replay).total_seconds() / 60) + 2
        lookback_minutes = max(lookback_minutes, elapsed_lookback)
        if lookback_minutes > 10_080:
            raise ValueError("replay timestamps exceed correlation's maximum lookback")
        summary["lookback_minutes"] = lookback_minutes
        started = time.perf_counter()
        correlated = api_json(
            args.base_url, "POST", "/api/v1/correlation/run",
            {"lookback_minutes": lookback_minutes, "window_minutes": 10, "min_alerts": 2}, timeout=300,
        )
        incidents = correlated["incidents"]
        linked_ids = {alert_id for incident in incidents for alert_id in incident["alert_ids"]}
        summary["correlation"] = {
            "seconds": round(time.perf_counter() - started, 4),
            "incidents": len(incidents),
            "created": correlated["created_count"],
            "updated": correlated["updated_count"],
            "linked_unique_alerts": len(linked_ids),
            "unlinked_unique_alerts": len(set(unique_ids) - linked_ids),
        }
        if args.triage:
            stage = "triage"
            triage_times: list[float] = []
            modes: set[str] = set()
            triage_results: list[dict[str, Any]] = []
            summary["triage"] = {
                "result_schema": "triage_decisions.v1",
                "requests": 0,
                "provider_modes": [],
                "latency_seconds": duration_stats([]),
                "results": triage_results,
            }
            for index, incident in enumerate(incidents, start=1):
                summary["last_attempted_incident_index"] = index
                source_ids = set().union(*(source_ids_by_alert_id[alert_id] for alert_id in incident["alert_ids"]))
                record: dict[str, Any] = {
                    "incident_key": incident_key(source_ids),
                    "source_alert_count": len(source_ids),
                }
                started = time.perf_counter()
                try:
                    triaged = api_json(
                        args.base_url, "POST", f"/api/v1/incidents/{incident['id']}/triage",
                        {"force": True, "persist": False}, timeout=300,
                    )
                    if triaged["incident_id"] != incident["id"]:
                        raise ValueError("triage returned a different incident ID")
                    mode = triaged["provider_mode"]
                    if mode not in {"offline", "jev"}:
                        raise ValueError("triage returned an invalid provider mode")
                    decision = triage_decision(triaged)
                except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
                    record.update({
                        "status": "failed",
                        "latency_seconds": round(time.perf_counter() - started, 4),
                        "error_type": type(exc).__name__,
                    })
                    triage_results.append(record)
                    raise RuntimeError("triage request or response failed") from exc
                elapsed = time.perf_counter() - started
                record.update({
                    "status": "completed",
                    "provider_mode": mode,
                    "latency_seconds": round(elapsed, 4),
                    **decision,
                })
                triage_results.append(record)
                triage_times.append(elapsed)
                modes.add(mode)
                summary["triage_completed_requests"] = len(triage_times)
                summary["triage"].update({
                    "requests": len(triage_times),
                    "provider_modes": sorted(modes),
                    "latency_seconds": duration_stats(triage_times),
                })
        summary["status"] = "completed"
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        summary["failure"] = {"stage": stage, "type": type(exc).__name__, "message": str(exc)}
    finally:
        if pipeline_started is not None:
            summary["pipeline_seconds"] = round(time.perf_counter() - pipeline_started, 4)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New JSON result file; no raw alerts are written")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--isolated-db", action="store_true")
    parser.add_argument("--triage", action="store_true", help="Also call the configured triage provider for every incident; Jev may receive redacted logs and incur external cost")
    result = replay(parser.parse_args())
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if result["status"] != "completed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
