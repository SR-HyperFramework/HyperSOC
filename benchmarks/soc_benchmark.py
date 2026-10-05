#!/usr/bin/env python3
"""Paired, blinded pilot benchmark for manual SOC review and HyperSOC review.

Only packet files are shown to analysts. The case catalog contains provisional
labels and must be kept with the benchmark coordinator.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib.util
import json
import os
import statistics
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
CATALOG = Path(__file__).with_name("cases.json")
CLASSES = ("true_positive", "false_positive", "needs_investigation", "unknown")
SEVERITIES = ("low", "medium", "high", "critical")


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def append_jsonl(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def validate_catalog(catalog: dict[str, Any]) -> None:
    seen_cases: set[str] = set()
    for case in catalog["cases"]:
        case_id = case["id"]
        if case_id in seen_cases:
            raise ValueError(f"duplicate case id: {case_id}")
        seen_cases.add(case_id)
        if case["truth"]["classification"] not in CLASSES or case["truth"]["severity"] not in SEVERITIES:
            raise ValueError(f"invalid truth label: {case_id}")
        keys = [alert["key"] for alert in case["alerts"]]
        if len(keys) < 2 or len(keys) != len(set(keys)):
            raise ValueError(f"case needs at least two distinct alerts: {case_id}")


def prepare_packet(case: dict[str, Any], *, run_id: str, start: datetime) -> dict[str, Any]:
    alerts = []
    for alert in case["alerts"]:
        raw = {key: value for key, value in alert.items() if key not in {"key", "offset_seconds"}}
        raw["id"] = f"{run_id}-{alert['key']}"
        raw["timestamp"] = (start + timedelta(seconds=alert["offset_seconds"])).isoformat()
        alerts.append(raw)
    return {
        "case_id": case["id"],
        "dataset": "hypersoc-mixed-pilot-v2",
        "replay_note": "Top-level timestamps are shifted for replay; original dates may remain in full_log.",
        "alerts": alerts,
        "bundle_sha256": hashlib.sha256(canonical_bytes(alerts)).hexdigest(),
    }


def validate_packet(packet: dict[str, Any]) -> None:
    if not isinstance(packet.get("alerts"), list) or len(packet["alerts"]) < 2:
        raise ValueError("packet needs at least two alerts")
    actual_hash = hashlib.sha256(canonical_bytes(packet["alerts"])).hexdigest()
    if actual_hash != packet.get("bundle_sha256"):
        raise ValueError("packet bundle hash does not match its alerts")


def prepare_command(args: argparse.Namespace) -> None:
    catalog = load_json(args.catalog)
    validate_catalog(catalog)
    args.output.mkdir(parents=True, exist_ok=True)
    existing = [args.output / f"{case['id']}.json" for case in catalog["cases"] if (args.output / f"{case['id']}.json").exists()]
    if existing:
        raise FileExistsError(f"refusing to overwrite packet: {existing[0]}")
    run_id = uuid.uuid4().hex[:12]
    maximum_offset = max(alert["offset_seconds"] for case in catalog["cases"] for alert in case["alerts"])
    start = datetime.now(timezone.utc) - timedelta(seconds=maximum_offset + 1)
    for case in catalog["cases"]:
        packet = prepare_packet(case, run_id=run_id, start=start)
        path = args.output / f"{case['id']}.json"
        path.write_text(json.dumps(packet, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Prepared {len(catalog['cases'])} blinded packets in {args.output}")
    print("Run each system case on a freshly reset, isolated benchmark database within the 60-minute correlation lookback.")


def _load_wazuh_adapter():
    adapter_path = ROOT / "integrations" / "wazuh" / "custom-ai-soc.py"
    spec = importlib.util.spec_from_file_location("benchmark_wazuh_adapter", adapter_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load Wazuh adapter")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def api_json(base_url: str, method: str, path: str, payload: Any = None, *, secret: str | None = None, timeout: float = 30) -> Any:
    body = None if payload is None else canonical_bytes(payload)
    headers = {"Content-Type": "application/json"}
    if secret is not None:
        stamp = str(time.time())
        headers["X-SOC-Timestamp"] = stamp
        headers["X-SOC-Signature"] = hmac.new(secret.encode(), stamp.encode() + b"." + (body or b""), hashlib.sha256).hexdigest()
    request = urllib.request.Request(base_url.rstrip("/") + path, data=body, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def require_local_url(base_url: str) -> None:
    parsed = urlsplit(base_url)
    if parsed.scheme != "http" or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("benchmark runner accepts only a loopback HTTP backend")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("base URL must not include an API path, query, or fragment")


def run_pipeline(packet: dict[str, Any], base_url: str, secret: str) -> dict[str, Any]:
    validate_packet(packet)
    require_local_url(base_url)
    existing = api_json(base_url, "GET", "/api/v1/alerts?limit=1")
    if existing:
        raise RuntimeError("benchmark database is not empty; reset its isolated DB before each case")

    adapter = _load_wazuh_adapter()
    stage_seconds: dict[str, float] = {}
    alert_ids: list[str] = []
    started = time.perf_counter()
    for raw in packet["alerts"]:
        t = time.perf_counter()
        ingested = api_json(base_url, "POST", "/api/v1/alerts", adapter.normalize(raw), secret=secret)
        stage_seconds["ingest"] = stage_seconds.get("ingest", 0.0) + time.perf_counter() - t
        alert_ids.append(ingested["id"])

    for alert_id in alert_ids:
        t = time.perf_counter()
        api_json(base_url, "POST", f"/api/v1/alerts/{alert_id}/threat-intel", {})
        stage_seconds["enrichment"] = stage_seconds.get("enrichment", 0.0) + time.perf_counter() - t

    t = time.perf_counter()
    correlated = api_json(base_url, "POST", "/api/v1/correlation/run", {"lookback_minutes": 60, "window_minutes": 10, "min_alerts": 2})
    stage_seconds["correlation"] = time.perf_counter() - t
    matching = [incident for incident in correlated["incidents"] if set(incident["alert_ids"]) == set(alert_ids)]
    if not matching:
        return {
            "provider_mode": None,
            "automation_status": "no_matching_incident",
            "correlation_incident_count": len(correlated["incidents"]),
            "alert_ids": alert_ids,
            "classification": None,
            "severity": None,
            "mitre_ids": [],
            "evidence": [],
            "recommended_actions": [],
            "pipeline_seconds": round(time.perf_counter() - started, 4),
            "stage_seconds": {key: round(value, 4) for key, value in stage_seconds.items()},
        }
    if len(matching) > 1:
        raise RuntimeError("correlation returned multiple exact-match incidents")
    incident = matching[0]

    t = time.perf_counter()
    triaged = api_json(base_url, "POST", f"/api/v1/incidents/{incident['id']}/triage", {"force": True, "persist": False})
    stage_seconds["triage"] = time.perf_counter() - t
    result = triaged["result"]
    return {
        "provider_mode": triaged["provider_mode"],
        "automation_status": "triaged",
        "incident_id": incident["id"],
        "alert_ids": alert_ids,
        "classification": result["classification"],
        "severity": result["severity"],
        "mitre_ids": [item["technique_id"] for item in result.get("mitre", [])],
        "evidence": result.get("evidence", []),
        "recommended_actions": result.get("recommended_actions", []),
        "pipeline_seconds": round(time.perf_counter() - started, 4),
        "stage_seconds": {key: round(value, 4) for key, value in stage_seconds.items()},
    }


def prompt_decision() -> dict[str, Any]:
    print("\nRecord your final analyst decision. Use comma-separated MITRE IDs; leave empty if none.")
    classification = input(f"Classification {CLASSES}: ").strip()
    severity = input(f"Severity {SEVERITIES}: ").strip()
    mitre_ids = [item.strip().upper() for item in input("MITRE IDs: ").split(",") if item.strip()]
    evidence = input("Supporting alert IDs / evidence (required): ").strip()
    response = input("Response recommendation or 'not applicable': ").strip()
    if classification not in CLASSES or severity not in SEVERITIES or not evidence or not response:
        raise ValueError("invalid or incomplete analyst decision; run not recorded")
    return {"classification": classification, "severity": severity, "mitre_ids": mitre_ids, "evidence": evidence, "response": response}


def review_command(args: argparse.Namespace) -> None:
    packet = load_json(args.packet)
    validate_packet(packet)
    if not args.analyst.strip():
        raise ValueError("an anonymized analyst ID is required")
    if args.arm == "hypersoc":
        require_local_url(args.base_url)
        if not args.isolated_db:
            raise ValueError("--isolated-db is required to confirm a disposable benchmark stack")
        secret = os.getenv("APP_SECRET_KEY")
        if not secret:
            raise ValueError("APP_SECRET_KEY must be set in the environment")
    print(f"Case: {packet['case_id']} | Analyst: {args.analyst} | Arm: {args.arm}")
    print("Press Enter when ready. The timer starts immediately after Enter.")
    input()
    started_at = datetime.now(timezone.utc)
    started = time.perf_counter()
    record: dict[str, Any] = {
        "case_id": packet["case_id"], "bundle_sha256": packet["bundle_sha256"],
        "analyst_id": args.analyst, "arm": args.arm,
        "started_at": started_at.isoformat(), "status": "failed",
    }
    try:
        print(packet.get("replay_note", ""))
        if args.arm == "traditional":
            print(json.dumps(packet["alerts"], ensure_ascii=False, indent=2))
            record["decision"] = prompt_decision()
        else:
            print(json.dumps(packet["alerts"], ensure_ascii=False, indent=2))
            system = run_pipeline(packet, args.base_url, secret)
            record["system"] = system
            print("\nHyperSOC output (review/correct before submitting):")
            print(json.dumps(system, ensure_ascii=False, indent=2))
            record["decision"] = prompt_decision()
        record["status"] = "completed"
    except (OSError, urllib.error.HTTPError, urllib.error.URLError, ValueError, RuntimeError, KeyError) as exc:
        record["error"] = f"{type(exc).__name__}: {exc}"
        print(f"Run failed: {record['error']}", file=sys.stderr)
    finally:
        record["elapsed_seconds"] = round(time.perf_counter() - started, 4)
        record["finished_at"] = datetime.now(timezone.utc).isoformat()
        append_jsonl(args.output, record)
        print(f"Recorded {record['status']} run in {args.output}")


def percentile95(values: list[float]) -> float:
    ordered = sorted(values)
    return ordered[max(0, (95 * len(ordered) + 99) // 100 - 1)]


def micro_f1(pairs: list[tuple[set[str], set[str]]]) -> float:
    tp = sum(len(expected & actual) for expected, actual in pairs)
    fp = sum(len(actual - expected) for expected, actual in pairs)
    fn = sum(len(expected - actual) for expected, actual in pairs)
    return 1.0 if tp + fp + fn == 0 else 2 * tp / (2 * tp + fp + fn)


def macro_classification_f1(decisions: list[tuple[dict[str, Any], dict[str, Any]]]) -> float:
    scores = []
    for label in CLASSES:
        tp = sum(t["classification"] == label and d["classification"] == label for t, d in decisions)
        fp = sum(t["classification"] != label and d["classification"] == label for t, d in decisions)
        fn = sum(t["classification"] == label and d["classification"] != label for t, d in decisions)
        scores.append(0.0 if tp + fp + fn == 0 else 2 * tp / (2 * tp + fp + fn))
    return statistics.mean(scores)


def summarize_arm(records: list[dict[str, Any]], truth: dict[str, dict[str, Any]]) -> dict[str, Any]:
    completed = [record for record in records if record.get("status") == "completed"]
    durations = [float(record["elapsed_seconds"]) for record in completed]
    decisions = [
        (truth[record["case_id"]], record.get("decision", {"classification": None, "severity": None, "mitre_ids": []}))
        for record in records
    ]
    critical = [(t, d) for t, d in decisions if t["severity"] == "critical"]
    return {
        "completed": len(completed), "failed": len(records) - len(completed),
        "median_seconds": round(statistics.median(durations), 3) if durations else None,
        "p95_seconds": round(percentile95(durations), 3) if durations else None,
        "classification_accuracy": round(sum(t["classification"] == d["classification"] for t, d in decisions) / len(records), 3) if records else None,
        "classification_macro_f1": round(macro_classification_f1(decisions), 3) if decisions else None,
        "severity_accuracy": round(sum(t["severity"] == d["severity"] for t, d in decisions) / len(records), 3) if records else None,
        "critical_recall": round(sum(d["severity"] == "critical" for _, d in critical) / len(critical), 3) if critical else None,
        "mitre_micro_f1": round(micro_f1([(set(t["mitre_ids"]), set(d["mitre_ids"])) for t, d in decisions]), 3) if decisions else None,
        "automation_coverage": round(sum(record.get("system", {}).get("automation_status") == "triaged" for record in completed) / len(records), 3) if records and any(record.get("arm") == "hypersoc" for record in records) else None,
    }


def report_command(args: argparse.Namespace) -> None:
    catalog = load_json(args.catalog)
    validate_catalog(catalog)
    truth = {case["id"]: case["truth"] for case in catalog["cases"]}
    records = read_jsonl(args.results)
    pairs: dict[str, dict[str, dict[str, Any]]] = {}
    for record in records:
        if record["case_id"] not in truth or record["arm"] not in {"traditional", "hypersoc"}:
            raise ValueError("results contain an unknown case or arm")
        arm_records = pairs.setdefault(record["case_id"], {})
        if record["arm"] in arm_records:
            raise ValueError(f"duplicate case/arm record: {record['case_id']} {record['arm']}")
        arm_records[record["arm"]] = record
    paired = [
        case_id for case_id, arms in pairs.items()
        if set(arms) == {"traditional", "hypersoc"}
        and arms["traditional"]["bundle_sha256"] == arms["hypersoc"]["bundle_sha256"]
        and arms["traditional"].get("analyst_id") != arms["hypersoc"].get("analyst_id")
    ]
    provider_modes = {
        pairs[case_id]["hypersoc"].get("system", {}).get("provider_mode")
        for case_id in paired
        if pairs[case_id]["hypersoc"].get("status") == "completed"
        and pairs[case_id]["hypersoc"].get("system", {}).get("automation_status") != "no_matching_incident"
    }
    if None in provider_modes or "" in provider_modes:
        raise ValueError("completed HyperSOC runs must record their provider mode")
    if len(provider_modes) > 1:
        raise ValueError("do not mix HyperSOC provider modes in one benchmark report")
    report: dict[str, Any] = {"dataset": catalog["dataset"], "total_cases": len(truth), "paired_cases": len(paired), "reportable": False}
    report["hypersoc_provider_mode"] = next(iter(provider_modes)) if provider_modes else None
    report["traditional"] = summarize_arm([pairs[key]["traditional"] for key in paired], truth)
    report["hypersoc"] = summarize_arm([pairs[key]["hypersoc"] for key in paired], truth)
    report["missing_or_unpaired_cases"] = sorted(set(truth) - set(paired))
    if len(paired) == len(truth) and all(report[arm]["failed"] == 0 for arm in ("traditional", "hypersoc")):
        report["pilot_pairs_complete"] = True
        baseline = report["traditional"]["median_seconds"]
        system = report["hypersoc"]["median_seconds"]
        report["median_time_ratio"] = round(baseline / system, 3) if baseline and system else None
    else:
        report["pilot_pairs_complete"] = False
    report["note"] = "Synthetic pilot only; provisional labels, tiny sample, no confidence interval. Not a CV/production speedup claim or the 100-point study score."
    print(json.dumps(report, ensure_ascii=False, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare", help="Create blinded packet files with fresh timestamps")
    prepare.add_argument("--catalog", type=Path, default=CATALOG)
    prepare.add_argument("--output", type=Path, required=True)
    prepare.set_defaults(func=prepare_command)
    review = commands.add_parser("review", help="Time one analyst review and append a result")
    review.add_argument("--arm", choices=("traditional", "hypersoc"), required=True)
    review.add_argument("--packet", type=Path, required=True)
    review.add_argument("--analyst", required=True)
    review.add_argument("--output", type=Path, required=True)
    review.add_argument("--base-url", default="http://127.0.0.1:8000")
    review.add_argument("--isolated-db", action="store_true")
    review.set_defaults(func=review_command)
    report = commands.add_parser("report", help="Summarize only matching-input paired runs")
    report.add_argument("--catalog", type=Path, default=CATALOG)
    report.add_argument("--results", type=Path, required=True)
    report.set_defaults(func=report_command)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
