#!/usr/bin/env python3
"""Run one deterministic pilot case through an empty offline HyperSOC stack."""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from soc_benchmark import CATALOG, load_json, prepare_packet, run_pipeline


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", default="C01")
    parser.add_argument("--base-url", default="http://backend:8000")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    secret = os.getenv("APP_SECRET_KEY")
    if not secret:
        raise SystemExit("APP_SECRET_KEY must be set")
    if args.output.exists():
        raise SystemExit(f"refusing to overwrite result: {args.output}")

    catalog = load_json(CATALOG)
    case = next((item for item in catalog["cases"] if item["id"] == args.case), None)
    if case is None:
        raise SystemExit(f"unknown benchmark case: {args.case}")
    # A replay observes its complete sequence now; do not manufacture future
    # evidence that the live correlator correctly refuses to use.
    duration = max(alert["offset_seconds"] for alert in case["alerts"])
    packet = prepare_packet(case, run_id="offline-smoke", start=datetime.now(timezone.utc) - timedelta(seconds=duration + 1))
    result = run_pipeline(packet, args.base_url, secret)
    summary = {
        "case_id": args.case,
        "status": "completed" if result.get("automation_status") == "triaged" else "failed",
        "system": result,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if summary["status"] != "completed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
