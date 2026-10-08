#!/usr/bin/env python3
"""Replay the pinned 738-alert Wazuh dataset through signed ingestion and the durable worker.

Unlike batch_replay.py, nothing is correlated or triaged by the runner: every alert
queues a workflow job and the worker(s) drain the queue exactly as in production.
This measures queue drain time, per-job service time, failures and how many
investigations (the model-call driver) the automation creates. It is a workload
benchmark, not an accuracy benchmark. Worker metrics are read from the isolated
benchmark database with plain SQL so the same runner works across code revisions.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from batch_replay import SOURCE_REVISION, SOURCE_SHA256, duration_stats, fetch_source, prepare_replay
from soc_benchmark import _load_wazuh_adapter, api_json, percentile95, require_local_url

ACTIVE_STATUSES = ("PENDING", "PROCESSING", "RETRY")


def _engine():
    from sqlalchemy.ext.asyncio import create_async_engine

    url = os.getenv("DATABASE_URL")
    if not url or not url.startswith("postgresql"):
        raise ValueError("DATABASE_URL must point at the isolated PostgreSQL benchmark database")
    return create_async_engine(url)


async def _rows(engine, sql: str) -> list[Any]:
    from sqlalchemy import text

    async with engine.connect() as connection:
        return list((await connection.execute(text(sql))).all())


async def _active_jobs(engine) -> tuple[int, int]:
    rows = await _rows(engine, "SELECT status IN ('PENDING','PROCESSING','RETRY') AS active, count(*) FROM workflow_jobs GROUP BY 1")
    counts = {bool(active): int(total) for active, total in rows}
    return counts.get(True, 0), counts.get(False, 0)


def service_times(jobs: list[tuple[datetime, datetime]]) -> list[float]:
    """Per-job service time for a single worker: completion minus max(previous completion, enqueue)."""
    ordered = sorted(jobs, key=lambda job: job[1])
    times, previous = [], None
    for created, finished in ordered:
        start = created if previous is None else max(previous, created)
        times.append(max(0.0, (finished - start).total_seconds()))
        previous = finished
    return times


def decile_medians(values: list[float]) -> list[float]:
    if len(values) < 10:
        return [round(statistics.median(values), 4)] if values else []
    size = len(values) / 10
    return [round(statistics.median(values[int(i * size):int((i + 1) * size)]), 4) for i in range(10)]


async def collect(engine, *, workers: int) -> dict[str, Any]:
    statuses = {status: int(total) for status, total in await _rows(engine, "SELECT status, count(*) FROM workflow_jobs GROUP BY status ORDER BY status")}
    errors = {error: int(total) for error, total in await _rows(engine, "SELECT error, count(*) FROM workflow_jobs WHERE error IS NOT NULL GROUP BY error ORDER BY 2 DESC LIMIT 10")}
    (attempts_total, retried_jobs, first_created, last_finished), = await _rows(
        engine, "SELECT sum(attempts), count(*) FILTER (WHERE attempts > 1), min(created_at), max(updated_at) FROM workflow_jobs")
    jobs = [(created, finished) for created, finished in await _rows(
        engine, "SELECT created_at, updated_at FROM workflow_jobs WHERE status NOT IN ('PENDING','PROCESSING','RETRY')")]
    latency = [(finished - created).total_seconds() for created, finished in jobs]
    (investigations, investigated_incidents, max_per_incident), = await _rows(engine, """
        SELECT count(*), count(DISTINCT incident_id), coalesce(max(per_incident), 0)
        FROM (SELECT incident_id, count(*) OVER (PARTITION BY incident_id) AS per_incident FROM investigations) AS counted""")
    (incidents, linked_alerts, max_alerts), = await _rows(
        engine, "SELECT count(*), coalesce(sum(alert_count), 0), coalesce(max(alert_count), 0) FROM incidents")
    alerts = int((await _rows(engine, "SELECT count(*) FROM alerts"))[0][0])
    result: dict[str, Any] = {
        "jobs": {
            "total": sum(statuses.values()),
            "by_status": statuses,
            "attempts_total": int(attempts_total or 0),
            "retried_jobs": int(retried_jobs or 0),
            "errors": errors,
            "makespan_seconds": round((last_finished - first_created).total_seconds(), 3) if jobs else None,
            "enqueue_to_finish_seconds": duration_stats(latency) | {"max": round(max(latency), 4) if latency else None},
        },
        "incidents": {"total": int(incidents), "linked_alerts": int(linked_alerts), "largest_alert_count": int(max_alerts)},
        "investigations": {
            "total": int(investigations),
            "incidents_investigated": int(investigated_incidents),
            "max_per_incident": int(max_per_incident),
            "per_alert": round(investigations / alerts, 4) if alerts else None,
        },
        # With every provider live, each alert costs one understanding call and each
        # investigation one triage call plus up to two investigator calls.
        "estimated_live_model_calls": {"understanding": alerts, "triage": int(investigations), "investigator_max": 2 * int(investigations),
                                       "total_max": alerts + 3 * int(investigations)},
    }
    if workers == 1 and jobs:
        service = service_times(jobs)
        result["jobs"]["service_seconds"] = duration_stats(service) | {
            "max": round(max(service), 4),
            "median_by_completion_decile": decile_medians(service),
        }
    return result


async def drain(engine, *, timeout: float, poll: float, progress) -> float:
    started = time.perf_counter()
    while True:
        active, finished = await _active_jobs(engine)
        progress(active, finished, time.perf_counter() - started)
        if active == 0:
            return time.perf_counter() - started
        if time.perf_counter() - started > timeout:
            raise TimeoutError(f"{active} workflow jobs still active after {timeout:.0f}s")
        await asyncio.sleep(poll)


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
        "kind": "worker_workload_not_accuracy",
        "status": "failed",
        "label": args.label,
        "workers": args.workers,
        "source_revision": SOURCE_REVISION,
        "source_sha256": SOURCE_SHA256,
        "ip_redaction": "deterministic_TEST_NET",
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    stage = "preflight"
    engine = _engine()
    pipeline_started: float | None = None
    try:
        if api_json(args.base_url, "GET", "/api/v1/alerts?limit=1"):
            raise RuntimeError("benchmark database is not empty; use a fresh isolated database")
        stage = "source_download"
        source_alerts = fetch_source()
        stage = "preparation"
        replay_alerts, _, redacted_ip_count = prepare_replay(source_alerts, now=datetime.now(timezone.utc))
        summary.update({"replay_alert_count": len(replay_alerts), "redacted_ip_count": redacted_ip_count})
        adapter = _load_wazuh_adapter()
        pipeline_started = time.perf_counter()
        stage = "ingest"
        ingest_times: list[float] = []
        queued = 0
        for index, raw in enumerate(replay_alerts, start=1):
            summary["last_attempted_alert_index"] = index
            started = time.perf_counter()
            api_json(args.base_url, "POST", "/api/v1/alerts", adapter.normalize(raw), secret=secret)
            ingest_times.append(time.perf_counter() - started)
            queued += 1
        ingest_seconds = time.perf_counter() - pipeline_started
        summary["ingest"] = {
            "requests": queued,
            "seconds": round(ingest_seconds, 3),
            "latency_seconds": duration_stats(ingest_times) | {"p95": round(percentile95(ingest_times), 4)},
        }
        stage = "drain"
        last_report = [0.0]

        def progress(active: int, finished: int, elapsed: float) -> None:
            if elapsed - last_report[0] >= args.progress_seconds or active == 0:
                last_report[0] = elapsed
                print(f"[drain {elapsed:7.1f}s] finished={finished} active={active}", flush=True)

        drain_seconds = asyncio.run(_drain_and_collect(engine, args, progress, summary))
        summary["drain_after_ingest_seconds"] = round(drain_seconds, 3)
        summary["status"] = "completed"
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, TimeoutError) as exc:
        summary["failure"] = {"stage": stage, "type": type(exc).__name__, "message": str(exc)}
        try:
            summary["worker"] = asyncio.run(_collect_only(args))
        except Exception:  # best effort diagnostics on failure
            pass
    finally:
        if pipeline_started is not None:
            summary["pipeline_seconds"] = round(time.perf_counter() - pipeline_started, 3)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(summary, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")
    return summary


async def _drain_and_collect(engine, args, progress, summary) -> float:
    try:
        seconds = await drain(engine, timeout=args.timeout, poll=args.poll_seconds, progress=progress)
        summary["worker"] = await collect(engine, workers=args.workers)
        return seconds
    finally:
        await engine.dispose()


async def _collect_only(args) -> dict[str, Any]:
    engine = _engine()
    try:
        return await collect(engine, workers=args.workers)
    finally:
        await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New JSON result file; no raw alerts are written")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--isolated-db", action="store_true")
    parser.add_argument("--workers", type=int, default=1, help="Worker replicas running in the stack (service-time stats need exactly 1)")
    parser.add_argument("--label", default="", help="Free-text run label, e.g. the code revision under test")
    parser.add_argument("--timeout", type=float, default=3600, help="Maximum seconds to wait for the queue to drain")
    parser.add_argument("--poll-seconds", type=float, default=2)
    parser.add_argument("--progress-seconds", type=float, default=30)
    result = replay(parser.parse_args())
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    if result["status"] != "completed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
