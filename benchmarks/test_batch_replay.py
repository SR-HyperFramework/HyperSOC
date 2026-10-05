"""Offline tests for the pinned full-dataset workload replay."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import batch_replay as batch


def sample_alert(alert_id: str, when: datetime, *, srcip: str = "8.8.8.8") -> dict:
    return {
        "id": alert_id,
        "timestamp": when.isoformat(),
        "agent": {"id": "001", "name": "masked-host"},
        "rule": {"id": "5710", "level": 5, "description": "sshd invalid user", "groups": ["sshd", "authentication_failed"]},
        "data": {"srcip": srcip, "srcuser": "invalid-user"},
        "full_log": f"Invalid user from {srcip}",
    }


class BatchReplayTests(unittest.TestCase):
    def test_fetch_verifies_digest_and_discards_author_labels(self) -> None:
        source = json.dumps([{"input": json.dumps(sample_alert("one", datetime.now(timezone.utc))), "output": "True Positive"}]).encode()
        with patch.object(batch.urllib.request, "urlopen", return_value=io.BytesIO(source)), patch.object(batch, "SOURCE_SHA256", hashlib.sha256(source).hexdigest()):
            alerts = batch.fetch_source()
        self.assertEqual(len(alerts), 1)
        self.assertNotIn("output", alerts[0])
        with patch.object(batch.urllib.request, "urlopen", return_value=io.BytesIO(source)), patch.object(batch, "SOURCE_SHA256", "0" * 64):
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                batch.fetch_source()

    def test_prepare_preserves_event_spacing_and_redacts_nested_ip(self) -> None:
        start = datetime(2025, 3, 5, tzinfo=timezone.utc)
        alerts = [sample_alert("two", start + timedelta(minutes=10)), sample_alert("one", start)]
        alerts[0]["data"]["nested"] = {"message": "connect to 8.8.8.8"}
        now = datetime(2026, 9, 26, tzinfo=timezone.utc)
        replay, lookback, redacted_count = batch.prepare_replay(alerts, now=now)
        self.assertEqual([item["id"] for item in replay], ["one", "two"])
        self.assertEqual(datetime.fromisoformat(replay[1]["timestamp"]) - datetime.fromisoformat(replay[0]["timestamp"]), timedelta(minutes=10))
        self.assertEqual(datetime.fromisoformat(replay[-1]["timestamp"]), now - timedelta(minutes=2))
        self.assertEqual(lookback, 60)
        self.assertEqual(redacted_count, 1)
        self.assertNotIn("8.8.8.8", json.dumps(replay))
        self.assertEqual(replay[0]["data"]["srcip"], replay[1]["data"]["srcip"])

    def test_replay_measures_dedup_enrichment_correlation_and_optional_triage(self) -> None:
        start = datetime.now(timezone.utc) - timedelta(hours=1)
        alerts = [sample_alert("one", start), sample_alert("two", start + timedelta(seconds=1)), sample_alert("three", start + timedelta(seconds=2))]
        calls = []
        ids = ["00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002"]

        def fake_api(_base_url, method, path, payload=None, **kwargs):
            calls.append((method, path, payload, kwargs))
            if path == "/api/v1/alerts?limit=1":
                return []
            if path == "/api/v1/incidents?limit=1":
                return []
            if path == "/api/v1/alerts":
                return {"id": ids[len([call for call in calls if call[1] == path]) - 1]}
            if path.endswith("/threat-intel"):
                return {}
            if path == "/api/v1/correlation/run":
                return {"created_count": 1, "updated_count": 0, "incidents": [{"id": "incident-1", "alert_ids": ids[:2]}]}
            if path.endswith("/triage"):
                return {
                    "incident_id": "incident-1",
                    "provider_mode": "offline",
                    "result": {
                        "classification": "true_positive",
                        "severity": "high",
                        "confidence": 88,
                        "false_positive_probability": 12,
                        "summary": "private-raw-log-should-not-appear",
                    },
                }
            raise AssertionError(path)

        with tempfile.TemporaryDirectory() as temporary, patch.object(batch, "fetch_source", return_value=alerts), patch.object(batch, "api_json", side_effect=fake_api), patch.dict(os.environ, {"APP_SECRET_KEY": "test-secret"}):
            result_file = Path(temporary) / "batch.json"
            args = argparse.Namespace(output=result_file, base_url="http://127.0.0.1:8000", isolated_db=True, triage=True)
            result = batch.replay(args)
            self.assertEqual(json.loads(result_file.read_text(encoding="utf-8"))["status"], "completed")
        self.assertEqual(result["ingest"]["requests"], 3)
        self.assertEqual(result["ingest"]["unique_persisted_alerts"], 2)
        self.assertEqual(result["ingest"]["deduplicated_requests"], 1)
        self.assertEqual(result["enrichment"]["requests"], 2)
        self.assertEqual(result["correlation"]["incidents"], 1)
        self.assertEqual(result["triage"]["requests"], 1)
        self.assertEqual(result["triage"]["provider_modes"], ["offline"])
        self.assertEqual(
            result["triage"]["results"][0],
            {
                "incident_key": batch.incident_key({"one", "two"}),
                "source_alert_count": 2,
                "status": "completed",
                "provider_mode": "offline",
                "latency_seconds": result["triage"]["results"][0]["latency_seconds"],
                "classification": "true_positive",
                "severity": "high",
                "confidence": 88,
                "false_positive_probability": 12,
            },
        )
        self.assertNotIn("private-raw-log-should-not-appear", json.dumps(result))
        self.assertEqual(len([call for call in calls if call[1] == "/api/v1/alerts"]), 3)
        self.assertTrue(all(call[3].get("secret") == "test-secret" for call in calls if call[1] == "/api/v1/alerts"))

    def test_incident_key_is_stable_across_replays(self) -> None:
        self.assertEqual(batch.incident_key({"one", "two"}), batch.incident_key({"two", "one"}))
        self.assertNotEqual(batch.incident_key({"one", "two"}), batch.incident_key({"one"}))

    def test_failed_triage_keeps_safe_per_incident_record(self) -> None:
        start = datetime.now(timezone.utc) - timedelta(minutes=5)
        alerts = [sample_alert("one", start), sample_alert("two", start + timedelta(seconds=1))]
        ids = ["00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002"]
        ingest_count = 0

        def fake_api(_base_url, _method, path, _payload=None, **_kwargs):
            nonlocal ingest_count
            if path in {"/api/v1/alerts?limit=1", "/api/v1/incidents?limit=1"}:
                return []
            if path == "/api/v1/alerts":
                alert_id = ids[ingest_count]
                ingest_count += 1
                return {"id": alert_id}
            if path.endswith("/threat-intel"):
                return {}
            if path == "/api/v1/correlation/run":
                return {"created_count": 1, "updated_count": 0, "incidents": [{"id": "incident-1", "alert_ids": ids}]}
            if path.endswith("/triage"):
                raise RuntimeError("private-secret-should-not-appear")
            raise AssertionError(path)

        with tempfile.TemporaryDirectory() as temporary, patch.object(batch, "fetch_source", return_value=alerts), patch.object(batch, "api_json", side_effect=fake_api), patch.dict(os.environ, {"APP_SECRET_KEY": "test-secret"}):
            result_file = Path(temporary) / "failed-triage.json"
            args = argparse.Namespace(output=result_file, base_url="http://127.0.0.1:8000", isolated_db=True, triage=True)
            result = batch.replay(args)
            contents = result_file.read_text(encoding="utf-8")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failure"]["stage"], "triage")
        self.assertEqual(result["triage"]["results"][0]["incident_key"], batch.incident_key({"one", "two"}))
        self.assertEqual(result["triage"]["results"][0]["error_type"], "RuntimeError")
        self.assertNotIn("private-secret-should-not-appear", contents)

    def test_structural_workload_result_validator_checks_source_pin(self) -> None:
        import subprocess
        import sys

        payload = {
            "kind": "full_dataset_workload_not_accuracy",
            "status": "completed",
            "source_revision": batch.SOURCE_REVISION,
            "source_sha256": batch.SOURCE_SHA256,
            "source_alert_count": 738,
            "replay_alert_count": 738,
            "ingest": {"unique_persisted_alerts": 738, "deduplicated_requests": 0},
        }
        with tempfile.TemporaryDirectory() as temporary:
            result = Path(temporary) / "workload.json"
            result.write_text(json.dumps(payload), encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, str(Path(__file__).with_name("validate_result.py")), "workload", str(result)],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_structural_workload_result_validator_rejects_dedup_loss(self) -> None:
        import subprocess
        import sys

        payload = {
            "kind": "full_dataset_workload_not_accuracy",
            "status": "completed",
            "source_revision": batch.SOURCE_REVISION,
            "source_sha256": batch.SOURCE_SHA256,
            "source_alert_count": 738,
            "replay_alert_count": 738,
            "ingest": {"unique_persisted_alerts": 657, "deduplicated_requests": 81},
        }
        with tempfile.TemporaryDirectory() as temporary:
            result = Path(temporary) / "workload.json"
            result.write_text(json.dumps(payload), encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, str(Path(__file__).with_name("validate_result.py")), "workload", str(result)],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(completed.returncode, 0)

    def test_structural_workload_result_validator_requires_all_triage_decisions(self) -> None:
        import subprocess
        import sys

        decision = {
            "incident_key": batch.incident_key({"one", "two"}),
            "source_alert_count": 2,
            "status": "completed",
            "provider_mode": "offline",
            "latency_seconds": 0.01,
            "classification": "needs_investigation",
            "severity": "medium",
            "confidence": 70,
            "false_positive_probability": 30,
        }
        payload = {
            "kind": "full_dataset_workload_not_accuracy",
            "status": "completed",
            "source_revision": batch.SOURCE_REVISION,
            "source_sha256": batch.SOURCE_SHA256,
            "source_alert_count": 738,
            "replay_alert_count": 738,
            "ingest": {"unique_persisted_alerts": 738, "deduplicated_requests": 0},
            "correlation": {"incidents": 1},
            "triage_requested": True,
            "triage": {
                "result_schema": "triage_decisions.v1",
                "requests": 1,
                "provider_modes": ["offline"],
                "latency_seconds": {"total": 0.01, "median": 0.01, "p95": 0.01},
                "results": [decision],
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            result = Path(temporary) / "workload.json"
            result.write_text(json.dumps(payload), encoding="utf-8")
            command = [sys.executable, str(Path(__file__).with_name("validate_result.py")), "workload", str(result)]
            valid = subprocess.run(command, check=False, capture_output=True, text=True)
            payload["triage"]["results"] = []
            result.write_text(json.dumps(payload), encoding="utf-8")
            incomplete = subprocess.run(command, check=False, capture_output=True, text=True)
        self.assertEqual(valid.returncode, 0, valid.stderr)
        self.assertNotEqual(incomplete.returncode, 0)

    def test_unsafe_target_and_dirty_database_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {"APP_SECRET_KEY": "test-secret"}):
            args = argparse.Namespace(output=Path(temporary) / "result.json", base_url="https://example.com", isolated_db=True, triage=False)
            with self.assertRaisesRegex(ValueError, "loopback"):
                batch.replay(args)
            args.base_url = "http://127.0.0.1:8000"
            args.isolated_db = False
            with self.assertRaisesRegex(ValueError, "isolated-db"):
                batch.replay(args)
            args.isolated_db = True
            with patch.object(batch, "api_json", return_value=[{"id": "existing"}]), patch.object(batch, "fetch_source", side_effect=AssertionError("should not download")):
                result = batch.replay(args)
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["failure"]["stage"], "preflight")
            self.assertTrue(args.output.exists())
            args.output = Path(temporary) / "incident-dirty.json"
            with patch.object(batch, "api_json", side_effect=[[], [{"id": "existing-incident"}]]), patch.object(batch, "fetch_source", side_effect=AssertionError("should not download")):
                result = batch.replay(args)
            self.assertEqual(result["failure"]["stage"], "preflight")

    def test_failed_ingest_writes_partial_result_without_secret(self) -> None:
        start = datetime.now(timezone.utc) - timedelta(minutes=5)
        alerts = [sample_alert("one", start), sample_alert("two", start + timedelta(seconds=1))]
        ingest_count = 0

        def fake_api(_base_url, _method, path, _payload=None, **_kwargs):
            nonlocal ingest_count
            if path == "/api/v1/alerts?limit=1":
                return []
            if path == "/api/v1/incidents?limit=1":
                return []
            if path == "/api/v1/alerts":
                ingest_count += 1
                if ingest_count == 2:
                    raise RuntimeError("backend unavailable")
                return {"id": "00000000-0000-0000-0000-000000000001"}
            raise AssertionError(path)

        with tempfile.TemporaryDirectory() as temporary, patch.object(batch, "fetch_source", return_value=alerts), patch.object(batch, "api_json", side_effect=fake_api), patch.dict(os.environ, {"APP_SECRET_KEY": "must-not-appear"}):
            result_file = Path(temporary) / "partial.json"
            args = argparse.Namespace(output=result_file, base_url="http://127.0.0.1:8000", isolated_db=True, triage=False)
            result = batch.replay(args)
            contents = result_file.read_text(encoding="utf-8")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failure"]["stage"], "ingest")
        self.assertEqual(result["ingest_completed_requests"], 1)
        self.assertEqual(result["last_attempted_alert_index"], 2)
        self.assertNotIn("must-not-appear", contents)


if __name__ == "__main__":
    unittest.main()
