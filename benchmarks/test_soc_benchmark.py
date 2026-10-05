"""Offline contract tests for the synthetic SOC benchmark harness."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

MODULE_PATH = Path(__file__).with_name("soc_benchmark.py")
SPEC = importlib.util.spec_from_file_location("soc_benchmark", MODULE_PATH)
assert SPEC and SPEC.loader
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)


class BenchmarkCaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = benchmark.load_json(benchmark.CATALOG)

    def test_catalog_has_pilot_cases_and_valid_labels(self) -> None:
        benchmark.validate_catalog(self.catalog)
        self.assertEqual(len(self.catalog["cases"]), 11)
        self.assertEqual({case["truth"]["classification"] for case in self.catalog["cases"]}, set(benchmark.CLASSES))
        for case in self.catalog["cases"]:
            self.assertLessEqual(max(alert["offset_seconds"] for alert in case["alerts"]) - min(alert["offset_seconds"] for alert in case["alerts"]), 600)
            self.assertEqual(len({(alert["agent"]["id"], alert.get("data", {}).get("srcip")) for alert in case["alerts"]}), 1)

    def test_observed_cases_are_attributed_redacted_and_blinded(self) -> None:
        observed = [case for case in self.catalog["cases"] if case.get("origin") == "public_observed_wazuh_redacted_projection"]
        self.assertEqual(len(observed), 3)
        catalog_text = benchmark.CATALOG.read_text(encoding="utf-8")
        self.assertNotIn("45.55.159.241", catalog_text)
        self.assertNotIn("8.220.202.246", catalog_text)
        for case in observed:
            self.assertEqual(case["source_revision"], "13cc552c9de42eecee22f6e4c2fe34c80ae3f5d8")
            self.assertEqual(len(case["source_sha256"]), 64)
            self.assertEqual(len(case["source_alert_ids"]), len(case["alerts"]))
            packet = benchmark.prepare_packet(case, run_id="fixed", start=datetime.now(timezone.utc))
            self.assertNotIn("origin", packet)
            self.assertNotIn("label_basis", packet)
            self.assertNotIn("source_alert_ids", packet)

    def test_prepared_packet_blinds_labels_and_is_hash_checked(self) -> None:
        case = self.catalog["cases"][0]
        packet = benchmark.prepare_packet(case, run_id="fixed", start=datetime.now(timezone.utc))
        benchmark.validate_packet(packet)
        self.assertNotIn("truth", packet)
        self.assertNotIn("scenario", packet)
        self.assertEqual(packet["case_id"], "C01")
        self.assertEqual(len({a["id"] for a in packet["alerts"]}), len(packet["alerts"]))
        packet["alerts"][0]["rule"]["level"] = 0
        with self.assertRaisesRegex(ValueError, "hash"):
            benchmark.validate_packet(packet)

    def test_prepare_command_writes_blinded_packets_without_overwrite(self) -> None:
        import argparse
        from contextlib import redirect_stdout
        from io import StringIO

        with tempfile.TemporaryDirectory() as temporary:
            arguments = argparse.Namespace(catalog=benchmark.CATALOG, output=Path(temporary) / "packets")
            with redirect_stdout(StringIO()):
                benchmark.prepare_command(arguments)
            packets = sorted(arguments.output.glob("*.json"))
            self.assertEqual(len(packets), 11)
            for path in packets:
                packet = benchmark.load_json(path)
                benchmark.validate_packet(packet)
                self.assertNotIn("truth", path.read_text(encoding="utf-8"))
                self.assertLessEqual(max(datetime.fromisoformat(alert["timestamp"]) for alert in packet["alerts"]), datetime.now(timezone.utc))
            with self.assertRaises(FileExistsError):
                benchmark.prepare_command(arguments)

    def test_system_pipeline_contract(self) -> None:
        case = self.catalog["cases"][0]
        packet = benchmark.prepare_packet(case, run_id="fixed", start=datetime.now(timezone.utc))
        calls = []
        ids = ["00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002", "00000000-0000-0000-0000-000000000003"]

        def fake_api(base_url, method, path, payload=None, *, secret=None):
            calls.append((method, path, payload, secret))
            if path == "/api/v1/alerts?limit=1":
                return []
            if path == "/api/v1/alerts":
                return {"id": ids[len([call for call in calls if call[1] == path]) - 1]}
            if path.endswith("/threat-intel"):
                return {}
            if path == "/api/v1/correlation/run":
                return {"incidents": [{"id": "incident-1", "alert_ids": ids}]}
            if path.endswith("/triage"):
                return {"provider_mode": "offline", "result": {"classification": "true_positive", "severity": "high", "mitre": [{"technique_id": "T1110"}], "evidence": []}}
            raise AssertionError(path)

        with patch.object(benchmark, "api_json", side_effect=fake_api):
            result = benchmark.run_pipeline(packet, "http://127.0.0.1:8000", "test-secret")
        self.assertEqual(result["classification"], "true_positive")
        self.assertEqual(result["alert_ids"], ids)
        self.assertEqual(len([call for call in calls if call[1] == "/api/v1/alerts"]), 3)
        self.assertTrue(all(call[2]["raw"]["id"].startswith("fixed-") for call in calls if call[1] == "/api/v1/alerts"))
        self.assertTrue(all(call[3] == "test-secret" for call in calls if call[1] == "/api/v1/alerts"))

    def test_nonempty_db_and_remote_backend_are_rejected(self) -> None:
        packet = benchmark.prepare_packet(self.catalog["cases"][0], run_id="fixed", start=datetime.now(timezone.utc))
        with self.assertRaisesRegex(ValueError, "loopback"):
            benchmark.run_pipeline(packet, "https://example.com", "secret")
        with patch.object(benchmark, "api_json", return_value=[{"id": "existing"}]):
            with self.assertRaisesRegex(RuntimeError, "not empty"):
                benchmark.run_pipeline(packet, "http://127.0.0.1:8000", "secret")

    def test_observed_log_rotation_is_recorded_as_no_matching_incident(self) -> None:
        case = next(case for case in self.catalog["cases"] if case["id"] == "C11")
        packet = benchmark.prepare_packet(case, run_id="fixed", start=datetime.now(timezone.utc))
        ids = ["00000000-0000-0000-0000-000000000011", "00000000-0000-0000-0000-000000000012", "00000000-0000-0000-0000-000000000013"]
        ingest_count = 0

        def fake_api(_base_url, _method, path, _payload=None, *, secret=None):
            nonlocal ingest_count
            if path == "/api/v1/alerts?limit=1":
                return []
            if path == "/api/v1/alerts":
                result = {"id": ids[ingest_count]}
                ingest_count += 1
                return result
            if path.endswith("/threat-intel"):
                return {}
            if path == "/api/v1/correlation/run":
                return {"incidents": []}
            raise AssertionError(path)

        with patch.object(benchmark, "api_json", side_effect=fake_api):
            result = benchmark.run_pipeline(packet, "http://127.0.0.1:8000", "test-secret")
        self.assertEqual(result["automation_status"], "no_matching_incident")
        self.assertIsNone(result["classification"])
        self.assertEqual(result["alert_ids"], ids)

    def test_summary_counts_failed_runs_in_accuracy_denominator(self) -> None:
        truth = {"C01": {"classification": "true_positive", "severity": "high", "mitre_ids": ["T1110"]}, "C02": {"classification": "unknown", "severity": "low", "mitre_ids": []}}
        records = [
            {"case_id": "C01", "status": "completed", "elapsed_seconds": 12, "decision": {"classification": "true_positive", "severity": "high", "mitre_ids": ["T1110"]}},
            {"case_id": "C02", "status": "failed", "elapsed_seconds": 30},
        ]
        summary = benchmark.summarize_arm(records, truth)
        self.assertEqual(summary["completed"], 1)
        self.assertEqual(summary["failed"], 1)
        self.assertEqual(summary["classification_accuracy"], 0.5)
        self.assertEqual(summary["classification_macro_f1"], 0.25)

    def test_structural_pilot_result_validator_accepts_offline_triage(self) -> None:
        import subprocess
        import sys

        with tempfile.TemporaryDirectory() as temporary:
            result = Path(temporary) / "pilot.json"
            result.write_text(json.dumps({
                "case_id": "C01",
                "status": "completed",
                "system": {"automation_status": "triaged", "provider_mode": "offline"},
            }), encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, str(Path(__file__).with_name("validate_result.py")), "pilot", str(result)],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_report_does_not_claim_speedup_without_complete_pairs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            results = Path(temporary) / "results.jsonl"
            benchmark.append_jsonl(results, {"case_id": "C01", "arm": "traditional", "status": "completed", "bundle_sha256": "same", "elapsed_seconds": 20, "decision": self.catalog["cases"][0]["truth"]})
            import argparse
            from contextlib import redirect_stdout
            from io import StringIO

            output = StringIO()
            with redirect_stdout(output):
                benchmark.report_command(argparse.Namespace(catalog=benchmark.CATALOG, results=results))
            report = json.loads(output.getvalue())
            self.assertFalse(report["reportable"])
            self.assertFalse(report["pilot_pairs_complete"])
            self.assertEqual(report["paired_cases"], 0)
            self.assertNotIn("median_time_ratio", report)

    def test_report_rejects_same_analyst_and_mismatched_packet(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            results = Path(temporary) / "results.jsonl"
            truth = self.catalog["cases"][0]["truth"]
            for arm, packet_hash, analyst in (("traditional", "hash-a", "A01"), ("hypersoc", "hash-b", "A01")):
                benchmark.append_jsonl(results, {"case_id": "C01", "arm": arm, "analyst_id": analyst, "status": "completed", "bundle_sha256": packet_hash, "elapsed_seconds": 20, "decision": truth})
            import argparse
            from contextlib import redirect_stdout
            from io import StringIO

            output = StringIO()
            with redirect_stdout(output):
                benchmark.report_command(argparse.Namespace(catalog=benchmark.CATALOG, results=results))
            self.assertEqual(json.loads(output.getvalue())["paired_cases"], 0)

    def test_report_rejects_mixed_offline_and_jev_modes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            results = Path(temporary) / "results.jsonl"
            for index, mode in ((0, "offline"), (1, "jev")):
                case = self.catalog["cases"][index]
                for arm, analyst in (("traditional", "A01"), ("hypersoc", "A02")):
                    record = {"case_id": case["id"], "arm": arm, "analyst_id": analyst, "status": "completed", "bundle_sha256": f"hash-{index}", "elapsed_seconds": 20, "decision": case["truth"]}
                    if arm == "hypersoc":
                        record["system"] = {"provider_mode": mode}
                    benchmark.append_jsonl(results, record)
            import argparse

            with self.assertRaisesRegex(ValueError, "provider modes"):
                benchmark.report_command(argparse.Namespace(catalog=benchmark.CATALOG, results=results))


if __name__ == "__main__":
    unittest.main()
