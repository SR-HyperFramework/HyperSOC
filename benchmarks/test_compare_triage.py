"""Tests for pairing two structured triage workload runs."""

from __future__ import annotations

import unittest

from batch_replay import SOURCE_REVISION, SOURCE_SHA256, incident_key
from compare_triage import compare


def run(mode: str, decisions: list[tuple[str, str, str]]) -> dict:
    return {
        "kind": "full_dataset_workload_not_accuracy",
        "status": "completed",
        "source_revision": SOURCE_REVISION,
        "source_sha256": SOURCE_SHA256,
        "source_alert_count": 738,
        "replay_alert_count": 738,
        "ingest": {"unique_persisted_alerts": 738, "deduplicated_requests": 0},
        "triage_requested": True,
        "correlation": {"incidents": len(decisions)},
        "triage": {
            "result_schema": "triage_decisions.v1",
            "requests": len(decisions),
            "provider_modes": [mode],
            "latency_seconds": {"total": 0.1, "median": 0.1, "p95": 0.1},
            "results": [
                {
                    "incident_key": incident_key({source_id}),
                    "source_alert_count": 1,
                    "status": "completed",
                    "provider_mode": mode,
                    "latency_seconds": 0.1,
                    "classification": classification,
                    "severity": severity,
                    "confidence": 80,
                    "false_positive_probability": 20,
                }
                for source_id, classification, severity in decisions
            ],
        },
    }


class CompareTriageTests(unittest.TestCase):
    def test_pairs_by_stable_key_and_reports_disagreement_not_accuracy(self) -> None:
        offline = run("offline", [("one", "true_positive", "high"), ("two", "needs_investigation", "medium")])
        jev = run("jev", [("two", "false_positive", "low"), ("one", "true_positive", "high")])
        report = compare(offline, jev)
        self.assertEqual(report["paired_incidents"], 2)
        self.assertEqual(report["classification_agreement"], 0.5)
        self.assertEqual(report["severity_agreement"], 0.5)
        self.assertEqual(report["left_only_keys"], [])
        self.assertEqual(report["right_only_keys"], [])
        self.assertNotIn("accuracy", report)

    def test_rejects_different_source_or_duplicate_incident_key(self) -> None:
        offline = run("offline", [("one", "true_positive", "high")])
        jev = run("jev", [("one", "true_positive", "high")])
        jev["source_sha256"] = "different"
        with self.assertRaisesRegex(ValueError, "source"):
            compare(offline, jev)
        jev["source_sha256"] = SOURCE_SHA256
        jev["triage"]["results"].append(jev["triage"]["results"][0])
        with self.assertRaisesRegex(ValueError, "duplicate|incomplete"):
            compare(offline, jev)

    def test_reports_unmatched_incident_membership(self) -> None:
        offline = run("offline", [("one", "true_positive", "high"), ("two", "needs_investigation", "medium")])
        jev = run("jev", [("one", "true_positive", "high"), ("three", "false_positive", "low")])
        report = compare(offline, jev)
        self.assertEqual(report["paired_incidents"], 1)
        self.assertEqual(report["left_only_keys"], [incident_key({"two"})])
        self.assertEqual(report["right_only_keys"], [incident_key({"three"})])


if __name__ == "__main__":
    unittest.main()
