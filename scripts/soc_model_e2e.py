"""HTTP/worker acceptance for the disposable model stack on loopback port 8020."""
import argparse
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from app.workers.import_hub import signed_headers

BASE_URL = "http://127.0.0.1:8020"
TEST_SECRET = "isolated-model-stack-test-secret"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=["prepare", "finish", "all"], default="all")
    parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    result = {"source": "synthetic disposable-stack acceptance"}
    with httpx.Client(base_url=BASE_URL, timeout=30) as client:
        assert client.get("/ready").status_code == 200
        assert client.get("/api/v1/incidents").status_code == 401
        login = client.post("/api/v1/auth/login", json={"username": "smoke-admin", "password": "smoke-only-password-123"})
        assert login.status_code == 200
        auth = {"Authorization": "Bearer " + login.json()["access_token"]}

        def native(format, source, event, category=None):
            envelope = {"format": format, "source": source, "event": event}
            if category:
                envelope["category"] = category
            body = json.dumps(envelope, separators=(",", ":")).encode()
            response = client.post("/api/v1/hub/native-events", content=body, headers=signed_headers(TEST_SECRET, body))
            assert response.status_code in {200, 201}, response.text[:200]
            return response.json()

        if args.phase in {"prepare", "all"}:
            if args.state.exists():
                raise RuntimeError("Use a new state path; existing acceptance state is preserved")
            clock = datetime.now(timezone.utc)
            run_id = uuid4().hex[:10]
            host, user, target = "model-endpoint-" + run_id, "model-user-" + run_id, "model-database-" + run_id
            inventory = {"entities": [
                {"kind": "asset", "external_key": host, "label": host, "source": "synthetic-cmdb", "observed_at": (clock - timedelta(hours=1)).isoformat(), "attributes": {"owner": "Model test", "criticality": "high"}},
                {"kind": "asset", "external_key": target, "label": target, "source": "synthetic-cmdb", "observed_at": (clock - timedelta(hours=1)).isoformat(), "attributes": {"criticality": "critical"}},
                {"kind": "identity", "external_key": user, "label": user, "source": "synthetic-directory", "observed_at": (clock - timedelta(hours=1)).isoformat(), "attributes": {"privileged": True}}],
                "relationships": [{"source_kind": "identity", "source_key": user, "target_kind": "asset", "target_key": target, "relation": "administers", "source_ref": "synthetic-grant:" + run_id, "observed_at": (clock - timedelta(hours=1)).isoformat()}]}
            assert client.post("/api/v1/hub/inventory", json=inventory, headers=auth).status_code == 200
            for index in range(25):
                native("osquery", "synthetic-osquery", {"name": "processes", "hostIdentifier": host,
                    "unixTime": (clock - timedelta(days=2, minutes=index)).timestamp(), "counter": index, "action": "added",
                    "columns": {"name": "backup", "path": "/usr/bin/backup", "pid": "42", "start_time": "1000", "username": user}})
            native("ecs", "synthetic-posture", {"@timestamp": (clock - timedelta(hours=2)).isoformat(), "event": {"id": "posture:" + run_id, "kind": "state", "category": ["vulnerability"]},
                "host": {"name": host}, "vulnerability": {"id": "synthetic-posture-check", "severity": "high"}})
            event = {"@timestamp": clock.isoformat(), "event": {"id": "detection:" + run_id, "kind": "alert", "category": ["process"]},
                "host": {"id": "001", "name": host}, "user": {"name": user},
                "process": {"name": "powershell.exe", "pid": 500, "entity_id": "synthetic-process:" + run_id},
                "source": {"ip": "8.8.8.8"}, "destination": {"ip": "9.9.9.9"},
                "rule": {"name": "Synthetic HTTP acceptance detection"}, "kibana.alert.severity": "high", "threat.technique.id": ["T1059.001"]}
            received = native("ecs", "synthetic-edr", event)
            again = native("ecs", "synthetic-edr", event)
            assert received["events"] == again["events"]
            alert_id = received["events"][0]["alert_id"]
            jobs = client.get("/api/v1/workflows?limit=200", headers=auth).json()
            job = next(item for item in jobs if item["alert_id"] == alert_id)
            assert sum(item["alert_id"] == alert_id for item in jobs) == 1
            state = {"workflow_id": job["id"], "alert_id": alert_id, "host": host, "target": target}
            if args.phase == "prepare":
                assert job["status"] == "PENDING", "Pause this test stack's worker before prepare"
            args.state.parent.mkdir(parents=True, exist_ok=True)
            args.state.write_text(json.dumps(state, indent=2), encoding="utf-8")
            result.update(state, queued_status=job["status"])
        else:
            state = json.loads(args.state.read_text(encoding="utf-8"))

        if args.phase in {"finish", "all"}:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                job = client.get("/api/v1/workflows/" + state["workflow_id"], headers=auth).json()
                if job["status"] in {"AWAITING_REVIEW", "FAILED"}:
                    break
                time.sleep(0.5)
            assert job["status"] == "AWAITING_REVIEW", job.get("error")
            context = job["output"]["internal_context"]
            assert context["analytics"]["sample_count"] == 25
            assert context["analytics"]["attack_paths"]["paths"][0]["target_label"] == state["target"]
            assert any(node["source"] == "synthetic-cmdb" for node in context["assets"])
            incident_id, report_id = next(iter(job["output"]["investigations"].items()))
            report = client.get("/api/v1/investigations/" + report_id, headers=auth).json()
            assert any(item["source"] == "synthetic-edr_normalized_alert" for item in report["evidence"])
            assert any(item["source"] == "hub_attack_path_hypothesis" for item in report["evidence"])
            review = client.post("/api/v1/investigations/" + report_id + "/review", headers=auth,
                json={"reviewed_by": "forged-name", "classification": "true_positive", "notes": "Synthetic acceptance case, reviewed to exercise the response flow"})
            assert review.status_code == 200 and review.json()["reviewed_by"] == "smoke-admin"
            action = client.post(f"/api/v1/incidents/{incident_id}/actions", headers=auth,
                json={"type": "BLOCK_IP", "target": "8.8.8.8", "reason": "Synthetic offline response test", "requested_by": "forged-name"})
            assert action.status_code == 201 and action.json()["requested_by"] == "smoke-admin"
            action_id = action.json()["id"]
            assert client.post(f"/api/v1/actions/{action_id}/approve", headers=auth, json={"approved_by": "forged-name"}).status_code == 200
            executed = client.post(f"/api/v1/actions/{action_id}/execute", headers=auth)
            assert executed.status_code == 200
            assert executed.json()["execution_result"]["metadata"]["execution_mode"] == "offline"
            incident = client.get("/api/v1/incidents/" + incident_id, headers=auth).json()
            assert incident["status"] == "INVESTIGATING"
            assert client.post(f"/api/v1/actions/{action_id}/verify", headers=auth,
                json={"evidence_ids": [str(uuid4())], "notes": "Simulation must not count as containment"}).status_code == 409
            assert client.get("/api/v1/workflows/" + state["workflow_id"], headers=auth).json()["status"] == "REVIEWED"
            result.update(state, incident_id=incident_id, report_id=report_id, action_id=action_id,
                worker_status="REVIEWED", incident_status=incident["status"], containment_verified=False,
                checks=["signed_native_ingest", "idempotency", "worker_after_restart", "prior_behavior_model", "inventory_access_path", "cited_report", "account_review", "approved_simulation"])
    output = args.state.with_suffix(".result.json")
    output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
