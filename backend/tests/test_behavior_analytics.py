from datetime import timedelta

from sqlalchemy import select

from app.models.incident import Incident
from app.models.behavior import BehaviorModel
from app.services.behavior import BehaviorAnalytics, CategoricalBehaviorModel
from app.services.hub import IntelligenceHub
from tests.test_hub_workflow import NOW, detection, ingest, run


def test_learned_likelihood_distinguishes_known_and_novel_processes():
    baseline = [detection(str(i), when=NOW - timedelta(days=2)).alert for i in range(30)]
    parameters = CategoricalBehaviorModel.train(baseline)
    normal = CategoricalBehaviorModel.score(baseline[0], parameters)
    unusual = baseline[0].model_copy(deep=True)
    unusual.process.name = unusual.process.image = "unknown-loader.exe"
    unusual.network.dst_ip = "9.9.9.9"
    anomalous = CategoricalBehaviorModel.score(unusual, parameters)
    assert anomalous["anomaly_score"] > normal["anomaly_score"] + 50
    assert any(item["unseen"] for item in anomalous["contributors"])


def test_hub_model_uses_only_prior_behavior_and_predicts_observed_transitions(monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "behavior_auto_train", False)
    async def scenario(factory):
        hub = IntelligenceHub()
        analytics = BehaviorAnalytics()
        async with factory() as db:
            for index in range(25):
                await hub.record(db, detection(f"normal-{index}", category="behavior", when=NOW - timedelta(days=2, minutes=index)))
            a = detection("old-attack-a", when=NOW - timedelta(days=2, minutes=3))
            b = detection("old-attack-b", when=NOW - timedelta(days=2, minutes=2))
            b.alert.detection.mitre_ids = ["T1053"]
            await hub.record(db, a)
            await hub.record(db, b)
            model = await analytics.train(db, host="server-a", since=NOW - timedelta(days=3), until=NOW - timedelta(days=1))
            await db.commit()
            await ingest(db, detection())
            from app.services.workflow import SOCWorkflow
            workflow = SOCWorkflow()
            job = await workflow.claim(db)
            await workflow.process(db, job)
            incident = await db.scalar(select(Incident))
            result = await analytics.analyze(db, incident)
            assert result["status"] == "analyzed" and result["sample_count"] == 25
            assert result["predictions"][0]["predicted_technique"] == "T1053"
            assert result["predictions"][0]["kind"] == "hypothesis"
            assert result["anomalies"][0]["evidence_id"]
            # A model trained through the current incident cannot evaluate that incident.
            model.trained_until = NOW + timedelta(hours=1)
            await db.commit()
            assert (await analytics.analyze(db, incident))["status"] == "insufficient_baseline"
    run(scenario)


def test_automation_trains_prior_behavior_and_reuses_unchanged_baseline():
    async def scenario(factory):
        hub, analytics = IntelligenceHub(), BehaviorAnalytics()
        async with factory() as db:
            for index in range(25):
                await hub.record(db, detection(f"baseline-{index}", category="behavior", when=NOW - timedelta(days=2, minutes=index)))
            # Future telemetry must neither train nor contaminate the baseline.
            await hub.record(db, detection("future", category="behavior", when=NOW + timedelta(days=1)))
            await ingest(db, detection())
            from app.services.workflow import SOCWorkflow
            workflow = SOCWorkflow()
            job = await workflow.claim(db)
            await workflow.process(db, job)
            assert job.output["internal_context"]["analytics"]["sample_count"] == 25
            model = await db.scalar(select(BehaviorModel))
            from app.services.hub import utc
            assert utc(model.trained_until) < NOW
            again = await analytics.ensure_baseline(db, host="SERVER-A", before=NOW + timedelta(minutes=10))
            assert again.id == model.id
            # A later detection is new transition-training evidence, so refresh once.
            refreshed = await analytics.ensure_baseline(db, host="SERVER-A", before=NOW + timedelta(hours=2))
            reused = await analytics.ensure_baseline(db, host="SERVER-A", before=NOW + timedelta(hours=4))
            assert refreshed.id != model.id and reused.id == refreshed.id
            await db.commit()
            from sqlalchemy import func
            assert await db.scalar(select(func.count()).select_from(BehaviorModel)) == 2
    run(scenario)
