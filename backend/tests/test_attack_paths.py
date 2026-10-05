from datetime import timedelta

from sqlalchemy import select

from app.models.incident import Incident
from app.schemas.hub import HubInventoryBatch
from app.services.hub import IntelligenceHub
from app.services.workflow import SOCWorkflow
from tests.test_hub_workflow import NOW, detection, ingest, run


def test_access_hypotheses_follow_explicit_privileges_and_do_not_infer_access_from_activity():
    async def scenario(factory):
        async with factory() as db:
            hub = IntelligenceHub()
            for index in range(60):
                observation = detection(f"normal-{index}", category="behavior", when=NOW - timedelta(minutes=index + 1))
                observation.alert.process.guid = "same-running-process"
                await hub.record(db, observation)
            await hub.import_inventory(db, HubInventoryBatch.model_validate({"entities": [
                {"kind": "identity", "external_key": "alice", "label": "alice", "source": "directory", "observed_at": (NOW - timedelta(days=1)).isoformat()},
                {"kind": "asset", "external_key": "database-b", "label": "Database B", "source": "cmdb", "observed_at": (NOW - timedelta(days=1)).isoformat(), "attributes": {"criticality": "critical"}}],
                "relationships": [{"source_kind": "identity", "source_key": "alice", "target_kind": "asset", "target_key": "database-b", "relation": "administers",
                    "source_ref": "directory:grant-1", "observed_at": (NOW - timedelta(days=1)).isoformat()}]}))
            await ingest(db, detection())
            workflow = SOCWorkflow()
            job = await workflow.claim(db)
            await workflow.process(db, job)
            context = await hub.context(db, await db.scalar(select(Incident)))
            paths = context.analytics["attack_paths"]
            assert paths["status"] == "hypotheses_available"
            assert paths["paths"][0]["target_label"] == "Database B"
            assert paths["paths"][0]["kind"] == "hypothesis"
            assert paths["paths"][0]["steps"][0]["source_ref"] == "directory:grant-1"
            # Sixty repeated activity records collapse to representative graph edges.
            assert sum(edge.relation == "observed_on" for edge in context.graph.edges) == 1
            assert sum(edge.relation == "executes" for edge in context.graph.edges) == 2
            assert not context.graph.truncated
            assert all(step["relation"] != "observed_on" for path in paths["paths"] for step in path["steps"])
    run(scenario)
