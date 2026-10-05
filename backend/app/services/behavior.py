"""Learn behavior likelihood and technique transitions from earlier Hub records.

This is a categorical density estimator with Laplace smoothing, not an LLM or
a hardcoded suspicious-token rule. Predictions are hypotheses with training
provenance. Only behavior records train the normal-activity density; earlier
detections train observed technique transitions separately.
"""
from __future__ import annotations

import hashlib
import json
import math
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from statistics import mean, pstdev
from uuid import uuid4

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.behavior import BehaviorModel
from app.core.config import settings
from app.models.hub import HubEvidence
from app.models.incident import Incident
from app.schemas.normalized_alert import NormalizedAlert
from app.services.hub import utc


def features(alert: NormalizedAlert) -> dict[str, str]:
    values = {
        "process": alert.process.image or alert.process.name,
        "identity": alert.identity.username,
        "remote_ip": alert.network.dst_ip,
        "domain": alert.network.domain,
        "auth_outcome": alert.identity.auth_outcome,
        "event_family": alert.detection.event_family,
        "hour_bucket": str(utc(alert.timestamp).hour // 4),
    }
    return {name: str(value).casefold() for name, value in values.items() if value is not None}


class CategoricalBehaviorModel:
    algorithm = "categorical-density-v1"

    @staticmethod
    def likelihood(values: dict, parameters: dict) -> tuple[float, list[dict]]:
        surprise, contributions = 0.0, []
        for name, value in values.items():
            counts = parameters["counts"].get(name)
            if not counts:
                continue
            probability = (counts.get(value, 0) + 1) / (sum(counts.values()) + len(counts) + 1)
            contribution = -math.log(probability)
            surprise += contribution
            contributions.append({"feature": name, "value": value, "probability": round(probability, 6), "unseen": value not in counts})
        return surprise, sorted(contributions, key=lambda item: item["probability"])

    @classmethod
    def train(cls, observations: list[NormalizedAlert]) -> dict:
        if len(observations) < 20:
            raise ValueError("At least 20 behavior observations are required to train a baseline")
        counts = defaultdict(Counter)
        vectors = [features(alert) for alert in observations]
        for vector in vectors:
            for name, value in vector.items():
                counts[name][value] += 1
        parameters = {"counts": {name: dict(values) for name, values in counts.items()}}
        scores = [cls.likelihood(vector, parameters)[0] for vector in vectors]
        parameters.update({"mean_surprise": mean(scores), "std_surprise": pstdev(scores), "sample_count": len(observations)})
        return parameters

    @classmethod
    def score(cls, alert: NormalizedAlert, parameters: dict) -> dict:
        surprise, contributions = cls.likelihood(features(alert), parameters)
        # A unit floor prevents constant baseline data from producing infinite scores.
        z = (surprise - parameters["mean_surprise"]) / max(1.0, parameters["std_surprise"])
        score = round(100 / (1 + math.exp(-max(-30, min(30, z - 2)))), 1)
        return {"anomaly_score": score, "surprise": round(surprise, 4), "z_score": round(z, 4), "contributors": contributions[:5]}


class BehaviorAnalytics:
    async def ensure_baseline(self, db: AsyncSession, *, host: str | None, before: datetime) -> BehaviorModel | None:
        """Refresh from prior telemetry during automation, with one writer per host.

        The cutoff is earlier than the alert, even when processing historical data.
        Analyst/LLM context queries remain read-only.
        """
        if not settings.behavior_auto_train or not host:
            return None
        host = host.casefold()
        cutoff = utc(before) - timedelta(microseconds=1)
        since = cutoff - timedelta(days=settings.behavior_training_days)
        if db.bind.dialect.name == "postgresql":
            await db.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"), {"key": "behavior:" + host})
        model = await db.scalar(select(BehaviorModel).where(
            BehaviorModel.host_key == host, BehaviorModel.trained_until <= cutoff,
        ).order_by(BehaviorModel.trained_until.desc()).limit(1))
        if model and cutoff - utc(model.trained_until) < timedelta(seconds=settings.behavior_refresh_seconds):
            return model
        count = await db.scalar(select(func.count()).select_from(HubEvidence).where(
            HubEvidence.host_key == host, HubEvidence.category == "behavior",
            HubEvidence.timestamp >= since, HubEvidence.timestamp <= cutoff,
        ))
        if count < 20:
            return model
        latest = await db.scalar(select(func.max(HubEvidence.timestamp)).where(
            HubEvidence.host_key == host, HubEvidence.category.in_(["behavior", "detection"]),
            HubEvidence.timestamp >= since, HubEvidence.timestamp <= cutoff,
        ))
        if model and latest and utc(latest) <= utc(model.trained_until):
            return model
        return await self.train(db, host=host, since=since, until=cutoff)

    async def train(self, db: AsyncSession, *, host: str, since: datetime, until: datetime, limit: int = 5000) -> BehaviorModel:
        if until <= since or until - since > timedelta(days=90):
            raise ValueError("Training window must be positive and no greater than 90 days")
        records = list((await db.scalars(select(HubEvidence).where(
            HubEvidence.host_key == host.casefold(), HubEvidence.category == "behavior",
            HubEvidence.timestamp >= since, HubEvidence.timestamp <= until,
        ).order_by(HubEvidence.timestamp.desc(), HubEvidence.id).limit(limit))).all())
        records.sort(key=lambda record: (utc(record.timestamp), record.id))
        observations = [NormalizedAlert.model_validate(row.normalized) for row in records]
        parameters = CategoricalBehaviorModel.train(observations)
        detections = list((await db.scalars(select(HubEvidence).where(
            HubEvidence.host_key == host.casefold(), HubEvidence.category == "detection",
            HubEvidence.timestamp >= since, HubEvidence.timestamp <= until,
        ).order_by(HubEvidence.timestamp.desc(), HubEvidence.id).limit(limit))).all())
        detections.sort(key=lambda record: (utc(record.timestamp), record.id))
        transitions = defaultdict(Counter)
        for first, second in zip(detections, detections[1:]):
            if utc(second.timestamp) - utc(first.timestamp) > timedelta(hours=1):
                continue
            for a in first.normalized.get("detection", {}).get("mitre_ids", []):
                for b in second.normalized.get("detection", {}).get("mitre_ids", []):
                    if a != b:
                        transitions[a][b] += 1
        parameters["technique_transitions"] = {a: dict(b) for a, b in transitions.items()}
        parameters["transition_sample_count"] = len(detections)
        identifiers = [str(record.id) for record in [*records, *detections]]
        row = BehaviorModel(
            id=uuid4(), algorithm=CategoricalBehaviorModel.algorithm, host_key=host.casefold(),
            sample_count=len(records), trained_since=since, trained_until=until,
            corpus_digest=hashlib.sha256(json.dumps(identifiers).encode()).hexdigest(), parameters=parameters,
        )
        db.add(row)
        await db.flush()
        return row

    async def analyze(self, db: AsyncSession, incident: Incident) -> dict:
        model = await db.scalar(select(BehaviorModel).where(
            BehaviorModel.host_key == (incident.primary_host or "").casefold(),
            BehaviorModel.trained_until < incident.first_seen,
        ).order_by(BehaviorModel.trained_until.desc()).limit(1))
        if model is None:
            return {"status": "insufficient_baseline", "gaps": ["No behavior model trained before this incident is available."], "predictions": [], "anomalies": []}
        evidence = list((await db.scalars(select(HubEvidence).where(
            HubEvidence.host_key == model.host_key, HubEvidence.timestamp >= incident.first_seen,
            HubEvidence.timestamp <= incident.last_seen,
        ).order_by(HubEvidence.timestamp).limit(100))).all())
        anomalies = [{"evidence_id": str(record.id), "source": record.source, **CategoricalBehaviorModel.score(NormalizedAlert.model_validate(record.normalized), model.parameters)} for record in evidence]
        anomalies.sort(key=lambda item: -item["anomaly_score"])
        transitions = model.parameters.get("technique_transitions", {})
        predictions = []
        for technique in incident.mitre_ids or []:
            following = transitions.get(technique, {})
            total = sum(following.values())
            for predicted, count in sorted(following.items(), key=lambda item: -item[1])[:3]:
                if predicted not in (incident.mitre_ids or []):
                    predictions.append({"from_technique": technique, "predicted_technique": predicted,
                        "probability": round(count / total, 4), "observed_transitions": count, "kind": "hypothesis"})
        return {
            "status": "analyzed", "model_id": str(model.id), "algorithm": model.algorithm,
            "sample_count": model.sample_count, "trained_since": utc(model.trained_since).isoformat(),
            "trained_until": utc(model.trained_until).isoformat(), "corpus_digest": model.corpus_digest,
            "anomalies": anomalies[:10], "predictions": predictions[:10],
            "gaps": [] if predictions else ["No learned technique transition extends the current incident."],
        }
