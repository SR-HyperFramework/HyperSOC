from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from app.schemas.threat_intel import ThreatIntelProviderResult

_VERDICT_PRIORITY = {"unknown": 0, "benign": 1, "suspicious": 2, "malicious": 3}


def _provider_result(value: ThreatIntelProviderResult | Mapping[str, Any]) -> ThreatIntelProviderResult:
    if isinstance(value, ThreatIntelProviderResult):
        return value
    return ThreatIntelProviderResult.model_validate(value)


def aggregate_provider_results(
    providers: Mapping[str, ThreatIntelProviderResult | Mapping[str, Any]],
) -> tuple[int, str]:
    results = [_provider_result(value) for value in providers.values()]
    if not results:
        return 0, "unknown"

    risk_score = max(result.risk_score for result in results)
    signal_count = sum(1 for result in results if not result.error and result.verdict in {"suspicious", "malicious"})
    if signal_count > 1:
        risk_score = min(100, risk_score + min(10, (signal_count - 1) * 5))

    if risk_score >= 70 or any(result.verdict == "malicious" and result.risk_score >= 70 for result in results):
        return risk_score, "malicious"
    if risk_score >= 40 or any(result.verdict == "suspicious" and result.risk_score >= 40 for result in results):
        return risk_score, "suspicious"

    meaningful = [result for result in results if not result.error]
    if meaningful and any(result.verdict == "benign" for result in meaningful):
        return risk_score, "benign"
    return risk_score, "unknown"


def aggregate_indicator_verdicts(verdict_scores: Iterable[tuple[str, int]]) -> tuple[int, str]:
    values = list(verdict_scores)
    if not values:
        return 0, "unknown"

    max_risk_score = max(score for _verdict, score in values)
    highest_verdict = max((verdict for verdict, _score in values), key=lambda verdict: _VERDICT_PRIORITY.get(verdict, 0))

    if max_risk_score >= 70:
        return max_risk_score, "malicious"
    if max_risk_score >= 40:
        return max_risk_score, "suspicious"
    return max_risk_score, highest_verdict if highest_verdict != "benign" or max_risk_score < 40 else "suspicious"
