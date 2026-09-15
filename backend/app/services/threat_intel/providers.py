from __future__ import annotations

import ipaddress
from typing import Protocol
from urllib.parse import urlsplit

from app.schemas.threat_intel import ThreatIntelProviderResult


class ThreatIntelProvider(Protocol):
    name: str
    supported_types: frozenset[str]

    async def lookup(self, indicator_type: str, indicator: str) -> ThreatIntelProviderResult:
        ...


class OfflineThreatIntelProvider:
    """Deterministic local provider used when external API keys are absent."""

    name = "offline"
    supported_types = frozenset({"ip", "domain", "hash", "url"})

    async def lookup(self, indicator_type: str, indicator: str) -> ThreatIntelProviderResult:
        if indicator_type == "ip":
            return self._lookup_ip(indicator)
        if indicator_type == "domain":
            return self._lookup_domain(indicator)
        if indicator_type == "hash":
            return self._lookup_hash(indicator)
        if indicator_type == "url":
            return self._lookup_url(indicator)
        return self._result(
            indicator_type,
            verdict="unknown",
            risk_score=0,
            confidence=0,
            summary="Unsupported offline indicator type",
            error="unsupported_indicator_type",
        )

    def _result(
        self,
        indicator_type: str,
        *,
        verdict: str,
        risk_score: int,
        confidence: int,
        summary: str,
        error: str | None = None,
        metadata: dict | None = None,
    ) -> ThreatIntelProviderResult:
        return ThreatIntelProviderResult(
            provider=self.name,
            verdict=verdict,
            risk_score=risk_score,
            confidence=confidence,
            summary=summary,
            error=error,
            metadata={"source": "offline", "indicator_type": indicator_type, **(metadata or {})},
        )

    def _lookup_ip(self, indicator: str) -> ThreatIntelProviderResult:
        ip = ipaddress.ip_address(indicator)
        if not ip.is_global or ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            return self._result(
                "ip",
                verdict="benign",
                risk_score=0,
                confidence=100,
                summary="Non-routable, local, or reserved IP address",
                metadata={"scope": "non_global"},
            )
        return self._result(
            "ip",
            verdict="unknown",
            risk_score=5,
            confidence=20,
            summary="No offline reputation match for public IP address",
            metadata={"scope": "public"},
        )

    def _lookup_domain(self, indicator: str) -> ThreatIntelProviderResult:
        reserved_names = {"localhost", "example.com", "example.net", "example.org"}
        reserved_suffixes = (".test", ".example", ".invalid", ".localhost", ".example.com", ".example.net", ".example.org")
        if indicator in reserved_names or indicator.endswith(reserved_suffixes):
            return self._result(
                "domain",
                verdict="benign",
                risk_score=0,
                confidence=100,
                summary="Reserved or local-use domain name",
                metadata={"scope": "reserved"},
            )
        if any(token in indicator for token in ("malware", "phish", "evil")):
            return self._result(
                "domain",
                verdict="suspicious",
                risk_score=45,
                confidence=60,
                summary="Offline heuristic matched a suspicious domain token",
                metadata={"heuristic": "suspicious_domain_token"},
            )
        return self._result(
            "domain",
            verdict="unknown",
            risk_score=5,
            confidence=20,
            summary="No offline reputation match for domain",
        )

    def _lookup_hash(self, indicator: str) -> ThreatIntelProviderResult:
        if indicator == "A" * 64:
            return self._result(
                "hash",
                verdict="malicious",
                risk_score=85,
                confidence=90,
                summary="Offline fixture hash marked malicious for deterministic tests",
                metadata={"fixture": "malicious_sha256"},
            )
        if indicator in {"B" * 40, "C" * 32}:
            return self._result(
                "hash",
                verdict="suspicious",
                risk_score=50,
                confidence=70,
                summary="Offline fixture hash marked suspicious for deterministic tests",
                metadata={"fixture": "suspicious_hash"},
            )
        return self._result(
            "hash",
            verdict="unknown",
            risk_score=5,
            confidence=20,
            summary="No offline reputation match for hash",
        )

    def _lookup_url(self, indicator: str) -> ThreatIntelProviderResult:
        parts = urlsplit(indicator)
        host = parts.hostname or ""
        path = parts.path.casefold()
        query = parts.query.casefold()
        if ".." in path or "%2e%2e" in path or any(path.endswith(ext) for ext in (".bat", ".dll", ".exe", ".ps1", ".scr")):
            return self._result(
                "url",
                verdict="suspicious",
                risk_score=55,
                confidence=65,
                summary="Offline heuristic matched suspicious URL path content",
                metadata={"heuristic": "suspicious_url_path"},
            )
        if any(token in host or token in query for token in ("malware", "phish", "evil")):
            return self._result(
                "url",
                verdict="suspicious",
                risk_score=45,
                confidence=60,
                summary="Offline heuristic matched suspicious URL token",
                metadata={"heuristic": "suspicious_url_token"},
            )
        return self._result(
            "url",
            verdict="unknown",
            risk_score=5,
            confidence=20,
            summary="No offline reputation match for URL",
        )


class DisabledThreatIntelProvider:
    """Placeholder for external providers until network lookups are enabled."""

    def __init__(self, name: str, supported_types: set[str] | frozenset[str]) -> None:
        self.name = name
        self.supported_types = frozenset(supported_types)

    async def lookup(self, indicator_type: str, indicator: str) -> ThreatIntelProviderResult:
        return ThreatIntelProviderResult(
            provider=self.name,
            verdict="unknown",
            risk_score=0,
            confidence=0,
            summary="External provider is configured as disabled in offline-first mode",
            error="provider_disabled",
            metadata={"indicator_type": indicator_type},
        )
