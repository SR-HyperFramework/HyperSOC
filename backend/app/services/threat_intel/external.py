from __future__ import annotations

import base64
import ipaddress
import re
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from app.schemas.threat_intel import ThreatIntelProviderResult

_UNSAFE_TEXT_RE = re.compile(r"[^A-Za-z0-9 ._:\-]")
_MAX_TEXT_CHARS = 120
_MAX_TAGS = 5
_MAX_RESPONSE_BYTES = 2_097_152
_MAX_SCANNED_URLS = 100

_RESERVED_DOMAIN_NAMES = frozenset({"localhost", "example.com", "example.net", "example.org"})
_RESERVED_DOMAIN_SUFFIXES = (
    ".test",
    ".example",
    ".invalid",
    ".localhost",
    ".local",
    ".internal",
    ".intranet",
    ".corp",
    ".home",
    ".lan",
)

VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
URLHAUS_BASE_URL = "https://urlhaus-api.abuse.ch/v1"


class ExternalThreatIntelError(Exception):
    """Bounded provider failure that is reported as a result error instead of raising."""

    def __init__(self, code: str, summary: str) -> None:
        super().__init__(summary)
        self.code = code
        self.summary = summary


def _safe_text(value: Any, *, max_chars: int = _MAX_TEXT_CHARS) -> str | None:
    """Reduce provider-controlled text to a bounded allowlist charset.

    Provider output reaches analyst UI and LLM triage context, so it is stripped
    rather than escaped; see docs/prompt-injection-protection.md.
    """
    if value is None or isinstance(value, (dict, list, tuple, set, bool)):
        return None
    text = _UNSAFE_TEXT_RE.sub("", str(value)).strip()
    return text[:max_chars] or None


def _safe_int(value: Any, *, minimum: int = 0, maximum: int = 1_000_000_000) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return minimum
    return max(minimum, min(maximum, number))


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _sequence(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else []


def _is_public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_global and not address.is_multicast


def _is_public_domain(value: str) -> bool:
    domain = value.strip().rstrip(".").casefold()
    if not domain or "." not in domain:
        return False
    return domain not in _RESERVED_DOMAIN_NAMES and not domain.endswith(_RESERVED_DOMAIN_SUFFIXES)


def is_externally_queryable(indicator_type: str, indicator: str) -> bool:
    """Keep local, private, and reserved assets from reaching third-party APIs."""
    if indicator_type == "ip":
        return _is_public_ip(indicator)
    if indicator_type == "domain":
        return _is_public_domain(indicator)
    if indicator_type == "url":
        host = urlsplit(indicator).hostname or ""
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return _is_public_domain(host)
        return _is_public_ip(host)
    return indicator_type == "hash"


class _HTTPThreatIntelProvider:
    """Shared plumbing for external providers: guarding, timeouts, and error mapping."""

    name = "external"
    supported_types: frozenset[str] = frozenset()

    def __init__(
        self,
        *,
        timeout_seconds: int = 5,
        client_factory: Callable[..., httpx.AsyncClient] | None = None,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.client_factory = client_factory or httpx.AsyncClient

    async def lookup(self, indicator_type: str, indicator: str) -> ThreatIntelProviderResult:
        if indicator_type not in self.supported_types:
            return self._result(
                indicator_type,
                summary=f"{self.name} does not support {indicator_type} indicators",
                error="unsupported_indicator_type",
            )
        if not is_externally_queryable(indicator_type, indicator):
            return self._result(
                indicator_type,
                summary="Local or reserved indicator was not sent to an external provider",
                error="indicator_not_queryable",
            )
        try:
            return await self._lookup_external(indicator_type, indicator)
        except ExternalThreatIntelError as exc:
            return self._result(indicator_type, summary=exc.summary, error=exc.code)
        except httpx.TimeoutException:
            return self._result(
                indicator_type,
                summary=f"{self.name} lookup timed out after {self.timeout_seconds}s",
                error="provider_timeout",
            )
        except httpx.HTTPError:
            return self._result(
                indicator_type,
                summary=f"{self.name} could not be reached",
                error="provider_unavailable",
            )
        except Exception:
            return self._result(
                indicator_type,
                summary=f"{self.name} lookup failed",
                error="provider_error",
            )

    async def _lookup_external(self, indicator_type: str, indicator: str) -> ThreatIntelProviderResult:
        raise NotImplementedError

    def _result(
        self,
        indicator_type: str,
        *,
        verdict: str = "unknown",
        risk_score: int = 0,
        confidence: int = 0,
        summary: str,
        error: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ThreatIntelProviderResult:
        return ThreatIntelProviderResult(
            provider=self.name,
            verdict=verdict,
            risk_score=max(0, min(100, risk_score)),
            confidence=max(0, min(100, confidence)),
            summary=summary,
            error=error,
            metadata={"source": self.name, "indicator_type": indicator_type, **(metadata or {})},
        )

    async def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
    ) -> httpx.Response:
        async with self.client_factory(timeout=self.timeout_seconds) as client:
            response = await client.request(method, url, headers=headers, params=params, data=data)
        if response.status_code in (401, 403):
            raise ExternalThreatIntelError(
                "provider_unauthorized", f"{self.name} rejected the configured API credentials"
            )
        if response.status_code == 429:
            raise ExternalThreatIntelError("provider_rate_limited", f"{self.name} rate limit was exceeded")
        return response

    def _json(self, response: httpx.Response) -> dict[str, Any]:
        if len(response.content) > _MAX_RESPONSE_BYTES:
            raise ExternalThreatIntelError("provider_response_too_large", f"{self.name} response exceeded the size limit")
        try:
            payload = response.json()
        except ValueError as exc:
            raise ExternalThreatIntelError("provider_invalid_response", f"{self.name} returned a non-JSON response") from exc
        if not isinstance(payload, Mapping):
            raise ExternalThreatIntelError("provider_invalid_response", f"{self.name} returned an unexpected JSON shape")
        return dict(payload)

    def _require_ok(self, response: httpx.Response) -> None:
        if response.status_code != 200:
            raise ExternalThreatIntelError(
                "provider_unavailable", f"{self.name} returned HTTP {response.status_code}"
            )


class VirusTotalProvider(_HTTPThreatIntelProvider):
    """VirusTotal v3 reputation lookups reduced to bounded detection counts."""

    name = "virustotal"
    supported_types = frozenset({"ip", "domain", "hash", "url"})

    def __init__(self, *, api_key: str, base_url: str = VIRUSTOTAL_BASE_URL, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.api_key = api_key
        self.base_url = (base_url or VIRUSTOTAL_BASE_URL).rstrip("/")

    async def _lookup_external(self, indicator_type: str, indicator: str) -> ThreatIntelProviderResult:
        response = await self._request(
            "GET",
            f"{self.base_url}/{self._path(indicator_type, indicator)}",
            headers={"x-apikey": self.api_key, "accept": "application/json"},
        )
        if response.status_code == 404:
            return self._result(indicator_type, summary="VirusTotal has no record for this indicator")
        self._require_ok(response)

        attributes = _mapping(_mapping(self._json(response).get("data")).get("attributes"))
        stats = _mapping(attributes.get("last_analysis_stats"))
        malicious = _safe_int(stats.get("malicious"))
        suspicious = _safe_int(stats.get("suspicious"))
        harmless = _safe_int(stats.get("harmless"))
        undetected = _safe_int(stats.get("undetected"))
        total_engines = malicious + suspicious + harmless + undetected
        metadata = {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total_engines": total_engines,
            "reputation": _safe_int(attributes.get("reputation"), minimum=-1_000_000),
        }

        if total_engines == 0:
            return self._result(
                indicator_type,
                summary="VirusTotal returned no engine results for this indicator",
                metadata=metadata,
            )

        verdict, risk_score = self._score(malicious, suspicious)
        return self._result(
            indicator_type,
            verdict=verdict,
            risk_score=risk_score,
            confidence=min(100, total_engines),
            summary=(
                f"VirusTotal: {malicious} malicious and {suspicious} suspicious "
                f"detections across {total_engines} engines"
            ),
            metadata=metadata,
        )

    def _path(self, indicator_type: str, indicator: str) -> str:
        if indicator_type == "ip":
            return f"ip_addresses/{quote(indicator, safe='')}"
        if indicator_type == "domain":
            return f"domains/{quote(indicator, safe='')}"
        if indicator_type == "hash":
            return f"files/{quote(indicator.lower(), safe='')}"
        url_id = base64.urlsafe_b64encode(indicator.encode("utf-8")).decode("ascii").rstrip("=")
        return f"urls/{url_id}"

    def _score(self, malicious: int, suspicious: int) -> tuple[str, int]:
        if malicious >= 5:
            return "malicious", min(100, 70 + malicious * 2)
        if malicious >= 1:
            return "suspicious", min(65, 45 + malicious * 5)
        if suspicious >= 1:
            return "suspicious", 40
        return "benign", 0


class AbuseIPDBProvider(_HTTPThreatIntelProvider):
    """AbuseIPDB abuse-confidence lookups for public IP addresses."""

    name = "abuseipdb"
    supported_types = frozenset({"ip"})

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str = ABUSEIPDB_BASE_URL,
        max_age_days: int = 90,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.api_key = api_key
        self.base_url = (base_url or ABUSEIPDB_BASE_URL).rstrip("/")
        self.max_age_days = max_age_days

    async def _lookup_external(self, indicator_type: str, indicator: str) -> ThreatIntelProviderResult:
        response = await self._request(
            "GET",
            f"{self.base_url}/check",
            headers={"Key": self.api_key, "Accept": "application/json"},
            params={"ipAddress": indicator, "maxAgeInDays": str(self.max_age_days)},
        )
        self._require_ok(response)

        data = _mapping(self._json(response).get("data"))
        score = _safe_int(data.get("abuseConfidenceScore"), maximum=100)
        total_reports = _safe_int(data.get("totalReports"))
        whitelisted = data.get("isWhitelisted") is True
        metadata = {
            "abuse_confidence_score": score,
            "total_reports": total_reports,
            "is_whitelisted": whitelisted,
            "country_code": _safe_text(data.get("countryCode"), max_chars=2),
            "usage_type": _safe_text(data.get("usageType"), max_chars=64),
        }

        if whitelisted:
            return self._result(
                indicator_type,
                verdict="benign",
                risk_score=0,
                confidence=90,
                summary="AbuseIPDB lists this address on its whitelist",
                metadata=metadata,
            )

        verdict = "malicious" if score >= 75 else "suspicious" if score >= 25 else "unknown"
        return self._result(
            indicator_type,
            verdict=verdict,
            risk_score=score,
            confidence=min(100, 40 + total_reports * 2) if total_reports else 40,
            summary=f"AbuseIPDB abuse confidence {score}% from {total_reports} reports in {self.max_age_days} days",
            metadata=metadata,
        )


class URLhausProvider(_HTTPThreatIntelProvider):
    """URLhaus (abuse.ch) lookups for malware distribution URLs, hosts, and payloads."""

    name = "urlhaus"
    supported_types = frozenset({"ip", "domain", "hash", "url"})

    def __init__(
        self,
        *,
        base_url: str = URLHAUS_BASE_URL,
        auth_key: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.base_url = (base_url or URLHAUS_BASE_URL).rstrip("/")
        self.auth_key = auth_key

    async def _lookup_external(self, indicator_type: str, indicator: str) -> ThreatIntelProviderResult:
        endpoint, form = self._endpoint(indicator_type, indicator)
        headers = {"Accept": "application/json"}
        if self.auth_key:
            headers["Auth-Key"] = self.auth_key

        response = await self._request("POST", f"{self.base_url}/{endpoint}/", headers=headers, data=form)
        self._require_ok(response)

        payload = self._json(response)
        query_status = _safe_text(payload.get("query_status"), max_chars=32) or "unknown"
        if query_status == "no_results":
            return self._result(indicator_type, summary="URLhaus has no record for this indicator")
        if query_status != "ok":
            raise ExternalThreatIntelError(
                "provider_rejected_indicator", f"URLhaus rejected the indicator with status {query_status}"
            )

        if endpoint == "url":
            return self._url_result(indicator_type, payload)
        if endpoint == "host":
            return self._host_result(indicator_type, payload)
        return self._payload_result(indicator_type, payload)

    def _endpoint(self, indicator_type: str, indicator: str) -> tuple[str, dict[str, str]]:
        if indicator_type == "url":
            return "url", {"url": indicator}
        if indicator_type in ("domain", "ip"):
            return "host", {"host": indicator}
        if len(indicator) == 32:
            return "payload", {"md5_hash": indicator.lower()}
        if len(indicator) == 64:
            return "payload", {"sha256_hash": indicator.lower()}
        raise ExternalThreatIntelError("unsupported_indicator_type", "URLhaus only indexes MD5 and SHA256 payloads")

    def _tags(self, payload: Mapping[str, Any]) -> list[str]:
        tags = (_safe_text(tag, max_chars=32) for tag in _sequence(payload.get("tags")))
        return [tag for tag in tags if tag][:_MAX_TAGS]

    def _url_result(self, indicator_type: str, payload: dict[str, Any]) -> ThreatIntelProviderResult:
        url_status = _safe_text(payload.get("url_status"), max_chars=16) or "unknown"
        threat = _safe_text(payload.get("threat"), max_chars=64)
        metadata = {"url_status": url_status, "threat": threat, "tags": self._tags(payload)}
        risk_score = 90 if url_status == "online" else 70 if url_status == "offline" else 55
        return self._result(
            indicator_type,
            verdict="malicious",
            risk_score=risk_score,
            confidence=90,
            summary=f"URLhaus lists this URL as a known malware distribution point (status {url_status})",
            metadata=metadata,
        )

    def _host_result(self, indicator_type: str, payload: dict[str, Any]) -> ThreatIntelProviderResult:
        url_count = _safe_int(payload.get("url_count"))
        entries = _sequence(payload.get("urls"))[:_MAX_SCANNED_URLS]
        online_count = sum(1 for entry in entries if _mapping(entry).get("url_status") == "online")
        metadata = {"url_count": url_count, "online_url_count": online_count, "tags": self._tags(payload)}

        if online_count:
            verdict, risk_score = "malicious", 85
        elif url_count:
            verdict, risk_score = "suspicious", 55
        else:
            return self._result(
                indicator_type,
                summary="URLhaus has no malware URLs recorded for this host",
                metadata=metadata,
            )
        return self._result(
            indicator_type,
            verdict=verdict,
            risk_score=risk_score,
            confidence=85,
            summary=f"URLhaus recorded {url_count} malware URLs on this host, {online_count} currently online",
            metadata=metadata,
        )

    def _payload_result(self, indicator_type: str, payload: dict[str, Any]) -> ThreatIntelProviderResult:
        signature = _safe_text(payload.get("signature"), max_chars=64)
        metadata = {
            "signature": signature,
            "file_type": _safe_text(payload.get("file_type"), max_chars=32),
            "url_count": _safe_int(payload.get("url_count")),
        }
        return self._result(
            indicator_type,
            verdict="malicious",
            risk_score=85,
            confidence=85,
            summary=f"URLhaus lists this payload as known malware ({signature or 'unclassified'})",
            metadata=metadata,
        )
