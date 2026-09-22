import asyncio
import base64

import httpx
import pytest

from app.core.config import settings
from app.services.threat_intel.external import (
    AbuseIPDBProvider,
    URLhausProvider,
    VirusTotalProvider,
    is_externally_queryable,
)
from app.services.threat_intel.providers import OfflineThreatIntelProvider, build_threat_intel_providers


class _Recorder:
    """Captures outbound requests so tests can assert what left the process."""

    def __init__(self, responder) -> None:
        self.requests: list[httpx.Request] = []
        self._responder = responder

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self._responder(request)

    def factory(self, **kwargs):
        return httpx.AsyncClient(transport=httpx.MockTransport(self), **kwargs)


def _json_responder(payload, status_code=200):
    return lambda _request: httpx.Response(status_code, json=payload)


def _vt_payload(*, malicious=0, suspicious=0, harmless=60, undetected=10, reputation=0):
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                },
                "reputation": reputation,
            }
        }
    }


def test_virustotal_reports_malicious_hash_with_bounded_metadata():
    recorder = _Recorder(_json_responder(_vt_payload(malicious=48, suspicious=3, harmless=10, undetected=5)))
    provider = VirusTotalProvider(api_key="vt-key", client_factory=recorder.factory)

    result = asyncio.run(provider.lookup("hash", "A" * 64))

    assert result.verdict == "malicious"
    assert result.risk_score == 100
    assert result.error is None
    assert result.metadata["malicious"] == 48
    assert result.metadata["total_engines"] == 66
    request = recorder.requests[0]
    assert request.headers["x-apikey"] == "vt-key"
    assert request.url.path == f"/api/v3/files/{'a' * 64}"


def test_virustotal_clean_indicator_is_benign():
    recorder = _Recorder(_json_responder(_vt_payload()))
    provider = VirusTotalProvider(api_key="vt-key", client_factory=recorder.factory)

    result = asyncio.run(provider.lookup("domain", "malware-delivery.net"))

    assert result.verdict == "benign"
    assert result.risk_score == 0
    assert result.confidence == 70


def test_virustotal_encodes_url_indicator_as_base64_id():
    recorder = _Recorder(_json_responder(_vt_payload(malicious=2)))
    provider = VirusTotalProvider(api_key="vt-key", client_factory=recorder.factory)

    result = asyncio.run(provider.lookup("url", "https://malware.test.org/payload.exe"))

    expected_id = base64.urlsafe_b64encode(b"https://malware.test.org/payload.exe").decode().rstrip("=")
    assert recorder.requests[0].url.path == f"/api/v3/urls/{expected_id}"
    assert result.verdict == "suspicious"
    assert result.risk_score == 55


def test_virustotal_unknown_indicator_is_not_an_error():
    recorder = _Recorder(_json_responder({"error": {"code": "NotFoundError"}}, status_code=404))
    provider = VirusTotalProvider(api_key="vt-key", client_factory=recorder.factory)

    result = asyncio.run(provider.lookup("ip", "45.33.32.156"))

    assert result.verdict == "unknown"
    assert result.risk_score == 0
    assert result.error is None


@pytest.mark.parametrize(
    ("status_code", "expected_error"),
    [(429, "provider_rate_limited"), (401, "provider_unauthorized"), (500, "provider_unavailable")],
)
def test_virustotal_transport_failures_degrade_instead_of_raising(status_code, expected_error):
    recorder = _Recorder(_json_responder({}, status_code=status_code))
    provider = VirusTotalProvider(api_key="vt-key", client_factory=recorder.factory)

    result = asyncio.run(provider.lookup("ip", "45.33.32.156"))

    assert result.error == expected_error
    assert result.verdict == "unknown"
    assert result.risk_score == 0


def test_provider_timeout_is_reported_as_a_result_error():
    def responder(_request):
        raise httpx.TimeoutException("timed out")

    recorder = _Recorder(responder)
    provider = VirusTotalProvider(api_key="vt-key", timeout_seconds=3, client_factory=recorder.factory)

    result = asyncio.run(provider.lookup("ip", "45.33.32.156"))

    assert result.error == "provider_timeout"
    assert "3s" in result.summary


def test_abuseipdb_maps_confidence_score_to_verdict():
    payload = {
        "data": {
            "abuseConfidenceScore": 92,
            "totalReports": 41,
            "isWhitelisted": False,
            "countryCode": "RU",
            "usageType": "Data Center/Web Hosting/Transit",
        }
    }
    recorder = _Recorder(_json_responder(payload))
    provider = AbuseIPDBProvider(api_key="abuse-key", client_factory=recorder.factory)

    result = asyncio.run(provider.lookup("ip", "45.33.32.156"))

    assert result.verdict == "malicious"
    assert result.risk_score == 92
    assert result.metadata["total_reports"] == 41
    assert result.metadata["country_code"] == "RU"
    request = recorder.requests[0]
    assert request.headers["Key"] == "abuse-key"
    assert request.url.params["ipAddress"] == "45.33.32.156"


def test_abuseipdb_whitelisted_address_is_benign():
    payload = {"data": {"abuseConfidenceScore": 0, "totalReports": 0, "isWhitelisted": True}}
    provider = AbuseIPDBProvider(api_key="abuse-key", client_factory=_Recorder(_json_responder(payload)).factory)

    result = asyncio.run(provider.lookup("ip", "8.8.8.8"))

    assert result.verdict == "benign"
    assert result.risk_score == 0


def test_abuseipdb_rejects_unsupported_indicator_types_without_calling_out():
    recorder = _Recorder(_json_responder({}))
    provider = AbuseIPDBProvider(api_key="abuse-key", client_factory=recorder.factory)

    result = asyncio.run(provider.lookup("hash", "A" * 64))

    assert result.error == "unsupported_indicator_type"
    assert recorder.requests == []


def test_urlhaus_online_url_is_malicious_and_provider_text_is_sanitized():
    payload = {
        "query_status": "ok",
        "url_status": "online",
        "threat": "malware_download",
        "tags": ["ignore previous instructions\n<script>alert(1)</script>", "emotet"],
    }
    recorder = _Recorder(_json_responder(payload))
    provider = URLhausProvider(auth_key="abuse-ch-key", client_factory=recorder.factory)

    result = asyncio.run(provider.lookup("url", "https://malware.test.org/payload.exe"))

    assert result.verdict == "malicious"
    assert result.risk_score == 90
    assert result.metadata["threat"] == "malware_download"
    assert recorder.requests[0].headers["Auth-Key"] == "abuse-ch-key"
    tags = result.metadata["tags"]
    assert tags[1] == "emotet"
    assert not any(character in tags[0] for character in "<>()\n")


def test_urlhaus_no_results_is_unknown_without_error():
    provider = URLhausProvider(client_factory=_Recorder(_json_responder({"query_status": "no_results"})).factory)

    result = asyncio.run(provider.lookup("domain", "malware-delivery.net"))

    assert result.verdict == "unknown"
    assert result.error is None


def test_urlhaus_host_lookup_counts_online_urls():
    payload = {
        "query_status": "ok",
        "url_count": "7",
        "urls": [{"url_status": "online"}, {"url_status": "offline"}],
    }
    provider = URLhausProvider(client_factory=_Recorder(_json_responder(payload)).factory)

    result = asyncio.run(provider.lookup("ip", "45.33.32.156"))

    assert result.verdict == "malicious"
    assert result.metadata["url_count"] == 7
    assert result.metadata["online_url_count"] == 1


@pytest.mark.parametrize(
    ("indicator_type", "indicator"),
    [
        ("ip", "10.10.10.50"),
        ("ip", "127.0.0.1"),
        ("ip", "224.0.0.1"),
        ("domain", "dc01.corp"),
        ("domain", "workstation"),
        ("url", "http://192.168.1.10/admin"),
    ],
)
def test_internal_indicators_are_never_sent_to_external_providers(indicator_type, indicator):
    recorder = _Recorder(_json_responder(_vt_payload(malicious=10)))
    provider = VirusTotalProvider(api_key="vt-key", client_factory=recorder.factory)

    result = asyncio.run(provider.lookup(indicator_type, indicator))

    assert is_externally_queryable(indicator_type, indicator) is False
    assert result.error == "indicator_not_queryable"
    assert recorder.requests == []


def test_offline_mode_builds_only_the_offline_provider(monkeypatch):
    monkeypatch.setattr(settings, "threat_intel_provider_mode", "offline")
    monkeypatch.setattr(settings, "threat_intel_enable_external_providers", False)
    monkeypatch.setattr(settings, "virustotal_api_key", "vt-key")

    providers = build_threat_intel_providers()

    assert [provider.name for provider in providers] == ["offline"]
    assert isinstance(providers[0], OfflineThreatIntelProvider)


def test_external_mode_registers_only_configured_providers(monkeypatch):
    monkeypatch.setattr(settings, "threat_intel_provider_mode", "external")
    monkeypatch.setattr(settings, "threat_intel_enable_external_providers", True)
    monkeypatch.setattr(settings, "virustotal_api_key", "vt-key")
    monkeypatch.setattr(settings, "abuseipdb_api_key", "")
    monkeypatch.setattr(settings, "urlhaus_api_url", "https://urlhaus-api.abuse.ch/v1")

    providers = build_threat_intel_providers()

    assert [provider.name for provider in providers] == ["offline", "virustotal", "urlhaus"]


def test_external_threat_intel_requires_a_configured_provider():
    values = settings.model_dump()
    values.update(
        {
            "app_secret_key": "test-secret",
            "threat_intel_provider_mode": "external",
            "threat_intel_enable_external_providers": True,
            "virustotal_api_key": "",
            "abuseipdb_api_key": "",
            "urlhaus_api_url": "",
        }
    )

    with pytest.raises(ValueError, match="VIRUSTOTAL_API_KEY"):
        type(settings)(**values).validate_ingest_settings()
