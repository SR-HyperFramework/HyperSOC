import pytest

from app.core.config import Settings


def configured(**updates) -> Settings:
    values = {
        "app_secret_key": "a-long-test-secret-value",
        "ai_triage_provider_mode": "offline",
        "knowledge_base_provider_mode": "offline",
        "threat_intel_provider_mode": "offline",
        "wazuh_active_response_provider_mode": "offline",
    }
    values.update(updates)
    return Settings(_env_file=None, **values)


@pytest.mark.parametrize("secret", ["change-me", "replace-with-a-random-secret", "too-short"])
def test_runtime_rejects_placeholder_or_short_secret(secret):
    with pytest.raises(ValueError, match="APP_SECRET_KEY"):
        configured(app_secret_key=secret).validate_runtime_settings()


@pytest.mark.parametrize("mode", ["openai_compatible", "anything-else"])
def test_runtime_rejects_unimplemented_ai_modes(mode):
    with pytest.raises(ValueError, match="AI_TRIAGE_PROVIDER_MODE"):
        configured(ai_triage_provider_mode=mode).validate_runtime_settings()


def test_runtime_rejects_unimplemented_knowledge_mode():
    with pytest.raises(ValueError, match="KNOWLEDGE_BASE_PROVIDER_MODE"):
        configured(knowledge_base_provider_mode="qdrant").validate_runtime_settings()


@pytest.mark.parametrize("agents", ["all", "*", "", "001,agent"])
def test_wazuh_mode_requires_explicit_numeric_agents(agents):
    settings = configured(
        wazuh_active_response_provider_mode="wazuh",
        wazuh_api_url="https://wazuh.internal:55000",
        wazuh_api_username="soc-api",
        wazuh_api_password="secret",
        wazuh_active_response_agents=agents,
    )
    with pytest.raises(ValueError, match="WAZUH_ACTIVE_RESPONSE_AGENTS"):
        settings.validate_runtime_settings()


def test_wazuh_mode_accepts_scoped_configuration():
    settings = configured(
        wazuh_active_response_provider_mode="wazuh",
        wazuh_api_url="https://wazuh.internal:55000",
        wazuh_api_username="soc-api",
        wazuh_api_password="secret",
        wazuh_active_response_agents="001,002",
    )
    settings.validate_runtime_settings()


def test_cors_origins_are_trimmed_and_deduplicated():
    settings = configured(cors_allowed_origins=" https://one.example,https://two.example,https://one.example ")
    assert settings.cors_origins() == ["https://one.example", "https://two.example"]


def test_cors_rejects_wildcard():
    with pytest.raises(ValueError, match="explicit origins"):
        configured(cors_allowed_origins="*").validate_runtime_settings()


def test_compatibility_validation_calls_full_runtime_validation():
    configured().validate_ingest_settings()
