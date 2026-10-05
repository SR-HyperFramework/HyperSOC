import json

from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.validation import parse_wazuh_agent_list


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+asyncpg://soc:soc@localhost:5432/soc"
    auth_enabled: bool = True
    auth_session_seconds: int = 3600

    automation_enabled: bool = True
    automation_poll_seconds: int = 2
    automation_lease_seconds: int = 300
    automation_max_attempts: int = 5
    behavior_auto_train: bool = True
    behavior_refresh_seconds: int = 3600
    behavior_training_days: int = 30
    alert_understanding_provider_mode: str = "offline"

    wazuh_api_url: str = ""
    wazuh_api_username: str = ""
    wazuh_api_password: str = ""
    wazuh_api_verify_tls: bool = True
    wazuh_active_response_provider_mode: str = "offline"
    wazuh_active_response_agents: str = "all"
    wazuh_active_response_command: str = "firewall-drop"
    wazuh_active_response_timeout_seconds: int = 10
    response_evidence_sources: str = "wazuh"

    typesafe_api_key: str = ""
    typesafe_base_url: str = ""
    typesafe_model: str = "jev-latest"

    ai_triage_provider_mode: str = "offline"
    ai_triage_timeout_seconds: int = 30
    ai_triage_max_alerts: int = 25
    ai_triage_max_text_chars: int = 1000
    ai_triage_max_context_chars: int = 20_000
    ai_triage_max_json_depth: int = 6
    ai_triage_max_list_items: int = 50
    ai_triage_binary_placeholder: str = "[BINARY_DATA_STRIPPED]"

    investigator_provider_mode: str = "offline"
    investigator_openrouter_api_key: str = ""
    investigator_model: str = ""
    investigator_timeout_seconds: int = 30
    investigator_max_tool_calls: int = 4

    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    urlhaus_api_url: str = ""
    urlhaus_auth_key: str = ""

    threat_intel_provider_mode: str = "offline"
    threat_intel_enable_external_providers: bool = False
    threat_intel_lookup_timeout_seconds: int = 5

    knowledge_base_provider_mode: str = "offline"
    knowledge_base_path: str = "knowledge"
    rag_top_k: int = 5
    rag_max_chunk_chars: int = 1200
    rag_max_context_chars: int = 6000

    app_secret_key: str = "change-me"
    cors_allowed_origins: str = "http://localhost:3000,http://localhost:8000"
    security_rate_limit_per_minute: int = 120

    ingest_signature_max_skew_seconds: int = 300
    ingest_max_body_bytes: int = 1_048_576
    hub_source_keys: str = ""

    def hub_keys(self) -> dict[str, str]:
        if not self.hub_source_keys:
            return {}
        try:
            keys = json.loads(self.hub_source_keys)
        except ValueError as exc:
            raise ValueError("HUB_SOURCE_KEYS must be a JSON object of source names and secrets") from exc
        if not isinstance(keys, dict) or not keys or any(
            not isinstance(source, str) or not source.strip() or len(source) > 128
            or not isinstance(secret, str) or len(secret) < 16 for source, secret in keys.items()
        ):
            raise ValueError("HUB_SOURCE_KEYS requires nonempty source names and secrets of at least 16 characters")
        return keys

    def investigator_api_key(self) -> str:
        if self.investigator_openrouter_api_key:
            return self.investigator_openrouter_api_key
        if self.typesafe_base_url.rstrip("/") in ("https://openrouter.ai/api", "https://openrouter.ai/api/v1"):
            return self.typesafe_api_key
        return ""

    def cors_origins(self) -> list[str]:
        origins = list(dict.fromkeys(item.strip() for item in self.cors_allowed_origins.split(",") if item.strip()))
        if "*" in origins:
            raise ValueError("CORS_ALLOWED_ORIGINS must list explicit origins; wildcard access is not allowed")
        return origins

    def validate_runtime_settings(self) -> None:
        positive_settings = {
            "AUTH_SESSION_SECONDS": self.auth_session_seconds,
            "AUTOMATION_POLL_SECONDS": self.automation_poll_seconds,
            "AUTOMATION_LEASE_SECONDS": self.automation_lease_seconds,
            "AUTOMATION_MAX_ATTEMPTS": self.automation_max_attempts,
            "BEHAVIOR_REFRESH_SECONDS": self.behavior_refresh_seconds,
            "BEHAVIOR_TRAINING_DAYS": self.behavior_training_days,
            "SECURITY_RATE_LIMIT_PER_MINUTE": self.security_rate_limit_per_minute,
            "INGEST_SIGNATURE_MAX_SKEW_SECONDS": self.ingest_signature_max_skew_seconds,
            "INGEST_MAX_BODY_BYTES": self.ingest_max_body_bytes,
            "THREAT_INTEL_LOOKUP_TIMEOUT_SECONDS": self.threat_intel_lookup_timeout_seconds,
            "AI_TRIAGE_TIMEOUT_SECONDS": self.ai_triage_timeout_seconds,
            "AI_TRIAGE_MAX_ALERTS": self.ai_triage_max_alerts,
            "AI_TRIAGE_MAX_TEXT_CHARS": self.ai_triage_max_text_chars,
            "AI_TRIAGE_MAX_CONTEXT_CHARS": self.ai_triage_max_context_chars,
            "AI_TRIAGE_MAX_JSON_DEPTH": self.ai_triage_max_json_depth,
            "AI_TRIAGE_MAX_LIST_ITEMS": self.ai_triage_max_list_items,
            "INVESTIGATOR_TIMEOUT_SECONDS": self.investigator_timeout_seconds,
            "INVESTIGATOR_MAX_TOOL_CALLS": self.investigator_max_tool_calls,
            "RAG_TOP_K": self.rag_top_k,
            "RAG_MAX_CHUNK_CHARS": self.rag_max_chunk_chars,
            "RAG_MAX_CONTEXT_CHARS": self.rag_max_context_chars,
        }
        for name, value in positive_settings.items():
            if value <= 0:
                raise ValueError(f"{name} must be positive")
        if not self.ai_triage_binary_placeholder:
            raise ValueError("AI_TRIAGE_BINARY_PLACEHOLDER must not be empty")
        if self.behavior_training_days > 90:
            raise ValueError("BEHAVIOR_TRAINING_DAYS cannot exceed 90")

        if self.wazuh_active_response_provider_mode not in ("offline", "wazuh"):
            raise ValueError("WAZUH_ACTIVE_RESPONSE_PROVIDER_MODE must be offline or wazuh")
        if self.wazuh_active_response_provider_mode == "wazuh":
            if not self.wazuh_api_url:
                raise ValueError("WAZUH_API_URL must be set for Wazuh active response")
            if not self.wazuh_api_username or not self.wazuh_api_password:
                raise ValueError("WAZUH_API_USERNAME and WAZUH_API_PASSWORD must be set for Wazuh active response")
            parse_wazuh_agent_list(self.wazuh_active_response_agents)
            if not self.wazuh_active_response_command:
                raise ValueError("WAZUH_ACTIVE_RESPONSE_COMMAND must name the active response command defined in ossec.conf")
            if self.wazuh_active_response_timeout_seconds <= 0:
                raise ValueError("WAZUH_ACTIVE_RESPONSE_TIMEOUT_SECONDS must be positive")

        if self.ai_triage_provider_mode not in ("offline", "jev"):
            raise ValueError("AI_TRIAGE_PROVIDER_MODE must be offline or jev")
        if self.ai_triage_provider_mode == "jev":
            if not self.typesafe_api_key:
                raise ValueError("TYPESAFE_API_KEY must be set for Jev AI triage")
            if not self.typesafe_model:
                raise ValueError("TYPESAFE_MODEL must be set for Jev AI triage")

        if self.investigator_provider_mode not in ("offline", "openrouter"):
            raise ValueError("INVESTIGATOR_PROVIDER_MODE must be offline or openrouter")
        if self.investigator_provider_mode == "openrouter":
            if not self.investigator_api_key() or not self.investigator_model:
                raise ValueError("An OpenRouter key and INVESTIGATOR_MODEL are required in openrouter mode")
        if self.alert_understanding_provider_mode not in ("offline", "openrouter"):
            raise ValueError("ALERT_UNDERSTANDING_PROVIDER_MODE must be offline or openrouter")
        if self.alert_understanding_provider_mode == "openrouter" and (not self.investigator_api_key() or not self.investigator_model):
            raise ValueError("OpenRouter key and INVESTIGATOR_MODEL are required for alert understanding")
        if self.investigator_max_tool_calls > 4:
            raise ValueError("INVESTIGATOR_MAX_TOOL_CALLS cannot exceed the four read-only tools")

        if self.knowledge_base_provider_mode != "offline":
            raise ValueError("KNOWLEDGE_BASE_PROVIDER_MODE must be offline")
        if self.threat_intel_provider_mode not in ("offline", "external"):
            raise ValueError("THREAT_INTEL_PROVIDER_MODE must be offline or external")
        if self.threat_intel_provider_mode == "external":
            if not self.threat_intel_enable_external_providers:
                raise ValueError("THREAT_INTEL_ENABLE_EXTERNAL_PROVIDERS must be true in external mode")
            if not (self.virustotal_api_key or self.abuseipdb_api_key or self.urlhaus_api_url):
                raise ValueError(
                    "External threat intel requires at least one of VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, or URLHAUS_API_URL"
                )

        placeholders = {"change-me", "replace-with-a-random-secret"}
        if self.app_secret_key in placeholders or len(self.app_secret_key) < 16:
            raise ValueError("APP_SECRET_KEY must be a non-placeholder value of at least 16 characters")
        self.cors_origins()
        self.hub_keys()

    def validate_ingest_settings(self) -> None:
        """Backward-compatible alias for the original startup validation hook."""
        self.validate_runtime_settings()


settings = Settings()
