from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+asyncpg://soc:soc@localhost:5432/soc"

    wazuh_api_url: str = ""
    wazuh_api_username: str = ""
    wazuh_api_password: str = ""
    wazuh_api_verify_tls: bool = True
    wazuh_active_response_provider_mode: str = "offline"
    wazuh_active_response_agents: str = "all"
    wazuh_active_response_command: str = "firewall-drop"
    wazuh_active_response_timeout_seconds: int = 10

    llm_base_url: str = ""
    llm_api_key: str = ""
    llm_model: str = ""

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

    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    urlhaus_api_url: str = ""
    urlhaus_auth_key: str = ""

    threat_intel_provider_mode: str = "offline"
    threat_intel_enable_external_providers: bool = False
    threat_intel_lookup_timeout_seconds: int = 5

    qdrant_url: str = ""
    qdrant_api_key: str = ""

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

    def validate_ingest_settings(self) -> None:
        if self.security_rate_limit_per_minute <= 0:
            raise ValueError("SECURITY_RATE_LIMIT_PER_MINUTE must be positive")
        if self.ingest_signature_max_skew_seconds <= 0:
            raise ValueError("INGEST_SIGNATURE_MAX_SKEW_SECONDS must be positive")
        if self.ingest_max_body_bytes <= 0:
            raise ValueError("INGEST_MAX_BODY_BYTES must be positive")
        if self.threat_intel_lookup_timeout_seconds <= 0:
            raise ValueError("THREAT_INTEL_LOOKUP_TIMEOUT_SECONDS must be positive")
        if self.ai_triage_timeout_seconds <= 0:
            raise ValueError("AI_TRIAGE_TIMEOUT_SECONDS must be positive")
        if self.ai_triage_max_alerts <= 0:
            raise ValueError("AI_TRIAGE_MAX_ALERTS must be positive")
        if self.ai_triage_max_text_chars <= 0:
            raise ValueError("AI_TRIAGE_MAX_TEXT_CHARS must be positive")
        if self.ai_triage_max_context_chars <= 0:
            raise ValueError("AI_TRIAGE_MAX_CONTEXT_CHARS must be positive")
        if self.ai_triage_max_json_depth <= 0:
            raise ValueError("AI_TRIAGE_MAX_JSON_DEPTH must be positive")
        if self.ai_triage_max_list_items <= 0:
            raise ValueError("AI_TRIAGE_MAX_LIST_ITEMS must be positive")
        if not self.ai_triage_binary_placeholder:
            raise ValueError("AI_TRIAGE_BINARY_PLACEHOLDER must not be empty")
        if self.wazuh_active_response_provider_mode not in ("offline", "wazuh"):
            raise ValueError("WAZUH_ACTIVE_RESPONSE_PROVIDER_MODE must be offline or wazuh")
        if self.wazuh_active_response_provider_mode != "offline":
            if not self.wazuh_api_url:
                raise ValueError("WAZUH_API_URL must be set for non-offline Wazuh active response providers")
            if not self.wazuh_api_username or not self.wazuh_api_password:
                raise ValueError("WAZUH_API_USERNAME and WAZUH_API_PASSWORD must be set for non-offline Wazuh active response providers")
            if not self.wazuh_active_response_command:
                raise ValueError("WAZUH_ACTIVE_RESPONSE_COMMAND must name the active response command defined in ossec.conf")
            if self.wazuh_active_response_timeout_seconds <= 0:
                raise ValueError("WAZUH_ACTIVE_RESPONSE_TIMEOUT_SECONDS must be positive")
        if self.ai_triage_provider_mode == "jev":
            if not self.typesafe_api_key:
                raise ValueError("TYPESAFE_API_KEY must be set for Jev AI triage")
            if not self.typesafe_model:
                raise ValueError("TYPESAFE_MODEL must be set for Jev AI triage")
        elif self.ai_triage_provider_mode != "offline":
            if not self.llm_model:
                raise ValueError("LLM_MODEL must be set for non-offline AI triage providers")
            if self.ai_triage_provider_mode == "openai_compatible" and not self.llm_base_url:
                raise ValueError("LLM_BASE_URL must be set for openai_compatible AI triage")
        if self.rag_top_k <= 0:
            raise ValueError("RAG_TOP_K must be positive")
        if self.rag_max_chunk_chars <= 0:
            raise ValueError("RAG_MAX_CHUNK_CHARS must be positive")
        if self.rag_max_context_chars <= 0:
            raise ValueError("RAG_MAX_CONTEXT_CHARS must be positive")
        if self.knowledge_base_provider_mode != "offline" and not self.qdrant_url:
            raise ValueError("QDRANT_URL must be set for non-offline knowledge providers")
        if self.threat_intel_provider_mode not in ("offline", "external"):
            raise ValueError("THREAT_INTEL_PROVIDER_MODE must be offline or external")
        if self.threat_intel_provider_mode != "offline":
            if not self.threat_intel_enable_external_providers:
                raise ValueError("THREAT_INTEL_PROVIDER_MODE must be offline unless external providers are enabled")
            if not (self.virustotal_api_key or self.abuseipdb_api_key or self.urlhaus_api_url):
                raise ValueError(
                    "External threat intel requires at least one of VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, or URLHAUS_API_URL"
                )
        if self.app_secret_key == "change-me":
            raise ValueError("APP_SECRET_KEY must be changed from the default")


settings = Settings()
