from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+asyncpg://soc:soc@localhost:5432/soc"

    wazuh_api_url: str = ""
    wazuh_api_username: str = ""
    wazuh_api_password: str = ""

    llm_base_url: str = ""
    llm_api_key: str = ""
    llm_model: str = ""

    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""

    qdrant_url: str = ""
    qdrant_api_key: str = ""

    app_secret_key: str = "change-me"

    ingest_signature_max_skew_seconds: int = 300
    ingest_max_body_bytes: int = 1_048_576

    def validate_ingest_settings(self) -> None:
        if self.ingest_signature_max_skew_seconds <= 0:
            raise ValueError("INGEST_SIGNATURE_MAX_SKEW_SECONDS must be positive")
        if self.ingest_max_body_bytes <= 0:
            raise ValueError("INGEST_MAX_BODY_BYTES must be positive")
        if self.app_secret_key == "change-me":
            raise ValueError("APP_SECRET_KEY must be changed from the default")


settings = Settings()
