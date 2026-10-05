import os

# App startup rejects the production placeholder secret. Tests intentionally use
# an isolated process-only value before application modules instantiate settings.
os.environ["APP_SECRET_KEY"] = "test-ingest-secret-value"
os.environ["SECURITY_RATE_LIMIT_PER_MINUTE"] = "100000"
os.environ["AI_TRIAGE_PROVIDER_MODE"] = "offline"
os.environ["INVESTIGATOR_PROVIDER_MODE"] = "offline"
os.environ["ALERT_UNDERSTANDING_PROVIDER_MODE"] = "offline"
os.environ["THREAT_INTEL_PROVIDER_MODE"] = "offline"
os.environ["THREAT_INTEL_ENABLE_EXTERNAL_PROVIDERS"] = "false"
os.environ["WAZUH_ACTIVE_RESPONSE_PROVIDER_MODE"] = "offline"
os.environ["AUTH_ENABLED"] = "false"
os.environ["HUB_SOURCE_KEYS"] = ""
