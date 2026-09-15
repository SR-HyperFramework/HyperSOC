import os

# App startup rejects the production placeholder secret. Tests intentionally use
# an isolated process-only value before application modules instantiate settings.
os.environ.setdefault("APP_SECRET_KEY", "test-ingest-secret")
