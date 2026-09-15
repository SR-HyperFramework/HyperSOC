from fastapi import FastAPI
from sqlalchemy import text

from app.api.alerts import router as alerts_router
from app.api.threat_intel import router as threat_intel_router
from app.core.config import settings
from app.core.database import engine
from app.core.logging import configure_logging

configure_logging()

# Fail fast in deployments instead of accepting alerts signed with a known
# development secret or an invalid request-size/replay configuration.
settings.validate_ingest_settings()

app = FastAPI(title="AI SOC Backend")
app.include_router(alerts_router)
app.include_router(threat_intel_router)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.get("/ready")
async def ready() -> dict:
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))
    return {"status": "ready"}
