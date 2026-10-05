from pathlib import Path

from fastapi import FastAPI, HTTPException, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.auth import SOCAuthMiddleware
from app.core.database import engine
from app.core.logging import configure_logging
from app.core.rate_limit import InMemoryRateLimiter, RateLimitMiddleware
from app.core.readiness import ReadinessError, check_readiness


def create_app() -> FastAPI:
    # Validate before routers instantiate configured provider services.
    settings.validate_runtime_settings()
    configure_logging()

    from app.api.alerts import router as alerts_router
    from app.api.dashboard import router as dashboard_router
    from app.api.incidents import router as incidents_router
    from app.api.investigations import router as investigations_router
    from app.api.hub import router as hub_router
    from app.api.workflow import router as workflow_router
    from app.api.auth import router as auth_router
    from app.api.knowledge_base import router as knowledge_router
    from app.api.response import router as response_router
    from app.api.threat_intel import router as threat_intel_router

    application = FastAPI(title="AI SOC Backend")
    application.add_middleware(
        RateLimitMiddleware,
        limiter=InMemoryRateLimiter(settings.security_rate_limit_per_minute),
    )
    application.add_middleware(SOCAuthMiddleware)
    # Starlette runs the last-added middleware outermost, so CORS also decorates
    # locally generated 429 responses.
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins(),
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    application.include_router(alerts_router)
    application.include_router(threat_intel_router)
    application.include_router(incidents_router)
    application.include_router(investigations_router)
    application.include_router(hub_router)
    application.include_router(workflow_router)
    application.include_router(auth_router)
    application.include_router(knowledge_router)
    application.include_router(dashboard_router)
    application.include_router(response_router)
    frontend_path = Path(__file__).resolve().parents[2] / "frontend"
    application.mount("/assets", StaticFiles(directory=frontend_path), name="assets")

    @application.get("/", include_in_schema=False)
    async def console() -> FileResponse:
        return FileResponse(frontend_path / "console.html")

    @application.get("/health")
    async def health() -> dict:
        return {"status": "ok"}

    @application.get("/investigator", include_in_schema=False)
    async def investigator_console() -> FileResponse:
        page = frontend_path / "console.html"
        return FileResponse(page)

    @application.get("/ready")
    async def ready() -> dict:
        try:
            return await check_readiness(engine)
        except ReadinessError as exc:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc

    return application


app = create_app()
