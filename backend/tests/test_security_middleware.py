from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastapi.middleware.cors import CORSMiddleware

from app.core.rate_limit import InMemoryRateLimiter, RateLimitMiddleware


def app_with_limit(limit: int, *, clock=lambda: 0.0) -> FastAPI:
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, limiter=InMemoryRateLimiter(limit, clock=clock))
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["https://allowed.example"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/api/test")
    async def api_test():
        return {"status": "ok"}

    return app


def test_rate_limit_allows_limit_then_returns_429():
    client = TestClient(app_with_limit(2))
    assert client.get("/api/test").status_code == 200
    second = client.get("/api/test")
    assert second.status_code == 200
    assert second.headers["x-ratelimit-remaining"] == "0"
    rejected = client.get("/api/test", headers={"Origin": "https://allowed.example"})
    assert rejected.status_code == 429
    assert rejected.headers["retry-after"] == "60"
    assert rejected.headers["access-control-allow-origin"] == "https://allowed.example"


def test_rate_limit_resets_after_one_minute():
    now = [0.0]
    client = TestClient(app_with_limit(1, clock=lambda: now[0]))
    assert client.get("/api/test").status_code == 200
    assert client.get("/api/test").status_code == 429
    now[0] = 61.0
    assert client.get("/api/test").status_code == 200


def test_health_and_preflight_are_not_rate_limited():
    client = TestClient(app_with_limit(1))
    for _ in range(3):
        assert client.get("/health").status_code == 200
    response = client.options(
        "/api/test",
        headers={"Origin": "https://allowed.example", "Access-Control-Request-Method": "GET"},
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://allowed.example"


def test_cors_does_not_authorize_unlisted_origin():
    client = TestClient(app_with_limit(10))
    response = client.get("/api/test", headers={"Origin": "https://denied.example"})
    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers
