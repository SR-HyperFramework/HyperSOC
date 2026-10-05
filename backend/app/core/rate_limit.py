from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response


@dataclass
class _Window:
    started_at: float
    requests: int


class InMemoryRateLimiter:
    """Per-process fixed-window limiter keyed by the direct client address."""

    def __init__(self, requests_per_minute: int, *, clock: Callable[[], float] = time.monotonic) -> None:
        if requests_per_minute <= 0:
            raise ValueError("requests_per_minute must be positive")
        self.requests_per_minute = requests_per_minute
        self.clock = clock
        self._windows: dict[str, _Window] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> tuple[bool, int, int]:
        now = self.clock()
        with self._lock:
            window = self._windows.get(key)
            if window is None or now - window.started_at >= 60:
                window = _Window(started_at=now, requests=0)
                self._windows[key] = window
            if window.requests >= self.requests_per_minute:
                retry_after = max(1, math.ceil(60 - (now - window.started_at)))
                return False, 0, retry_after
            window.requests += 1
            remaining = self.requests_per_minute - window.requests
            retry_after = max(1, math.ceil(60 - (now - window.started_at)))
            return True, remaining, retry_after


class RateLimitMiddleware(BaseHTTPMiddleware):
    EXCLUDED_PATHS = frozenset({"/health", "/ready", "/docs", "/redoc", "/openapi.json"})

    def __init__(self, app, *, limiter: InMemoryRateLimiter) -> None:
        super().__init__(app)
        self.limiter = limiter

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.method == "OPTIONS" or request.url.path in self.EXCLUDED_PATHS:
            return await call_next(request)
        client = request.client.host if request.client else "unknown"
        allowed, remaining, retry_after = self.limiter.check(client)
        headers = {
            "X-RateLimit-Limit": str(self.limiter.requests_per_minute),
            "X-RateLimit-Remaining": str(remaining),
        }
        if not allowed:
            headers["Retry-After"] = str(retry_after)
            return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"}, headers=headers)
        response = await call_next(request)
        response.headers.update(headers)
        return response
