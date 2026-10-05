"""Signed expiring sessions, database-backed roles, and cookie CSRF protection."""
import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from uuid import UUID, uuid4

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.config import settings
from app.models.identity import AuditEvent, SOCUser


@dataclass(frozen=True)
class Principal:
    user_id: UUID
    username: str
    role: str


def password_hash(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 600_000).hex()
    return f"pbkdf2_sha256$600000${salt}${digest}"


def check_password(password: str, stored: str) -> bool:
    try:
        algorithm, iterations, salt, expected = stored.split("$")
        if algorithm != "pbkdf2_sha256" or not 100_000 <= int(iterations) <= 1_000_000:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iterations)).hex()
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def issue_session(user: SOCUser) -> tuple[str, str]:
    csrf = secrets.token_urlsafe(24)
    payload = {"sub": str(user.id), "exp": int(time.time()) + settings.auth_session_seconds,
        "csrf": csrf, "credential_version": hashlib.sha256(user.password_hash.encode()).hexdigest()}
    body = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    signature = hmac.new(settings.app_secret_key.encode(), body.encode(), hashlib.sha256).hexdigest()
    return body + "." + signature, csrf


def verify_session(token: str) -> dict:
    try:
        if len(token) > 4096:
            raise ValueError("invalid token")
        body, signature = token.split(".")
        expected = hmac.new(settings.app_secret_key.encode(), body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise ValueError("invalid signature")
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        if not isinstance(payload, dict) or not isinstance(payload.get("exp"), int) or payload["exp"] <= time.time():
            raise ValueError("expired token")
        UUID(payload["sub"])
        return payload
    except (ValueError, KeyError, TypeError) as exc:
        raise ValueError("Invalid or expired session") from exc


def audit(db, operation: str, resource: str, *, actor: str = "system", details=None):
    principal = getattr(db, "info", {}).get("soc_principal")
    db.add(AuditEvent(id=uuid4(), actor=principal.username if principal else actor,
        role=principal.role if principal else "system", operation=operation, resource=resource, details=details or {}))


class SOCAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        signed_ingest = request.method == "POST" and path in {"/api/v1/alerts", "/api/v1/hub/events", "/api/v1/hub/native-events"}
        if not settings.auth_enabled or not path.startswith("/api/") or signed_ingest or path == "/api/v1/auth/login" or request.method == "OPTIONS":
            return await call_next(request)
        authorization = request.headers.get("Authorization", "")
        bearer = authorization.startswith("Bearer ")
        token = authorization[7:] if bearer else request.cookies.get("soc_session", "")
        try:
            payload = verify_session(token)
        except ValueError:
            return JSONResponse({"detail": "Authentication required"}, status_code=401)
        from app.core.database import async_session_factory
        async with async_session_factory() as db:
            user = await db.get(SOCUser, UUID(payload["sub"]))
            if user is None or not user.active or user.role not in {"viewer", "analyst", "admin"}:
                return JSONResponse({"detail": "Account is inactive or unavailable"}, status_code=401)
            if not hmac.compare_digest(payload.get("credential_version", ""), hashlib.sha256(user.password_hash.encode()).hexdigest()):
                return JSONResponse({"detail": "Session was revoked"}, status_code=401)
            principal = Principal(user.id, user.username, user.role)
        read_query = request.method == "POST" and path == "/api/v1/hub/search"
        mutation = request.method not in {"GET", "HEAD"} and not read_query
        if mutation and not bearer:
            csrf = request.headers.get("X-SOC-CSRF", "")
            if not csrf or not hmac.compare_digest(csrf, payload.get("csrf", "")):
                return JSONResponse({"detail": "CSRF token required"}, status_code=403)
            origin = request.headers.get("Origin")
            if origin and origin not in settings.cors_origins():
                return JSONResponse({"detail": "Origin is not permitted"}, status_code=403)
        admin_mutation = mutation and (path.startswith("/api/v1/hub/") or path == "/api/v1/knowledge/index")
        if mutation and (principal.role == "viewer" or (admin_mutation and principal.role != "admin")):
            return JSONResponse({"detail": "Insufficient SOC role"}, status_code=403)
        request.state.principal = principal
        return await call_next(request)
