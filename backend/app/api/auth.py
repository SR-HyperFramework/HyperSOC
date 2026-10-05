from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool

from app.core.auth import Principal, audit, check_password, issue_session, verify_session
from app.core.config import settings
from app.core.database import get_db
from app.models.identity import AuditEvent, SOCUser

router = APIRouter(prefix="/api/v1/auth", tags=["identity"])
_DUMMY_PASSWORD_HASH = "pbkdf2_sha256$600000$" + "00" * 16 + "$" + "00" * 32


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


@router.post("/login")
async def login(payload: LoginRequest, request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    user = await db.scalar(select(SOCUser).where(SOCUser.username == payload.username.casefold(), SOCUser.active.is_(True)))
    valid = await run_in_threadpool(check_password, payload.password, user.password_hash if user else _DUMMY_PASSWORD_HASH)
    if user is None or not valid:
        raise HTTPException(401, "Invalid username or password")
    token, csrf = issue_session(user)
    response.set_cookie("soc_session", token, max_age=settings.auth_session_seconds, httponly=True, secure=request.url.scheme == "https", samesite="strict", path="/")
    db.info["soc_principal"] = Principal(user.id, user.username, user.role)
    audit(db, "session.login", str(user.id), actor=user.username)
    await db.commit()
    return {"access_token": token, "token_type": "bearer", "csrf_token": csrf, "username": user.username, "role": user.role}


@router.get("/me")
async def me(request: Request):
    principal = getattr(request.state, "principal", None)
    csrf = None
    if principal and "soc_session" in request.cookies:
        try:
            csrf = verify_session(request.cookies["soc_session"]).get("csrf")
        except ValueError:
            pass
    return {"username": principal.username if principal else "lab", "role": principal.role if principal else "admin", "authenticated": principal is not None, "csrf_token": csrf}


@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie("soc_session", path="/")
    return {"status": "logged_out"}


@router.get("/audit")
async def list_audit(request: Request, db: AsyncSession = Depends(get_db)):
    principal = getattr(request.state, "principal", None)
    if settings.auth_enabled and (principal is None or principal.role != "admin"):
        raise HTTPException(403, "Admin role required")
    records = (await db.scalars(select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(100))).all()
    return [{key: getattr(row, key) for key in ("id", "actor", "role", "operation", "resource", "details", "created_at")} for row in records]
