from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response

from cairn.server.auth import (
    AuthLoginError,
    build_auth_status,
    clear_auth_cookie,
    extract_session_token,
    login_with_password,
    logout_with_token,
    set_auth_cookie,
)
from cairn.server.db import get_conn
from cairn.server.models import AuthLoginRequest, AuthStatus

router = APIRouter(tags=["auth"])


@router.get("/auth/me", response_model=AuthStatus)
def auth_me(request: Request):
    with get_conn() as conn:
        enabled = bool(getattr(request.app.state, "auth_enabled", False))
        return build_auth_status(
            conn,
            enabled=enabled,
            session_token=extract_session_token(request),
        )


@router.post("/auth/login", response_model=AuthStatus)
def auth_login(body: AuthLoginRequest, request: Request, response: Response):
    enabled = bool(getattr(request.app.state, "auth_enabled", False))
    if not enabled:
        return AuthStatus(enabled=False, authenticated=True)

    with get_conn() as conn:
        try:
            status, session_token = login_with_password(
                conn,
                username=body.username,
                password=body.password,
            )
        except AuthLoginError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

        set_auth_cookie(response, session_token)
        return status


@router.post("/auth/logout", response_model=AuthStatus)
def auth_logout(request: Request, response: Response):
    enabled = bool(getattr(request.app.state, "auth_enabled", False))
    with get_conn() as conn:
        status = logout_with_token(
            conn,
            enabled=enabled,
            session_token=extract_session_token(request),
        )
    clear_auth_cookie(response)
    return status
