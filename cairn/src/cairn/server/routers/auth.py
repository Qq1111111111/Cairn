from __future__ import annotations

from fastapi import APIRouter, Request, Response

from cairn.server.auth import AUTH
from cairn.server.models import LoginRequest, SessionResponse

router = APIRouter(tags=["auth"])


@router.get("/auth/session", response_model=SessionResponse)
def get_session(request: Request):
    return SessionResponse(**AUTH.session_payload(request))


@router.post("/auth/login", response_model=SessionResponse)
def login(body: LoginRequest, request: Request, response: Response):
    username = AUTH.login(request, response, body.username, body.password)
    return SessionResponse(enabled=AUTH.enabled, authenticated=True, username=username)


@router.post("/auth/logout", response_model=SessionResponse)
def logout(request: Request, response: Response):
    AUTH.logout(request, response)
    return SessionResponse(enabled=AUTH.enabled, authenticated=False, username=None)
