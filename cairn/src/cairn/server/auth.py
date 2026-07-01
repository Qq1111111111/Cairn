from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
import secrets
import sqlite3
from typing import Callable

from fastapi import HTTPException, Request, Response

from cairn.server.db import get_conn

AUTH_USERNAME_ENV = "CAIRN_AUTH_USERNAME"
AUTH_PASSWORD_ENV = "CAIRN_AUTH_PASSWORD"
AUTH_SESSION_SECRET_ENV = "CAIRN_SESSION_SECRET"
AUTH_INTERNAL_TOKEN_ENV = "CAIRN_INTERNAL_TOKEN"
AUTH_COOKIE_NAME = "cairn_session"
SESSION_TTL_HOURS = 12
FAILED_WINDOW_MINUTES = 15
FAILED_MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 30


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _format_ts(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    client = request.client
    return client.host if client else "unknown"


@dataclass(slots=True)
class AuthSession:
    session_id: str
    username: str
    expires_at: str


class AuthManager:
    def __init__(self) -> None:
        self.username = (os.getenv(AUTH_USERNAME_ENV) or "").strip()
        self.password = os.getenv(AUTH_PASSWORD_ENV) or ""
        self.session_secret = os.getenv(AUTH_SESSION_SECRET_ENV) or ""
        self.internal_token = os.getenv(AUTH_INTERNAL_TOKEN_ENV) or ""
        self.enabled = bool(self.username and self.password and self.session_secret)

    def require_auth(self, request: Request) -> str | None:
        if not self.enabled:
            return None
        cookie_value = request.cookies.get(AUTH_COOKIE_NAME)
        if not cookie_value:
            raise HTTPException(401, "Authentication required")
        session_id = self._verify_cookie(cookie_value)
        if not session_id:
            raise HTTPException(401, "Authentication required")
        with get_conn() as conn:
            row = conn.execute(
                """
                SELECT session_id, username, expires_at
                FROM auth_sessions
                WHERE session_id = ?
                """,
                (session_id,),
            ).fetchone()
            if row is None:
                raise HTTPException(401, "Authentication required")
            expires_at = _parse_ts(row["expires_at"])
            if expires_at is None or expires_at <= _utcnow():
                conn.execute("DELETE FROM auth_sessions WHERE session_id = ?", (session_id,))
                raise HTTPException(401, "Authentication required")
            conn.execute(
                "UPDATE auth_sessions SET last_seen_at = ? WHERE session_id = ?",
                (_format_ts(_utcnow()), session_id),
            )
            return row["username"]

    def login(self, request: Request, response: Response, username: str, password: str) -> str:
        if not self.enabled:
            return "auth-disabled"
        ip_address = _client_ip(request)
        self._check_lockout(ip_address, username)
        valid = hmac.compare_digest(username, self.username) and hmac.compare_digest(password, self.password)
        with get_conn() as conn:
            conn.execute(
                """
                INSERT INTO auth_login_attempts (username, ip_address, success, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (username, ip_address, 1 if valid else 0, _format_ts(_utcnow())),
            )
        if not valid:
            self._check_lockout(ip_address, username, post_failure=True)
            raise HTTPException(401, "用户名或密码错误")
        session = self._create_session(username, ip_address, request.headers.get("user-agent"))
        response.set_cookie(
            AUTH_COOKIE_NAME,
            self._sign_cookie(session.session_id),
            httponly=True,
            samesite="strict",
            secure=False,
            max_age=SESSION_TTL_HOURS * 3600,
            path="/",
        )
        return username

    def logout(self, request: Request, response: Response) -> None:
        if self.enabled:
            cookie_value = request.cookies.get(AUTH_COOKIE_NAME)
            session_id = self._verify_cookie(cookie_value) if cookie_value else None
            if session_id:
                with get_conn() as conn:
                    conn.execute("DELETE FROM auth_sessions WHERE session_id = ?", (session_id,))
        response.delete_cookie(AUTH_COOKIE_NAME, path="/")

    def session_payload(self, request: Request) -> dict[str, object]:
        if not self.enabled:
            return {"enabled": False, "authenticated": True, "username": None}
        try:
            username = self.require_auth(request)
        except HTTPException:
            return {"enabled": True, "authenticated": False, "username": None}
        return {"enabled": True, "authenticated": True, "username": username}

    def _create_session(self, username: str, ip_address: str, user_agent: str | None) -> AuthSession:
        now = _utcnow()
        session = AuthSession(
            session_id=secrets.token_urlsafe(32),
            username=username,
            expires_at=_format_ts(now + timedelta(hours=SESSION_TTL_HOURS)),
        )
        with get_conn() as conn:
            conn.execute(
                """
                INSERT INTO auth_sessions (
                    session_id, username, created_at, expires_at, last_seen_at, ip_address, user_agent
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session.session_id,
                    session.username,
                    _format_ts(now),
                    session.expires_at,
                    _format_ts(now),
                    ip_address,
                    user_agent or "",
                ),
            )
        return session

    def _check_lockout(self, ip_address: str, username: str, *, post_failure: bool = False) -> None:
        with get_conn() as conn:
            window_start = _format_ts(_utcnow() - timedelta(minutes=FAILED_WINDOW_MINUTES))
            rows = conn.execute(
                """
                SELECT username, ip_address, success, created_at
                FROM auth_login_attempts
                WHERE created_at >= ?
                  AND success = 0
                  AND (ip_address = ? OR username = ?)
                ORDER BY created_at DESC
                """,
                (window_start, ip_address, username),
            ).fetchall()
        if len(rows) < FAILED_MAX_ATTEMPTS:
            return
        latest = _parse_ts(rows[0]["created_at"])
        if latest is None:
            return
        locked_until = latest + timedelta(minutes=LOCKOUT_MINUTES)
        if locked_until <= _utcnow():
            return
        if post_failure:
            raise HTTPException(429, f"登录失败次数过多，请在 {locked_until.astimezone().strftime('%Y-%m-%d %H:%M:%S')} 后重试")
        raise HTTPException(429, f"登录暂时锁定，请在 {locked_until.astimezone().strftime('%Y-%m-%d %H:%M:%S')} 后重试")

    def _sign_cookie(self, session_id: str) -> str:
        signature = hmac.new(
            self.session_secret.encode("utf-8"),
            session_id.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return f"{session_id}.{signature}"

    def _verify_cookie(self, cookie_value: str | None) -> str | None:
        if not cookie_value:
            return None
        session_id, dot, signature = cookie_value.partition(".")
        if not session_id or not dot or not signature:
            return None
        expected = hmac.new(
            self.session_secret.encode("utf-8"),
            session_id.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        return session_id


AUTH = AuthManager()


def require_authenticated_user(request: Request) -> str | None:
    return AUTH.require_auth(request)


def protected_route(path: str) -> bool:
    if path == "/" or path.startswith("/static/") or path.startswith("/auth/"):
        return False
    return True


def request_uses_internal_token(request: Request) -> bool:
    if not AUTH.internal_token:
        return False
    token = request.headers.get("x-cairn-internal-token", "")
    return bool(token) and hmac.compare_digest(token, AUTH.internal_token)
