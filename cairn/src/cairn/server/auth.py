from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
import hashlib
import hmac
import logging
import secrets

import yaml

from cairn.server.models import AuthStatus

LOG = logging.getLogger(__name__)

AUTH_COOKIE_NAME = "cairn_session"
AUTH_SESSION_TTL_SECONDS = 12 * 60 * 60
AUTH_LOCK_SECONDS = 2 * 60 * 60
AUTH_LOCK_FAILURES = 5
PASSWORD_HASH_ITERATIONS = 210_000
PASSWORD_HASH_NAME = "sha256"


@dataclass(slots=True)
class WebAuthConfig:
    username: str
    password: str


def load_web_auth_config(path: Path) -> WebAuthConfig | None:
    if not path.exists():
        return None
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        LOG.warning("web auth config load failed path=%s error=%s", path, exc)
        return None
    if not isinstance(data, dict):
        return None
    username = _clean_text(
        data.get("WEB_USERNAME")
        or data.get("LOGIN_USERNAME")
        or data.get("WEB_USER")
    )
    password = _clean_text(
        data.get("WEB_PASSWORD")
        or data.get("LOGIN_PASSWORD")
        or data.get("WEB_PASS")
    )
    if not username or not password:
        return None
    return WebAuthConfig(username=username, password=password)


def sync_web_auth_user(
    conn,
    config: WebAuthConfig,
    *,
    now: str | None = None,
) -> None:
    now = now or utcnow()
    conn.execute("DELETE FROM auth_users WHERE username != ?", (config.username,))
    row = conn.execute(
        "SELECT * FROM auth_users WHERE username = ?",
        (config.username,),
    ).fetchone()
    if row is None:
        salt = _new_salt()
        conn.execute(
            """
            INSERT INTO auth_users (
                username, password_salt, password_hash,
                failed_attempts, locked_until, created_at, updated_at
            ) VALUES (?, ?, ?, 0, NULL, ?, ?)
            """,
            (
                config.username,
                salt,
                _hash_password(config.password, salt),
                now,
                now,
            ),
        )
        return

    if _verify_password(config.password, row["password_salt"], row["password_hash"]):
        conn.execute(
            "UPDATE auth_users SET updated_at = ? WHERE username = ?",
            (now, config.username),
        )
        return

    salt = _new_salt()
    conn.execute(
        """
        UPDATE auth_users
        SET password_salt = ?,
            password_hash = ?,
            failed_attempts = 0,
            locked_until = NULL,
            updated_at = ?
        WHERE username = ?
        """,
        (salt, _hash_password(config.password, salt), now, config.username),
    )
    conn.execute("DELETE FROM auth_sessions WHERE username = ?", (config.username,))


def build_auth_status(
    conn,
    *,
    enabled: bool,
    session_token: str | None = None,
    now: str | None = None,
) -> AuthStatus:
    if not enabled:
        return AuthStatus(enabled=False, authenticated=True)

    now = now or utcnow()
    user_row = _current_auth_user(conn)
    if user_row is None:
        return AuthStatus(
            enabled=True,
            authenticated=False,
            message="尚未配置登录账号",
        )

    user_row = _refresh_lock_state(conn, user_row, now)
    session_row = _current_session(conn, session_token, now) if session_token else None
    if session_row is not None:
        return AuthStatus(
            enabled=True,
            authenticated=True,
            username=session_row["username"],
            expires_at=session_row["expires_at"],
        )

    locked_until = _clean_text(user_row["locked_until"])
    message = "请先登录"
    if locked_until:
        message = f"账号已锁定，解锁时间：{locked_until}"
    return AuthStatus(
        enabled=True,
        authenticated=False,
        locked_until=locked_until,
        message=message,
    )


def login_with_password(
    conn,
    *,
    username: str,
    password: str,
    now: str | None = None,
) -> tuple[AuthStatus, str]:
    now = now or utcnow()
    user_row = _current_auth_user(conn)
    if user_row is None:
        raise ValueError("web auth is not configured")

    if username != user_row["username"]:
        raise AuthLoginError("账号或密码错误", status_code=401)

    user_row = _refresh_lock_state(conn, user_row, now)
    locked_until = _clean_text(user_row["locked_until"])
    if locked_until:
        raise AuthLoginError(
            f"账号已锁定，请在 {locked_until} 后重试",
            status_code=423,
        )

    if not _verify_password(password, user_row["password_salt"], user_row["password_hash"]):
        failed_attempts = int(user_row["failed_attempts"]) + 1
        if failed_attempts >= AUTH_LOCK_FAILURES:
            lock_until = _to_iso(_parse_iso(now) + timedelta(seconds=AUTH_LOCK_SECONDS))
            conn.execute(
                """
                UPDATE auth_users
                SET failed_attempts = 0,
                    locked_until = ?,
                    updated_at = ?
                WHERE username = ?
                """,
                (lock_until, now, user_row["username"]),
            )
            raise AuthLoginError(
                f"账号已锁定，请在 {lock_until} 后重试",
                status_code=423,
            )

        conn.execute(
            """
            UPDATE auth_users
            SET failed_attempts = ?,
                updated_at = ?
            WHERE username = ?
            """,
            (failed_attempts, now, user_row["username"]),
        )
        raise AuthLoginError("账号或密码错误", status_code=401)

    session_token, expires_at = _create_session(conn, user_row["username"], now)
    conn.execute(
        """
        UPDATE auth_users
        SET failed_attempts = 0,
            locked_until = NULL,
            updated_at = ?
        WHERE username = ?
        """,
        (now, user_row["username"]),
    )
    return (
        AuthStatus(
            enabled=True,
            authenticated=True,
            username=user_row["username"],
            expires_at=expires_at,
        ),
        session_token,
    )


def logout_with_token(
    conn,
    *,
    enabled: bool,
    session_token: str | None,
    now: str | None = None,
) -> AuthStatus:
    now = now or utcnow()
    if session_token:
        conn.execute("DELETE FROM auth_sessions WHERE token = ?", (session_token,))
    return build_auth_status(conn, enabled=enabled, now=now)


def clear_expired_sessions(conn, *, now: str | None = None) -> None:
    now = now or utcnow()
    conn.execute("DELETE FROM auth_sessions WHERE expires_at <= ?", (now,))


def extract_session_token(request) -> str | None:
    return _clean_text(request.cookies.get(AUTH_COOKIE_NAME))


def resolve_authenticated_username(
    conn,
    *,
    enabled: bool,
    session_token: str | None,
    now: str | None = None,
) -> str | None:
    if not enabled or not session_token:
        return None
    session_row = _current_session(conn, session_token, now or utcnow())
    return None if session_row is None else session_row["username"]


def set_auth_cookie(response, session_token: str) -> None:
    response.set_cookie(
        AUTH_COOKIE_NAME,
        session_token,
        max_age=AUTH_SESSION_TTL_SECONDS,
        httponly=True,
        samesite="lax",
        path="/",
    )


def clear_auth_cookie(response) -> None:
    response.delete_cookie(AUTH_COOKIE_NAME, path="/")


class AuthLoginError(Exception):
    def __init__(self, message: str, *, status_code: int = 401):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def utcnow() -> str:
    return _to_iso(datetime.now(timezone.utc))


def _create_session(conn, username: str, now: str) -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    expires_at = _to_iso(_parse_iso(now) + timedelta(seconds=AUTH_SESSION_TTL_SECONDS))
    conn.execute(
        """
        INSERT INTO auth_sessions (token, username, expires_at, created_at, last_seen_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (token, username, expires_at, now, now),
    )
    clear_expired_sessions(conn, now=now)
    return token, expires_at


def _current_auth_user(conn):
    clear_expired_sessions(conn)
    return conn.execute(
        "SELECT * FROM auth_users ORDER BY created_at LIMIT 1",
    ).fetchone()


def _refresh_lock_state(conn, row, now: str):
    locked_until = _clean_text(row["locked_until"])
    if not locked_until:
        return row
    try:
        locked_dt = _parse_iso(locked_until)
    except ValueError:
        return row
    if locked_dt > _parse_iso(now):
        return row
    conn.execute(
        """
        UPDATE auth_users
        SET failed_attempts = 0,
            locked_until = NULL,
            updated_at = ?
        WHERE username = ?
        """,
        (now, row["username"]),
    )
    return conn.execute(
        "SELECT * FROM auth_users WHERE username = ?",
        (row["username"],),
    ).fetchone()


def _current_session(conn, token: str | None, now: str):
    if not token:
        return None
    clear_expired_sessions(conn, now=now)
    row = conn.execute(
        """
        SELECT token, username, expires_at, created_at, last_seen_at
        FROM auth_sessions
        WHERE token = ? AND expires_at > ?
        """,
        (token, now),
    ).fetchone()
    if row is None:
        conn.execute("DELETE FROM auth_sessions WHERE token = ?", (token,))
    return row


def _hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        PASSWORD_HASH_NAME,
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PASSWORD_HASH_ITERATIONS,
    ).hex()


def _verify_password(password: str, salt: str, expected_hash: str) -> bool:
    actual = _hash_password(password, salt)
    return hmac.compare_digest(actual, expected_hash)


def _new_salt() -> str:
    return secrets.token_hex(16)


def _clean_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _to_iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
