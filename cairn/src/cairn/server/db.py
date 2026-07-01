from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

DEFAULT_DB = Path.home() / ".local" / "share" / "cairn" / "cairn.db"

_db_path: Path | None = None

SCHEMA = """\
CREATE TABLE IF NOT EXISTS settings (
    intent_timeout INTEGER NOT NULL DEFAULT 15,
    reason_timeout INTEGER NOT NULL DEFAULT 15
);

INSERT OR IGNORE INTO settings (rowid, intent_timeout, reason_timeout) VALUES (1, 15, 15);

CREATE TABLE IF NOT EXISTS auth_users (
    username TEXT PRIMARY KEY,
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    token TEXT PRIMARY KEY,
    username TEXT NOT NULL REFERENCES auth_users(username) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT '未分类',
    status TEXT NOT NULL DEFAULT 'active',
    bootstrap_enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    reason_worker TEXT,
    reason_trigger TEXT,
    reason_started_at TEXT,
    reason_last_heartbeat_at TEXT
);

CREATE TABLE IF NOT EXISTS facts (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    description TEXT NOT NULL,
    PRIMARY KEY (id, project_id)
);

CREATE TABLE IF NOT EXISTS fact_provenance (
    project_id TEXT NOT NULL,
    fact_id TEXT NOT NULL,
    scheme TEXT,
    host TEXT,
    port INTEGER,
    method TEXT,
    path TEXT,
    url TEXT,
    interface_label TEXT,
    repro_command TEXT,
    evidence_files_json TEXT NOT NULL DEFAULT '[]',
    traffic_ids_json TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (project_id, fact_id),
    FOREIGN KEY (fact_id, project_id) REFERENCES facts(id, project_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS intents (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    to_fact_id TEXT,
    description TEXT NOT NULL,
    creator TEXT NOT NULL,
    worker TEXT,
    last_heartbeat_at TEXT,
    created_at TEXT NOT NULL,
    concluded_at TEXT,
    PRIMARY KEY (id, project_id)
);

CREATE TABLE IF NOT EXISTS reports (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    intent_id TEXT NOT NULL,
    fact_id TEXT NOT NULL,
    worker TEXT NOT NULL,
    source_fact_ids TEXT NOT NULL,
    request_packet TEXT NOT NULL,
    response_packet TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (id, project_id),
    FOREIGN KEY (intent_id, project_id) REFERENCES intents(id, project_id) ON DELETE CASCADE,
    FOREIGN KEY (fact_id, project_id) REFERENCES facts(id, project_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS intent_sources (
    intent_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    fact_id TEXT NOT NULL,
    PRIMARY KEY (intent_id, project_id, fact_id),
    FOREIGN KEY (intent_id, project_id) REFERENCES intents(id, project_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS hints (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    creator TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (id, project_id)
);

CREATE TABLE IF NOT EXISTS counters (
    name TEXT PRIMARY KEY,
    value INTEGER NOT NULL DEFAULT 0
);

INSERT OR IGNORE INTO counters (name, value) VALUES ('project', 0);

CREATE TABLE IF NOT EXISTS scoped_counters (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    value INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, kind)
);

CREATE TABLE IF NOT EXISTS timeline_prompts (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    timeline_entry_id TEXT NOT NULL,
    intent_id TEXT,
    phase TEXT NOT NULL,
    worker TEXT NOT NULL,
    prompt_text TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (project_id, timeline_entry_id),
    FOREIGN KEY (intent_id, project_id) REFERENCES intents(id, project_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    session_id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    user_agent TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS auth_login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    success INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
"""


def configure(path: Path) -> None:
    global _db_path
    if _db_path is not None:
        return
    _db_path = path
    _db_path.parent.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        conn.executescript(SCHEMA)
        _ensure_project_columns(conn)


def _ensure_project_columns(conn: sqlite3.Connection) -> None:
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(projects)")}
    if "category" not in columns:
        conn.execute("ALTER TABLE projects ADD COLUMN category TEXT NOT NULL DEFAULT '未分类'")
    if "bootstrap_enabled" not in columns:
        conn.execute("ALTER TABLE projects ADD COLUMN bootstrap_enabled INTEGER NOT NULL DEFAULT 1")
        if "bootstrap_mode" in columns:
            conn.execute(
                "UPDATE projects SET bootstrap_enabled = CASE WHEN bootstrap_mode = 'disabled' THEN 0 ELSE 1 END"
            )
    conn.execute(
        "UPDATE projects SET category = '未分类' WHERE category IS NULL OR trim(category) = ''"
    )


@contextmanager
def get_conn() -> Generator[sqlite3.Connection, None, None]:
    assert _db_path is not None
    conn = sqlite3.connect(str(_db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
