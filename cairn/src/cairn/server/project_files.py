from __future__ import annotations

import os
from pathlib import Path
import shutil

PROJECT_FILES_ENV = "CAIRN_PROJECT_FILES_DIR"


def project_files_root() -> Path:
    raw = os.getenv(PROJECT_FILES_ENV)
    if raw:
        return Path(raw).expanduser().resolve()
    return (Path.cwd() / "worker-project-files").resolve()


def project_root_dir(project_id: str) -> Path:
    return project_files_root() / project_id


def ensure_project_files_root() -> Path:
    root = project_files_root()
    root.mkdir(parents=True, exist_ok=True)
    return root


def delete_project_root(project_id: str) -> None:
    root = project_root_dir(project_id)
    if root.exists():
        shutil.rmtree(root)


def resolve_project_relative_path(project_id: str, relative_path: str) -> Path:
    project_root = project_root_dir(project_id).resolve()
    candidate = (project_root / relative_path).resolve()
    if project_root != candidate and project_root not in candidate.parents:
        raise ValueError("invalid project file path")
    return candidate
