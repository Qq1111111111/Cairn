from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
import json
from pathlib import Path

from cairn.server.models import ProjectFileEntry, TrafficRecordDetail, TrafficRecordSummary
from cairn.server.project_files import project_root_dir, resolve_project_relative_path

router = APIRouter(tags=["traffic"])

INDEX_FILE = "traffic/index.jsonl"


def _traffic_index_path(project_id: str) -> Path:
    return project_root_dir(project_id) / INDEX_FILE


def _iter_traffic_rows(project_id: str):
    index_path = _traffic_index_path(project_id)
    if not index_path.exists():
        return
    with index_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            text = line.strip()
            if not text:
                continue
            yield json.loads(text)


def _record_path(project_id: str, traffic_id: str) -> Path:
    return project_root_dir(project_id) / "traffic" / "records" / f"{traffic_id}.json"


def _match_summary(row: dict[str, object], query: str) -> tuple[str | None, str | None]:
    fields = (
        ("url", row.get("url")),
        ("host", row.get("host")),
        ("path", row.get("path")),
        ("method", row.get("method")),
        ("raw_request", row.get("raw_request")),
        ("raw_response", row.get("raw_response")),
    )
    needle = query.lower()
    for field, value in fields:
        text = str(value or "")
        if needle not in text.lower():
            continue
        index = text.lower().find(needle)
        start = max(0, index - 60)
        end = min(len(text), index + len(query) + 60)
        excerpt = text[start:end].replace("\r", " ").replace("\n", " ")
        return field, excerpt
    return None, None


@router.get("/projects/{project_id}/traffic", response_model=list[TrafficRecordSummary])
def search_traffic(project_id: str, q: str = "", limit: int = 100):
    items: list[TrafficRecordSummary] = []
    query = q.strip()
    for row in _iter_traffic_rows(project_id) or []:
        matched_field = None
        matched_excerpt = None
        if query:
            matched_field, matched_excerpt = _match_summary(row, query)
            if not matched_field:
                continue
        items.append(
            TrafficRecordSummary(
                id=row["id"],
                timestamp=row["timestamp"],
                scheme=row["scheme"],
                host=row["host"],
                port=row["port"],
                method=row["method"],
                path=row["path"],
                url=row["url"],
                status_code=row.get("status_code"),
                matched_field=matched_field,
                matched_excerpt=matched_excerpt,
            )
        )
        if len(items) >= max(1, min(limit, 500)):
            break
    return items


@router.get("/projects/{project_id}/traffic/{traffic_id}", response_model=TrafficRecordDetail)
def get_traffic_detail(project_id: str, traffic_id: str):
    record_path = _record_path(project_id, traffic_id)
    if not record_path.exists():
        raise HTTPException(404, "Traffic record not found")
    payload = json.loads(record_path.read_text(encoding="utf-8"))
    return TrafficRecordDetail(**payload)


@router.get("/projects/{project_id}/files", response_model=list[ProjectFileEntry])
def list_project_files(project_id: str, prefix: str = ""):
    base = project_root_dir(project_id)
    target = resolve_project_relative_path(project_id, prefix) if prefix else base
    if not target.exists():
        return []
    entries: list[ProjectFileEntry] = []
    for child in sorted(target.iterdir(), key=lambda item: (item.is_file(), item.name.lower())):
        rel = child.relative_to(base).as_posix()
        entries.append(
            ProjectFileEntry(
                path=rel,
                name=child.name,
                kind="directory" if child.is_dir() else "file",
                size=None if child.is_dir() else child.stat().st_size,
            )
        )
    return entries


@router.get("/projects/{project_id}/files/{relative_path:path}")
def read_project_file(project_id: str, relative_path: str):
    path = resolve_project_relative_path(project_id, relative_path)
    if not path.exists() or not path.is_file():
        raise HTTPException(404, "Project file not found")
    return FileResponse(path)
