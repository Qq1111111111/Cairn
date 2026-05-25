from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException

from cairn.reporting import build_fallback_report_from_conclusion
from cairn.server.models import Intent, ProjectMeta, ProjectReason, Report


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def next_project_id(conn: sqlite3.Connection) -> str:
    conn.execute("UPDATE counters SET value = value + 1 WHERE name = 'project'")
    row = conn.execute("SELECT value FROM counters WHERE name = 'project'").fetchone()
    return f"proj_{row['value']:03d}"


def _next_scoped_id(
    conn: sqlite3.Connection, kind: str, prefix: str, project_id: str
) -> str:
    conn.execute(
        "INSERT OR IGNORE INTO scoped_counters (project_id, kind, value) VALUES (?, ?, 0)",
        (project_id, kind),
    )
    conn.execute(
        "UPDATE scoped_counters SET value = value + 1 WHERE project_id = ? AND kind = ?",
        (project_id, kind),
    )
    row = conn.execute(
        "SELECT value FROM scoped_counters WHERE project_id = ? AND kind = ?",
        (project_id, kind),
    ).fetchone()
    assert row is not None
    return f"{prefix}{row['value']:03d}"


def next_fact_id(conn: sqlite3.Connection, project_id: str) -> str:
    return _next_scoped_id(conn, "fact", "f", project_id)


def next_intent_id(conn: sqlite3.Connection, project_id: str) -> str:
    return _next_scoped_id(conn, "intent", "i", project_id)


def next_hint_id(conn: sqlite3.Connection, project_id: str) -> str:
    return _next_scoped_id(conn, "hint", "h", project_id)


def next_report_id(conn: sqlite3.Connection, project_id: str) -> str:
    return _next_scoped_id(conn, "report", "r", project_id)


def get_project_or_404(conn: sqlite3.Connection, project_id: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "Project not found")
    return row


def check_project_active(conn: sqlite3.Connection, project_id: str) -> sqlite3.Row:
    row = get_project_or_404(conn, project_id)
    if row["status"] != "active":
        raise HTTPException(403, f"Project is {row['status']}")
    return row


def check_project_hint_writable(conn: sqlite3.Connection, project_id: str) -> sqlite3.Row:
    row = get_project_or_404(conn, project_id)
    if row["status"] not in ("active", "stopped", "completed"):
        raise HTTPException(403, f"Project is {row['status']}")
    return row


def check_project_completed(conn: sqlite3.Connection, project_id: str) -> sqlite3.Row:
    row = get_project_or_404(conn, project_id)
    if row["status"] != "completed":
        raise HTTPException(403, f"Project is {row['status']}")
    return row


def validate_facts_exist(
    conn: sqlite3.Connection, project_id: str, fact_ids: list[str]
) -> None:
    for fid in fact_ids:
        row = conn.execute(
            "SELECT 1 FROM facts WHERE id = ? AND project_id = ?", (fid, project_id)
        ).fetchone()
        if row is None:
            raise HTTPException(404, f"Fact {fid} not found")


def validate_goal_not_in_sources(fact_ids: list[str]) -> None:
    if "goal" in fact_ids:
        raise HTTPException(400, "goal cannot be used in from")


def validate_intent_creator_worker(creator: str, worker: str | None) -> None:
    if worker is not None and worker != creator:
        raise HTTPException(400, "worker must be null or equal to creator")


def get_intent_or_404(
    conn: sqlite3.Connection, project_id: str, intent_id: str
) -> sqlite3.Row:
    row = conn.execute(
        "SELECT * FROM intents WHERE id = ? AND project_id = ?",
        (intent_id, project_id),
    ).fetchone()
    if row is None:
        raise HTTPException(404, "Intent not found")
    return row


def get_claimable_open_intent_or_404(
    conn: sqlite3.Connection, project_id: str, intent_id: str, worker: str
) -> sqlite3.Row:
    expire_workers(conn, project_id)
    row = get_intent_or_404(conn, project_id, intent_id)
    if row["to_fact_id"] is not None:
        raise HTTPException(409, "Intent already concluded")
    if row["worker"] is not None and row["worker"] != worker:
        raise HTTPException(409, f"Intent is currently claimed by {row['worker']}")
    return row


def get_releasable_open_intent_or_404(
    conn: sqlite3.Connection, project_id: str, intent_id: str, worker: str
) -> sqlite3.Row:
    expire_workers(conn, project_id)
    row = get_intent_or_404(conn, project_id, intent_id)
    if row["to_fact_id"] is not None:
        raise HTTPException(409, "Intent already concluded")
    if row["worker"] is None:
        return row
    if row["worker"] != worker:
        raise HTTPException(409, f"Intent is currently claimed by {row['worker']}")
    return row


def get_completion_intent_or_409(conn: sqlite3.Connection, project_id: str) -> sqlite3.Row:
    rows = conn.execute(
        "SELECT * FROM intents WHERE project_id = ? AND to_fact_id = 'goal'",
        (project_id,),
    ).fetchall()
    if not rows:
        raise HTTPException(409, "Completed project is missing its completion intent")
    if len(rows) != 1:
        raise HTTPException(409, "Completed project has multiple completion intents")
    return rows[0]


def intent_to_model(conn: sqlite3.Connection, row: sqlite3.Row, project_id: str) -> Intent:
    sources = conn.execute(
        "SELECT fact_id FROM intent_sources WHERE intent_id = ? AND project_id = ? ORDER BY rowid",
        (row["id"], project_id),
    ).fetchall()
    return Intent(
        id=row["id"],
        **{"from": [s["fact_id"] for s in sources]},
        to=row["to_fact_id"],
        description=row["description"],
        creator=row["creator"],
        worker=row["worker"],
        last_heartbeat_at=row["last_heartbeat_at"],
        created_at=row["created_at"],
        concluded_at=row["concluded_at"],
    )


def build_intents(conn: sqlite3.Connection, project_id: str) -> list[Intent]:
    rows = conn.execute(
        "SELECT * FROM intents WHERE project_id = ? ORDER BY created_at",
        (project_id,),
    ).fetchall()
    return [intent_to_model(conn, r, project_id) for r in rows]


def _report_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        try:
            text = json.dumps(value, ensure_ascii=False)
        except TypeError:
            text = str(value)
    else:
        text = str(value)
    text = text.strip()
    return text or None


def _report_title_from_summary(summary: str, fallback: str = "未命名发现") -> str:
    text = " ".join(summary.split())
    if not text:
        return fallback
    cut = len(text)
    for sep in ("。", ".", "；", ";", "\n"):
        pos = text.find(sep)
        if pos > 0:
            cut = min(cut, pos)
    text = text[:cut].strip() or text
    chars = list(text)
    if len(chars) <= 36:
        return text
    return "".join(chars[:36]) + "..."


def _report_source_label(
    intent_id: str, fact_id: str, source_fact_ids: list[str]
) -> str:
    if source_fact_ids:
        source = " · ".join(source_fact_ids)
    else:
        source = "—"
    return f"来自结论 {intent_id} → {fact_id}，来源事实：{source}"


def _normalize_report_evidence(raw: Any) -> list[dict[str, Any]]:
    if raw is None:
        return []
    if isinstance(raw, str):
        text = raw.strip()
        return [{"kind": "code", "label": "证据", "content": text}] if text else []
    items = raw if isinstance(raw, list) else [raw]
    normalized: list[dict[str, Any]] = []
    for item in items:
        if isinstance(item, str):
            text = item.strip()
            if text:
                normalized.append({"kind": "code", "label": "证据", "content": text})
            continue
        if not isinstance(item, dict):
            continue
        kind = _report_text(item.get("kind") or item.get("type"))
        label = _report_text(item.get("label") or item.get("title"))
        content = _report_text(
            item.get("content")
            or item.get("text")
            or item.get("code")
            or item.get("snippet")
        )
        request_packet = _report_text(
            item.get("request_packet")
            or item.get("request")
            or item.get("request_data")
            or item.get("request_body")
        )
        response_packet = _report_text(
            item.get("response_packet")
            or item.get("response")
            or item.get("response_data")
            or item.get("response_body")
        )
        if not kind:
            if request_packet or response_packet:
                kind = "packet"
            elif content is not None:
                kind = "code"
        evidence_item: dict[str, Any] = {}
        if kind:
            evidence_item["kind"] = kind
        if label:
            evidence_item["label"] = label
        if content is not None:
            evidence_item["content"] = content
        if request_packet is not None:
            evidence_item["request_packet"] = request_packet
        if response_packet is not None:
            evidence_item["response_packet"] = response_packet
        if evidence_item:
            normalized.append(evidence_item)
    return normalized


def _normalize_report_findings(raw: Any, fallback_source: str) -> list[dict[str, Any]]:
    if isinstance(raw, dict):
        candidates = [raw]
    elif isinstance(raw, list):
        candidates = raw
    else:
        candidates = []

    findings: list[dict[str, Any]] = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            text = _report_text(candidate)
            if not text:
                continue
            candidate = {"title": _report_title_from_summary(text), "finding": text}

        finding_text = _report_text(
            candidate.get("finding")
            or candidate.get("description")
            or candidate.get("summary")
        )
        title = _report_text(candidate.get("title") or candidate.get("name"))
        if not title:
            title = _report_title_from_summary(finding_text or "", "未命名发现")

        evidence = _normalize_report_evidence(candidate.get("evidence"))
        direct_evidence = _normalize_report_evidence(
            {
                "request_packet": candidate.get("request_packet")
                or candidate.get("request"),
                "response_packet": candidate.get("response_packet")
                or candidate.get("response"),
            }
        )
        evidence.extend(direct_evidence)

        findings.append(
            {
                "title": title,
                "asset": _report_text(candidate.get("asset") or candidate.get("target")),
                "endpoint": _report_text(
                    candidate.get("endpoint")
                    or candidate.get("uri")
                    or candidate.get("path")
                ),
                "source": _report_text(candidate.get("source")) or fallback_source,
                "type": _report_text(
                    candidate.get("type") or candidate.get("category") or candidate.get("kind")
                ),
                "status": _report_text(candidate.get("status")) or "已确认",
                "severity": _report_text(
                    candidate.get("severity") or candidate.get("risk")
                )
                or "待定",
                "finding": finding_text or title,
                "fix": _report_text(
                    candidate.get("fix")
                    or candidate.get("remediation")
                    or candidate.get("recommendation")
                ),
                "evidence": evidence,
            }
        )
    return findings


def normalize_report_payload(
    raw: Any,
    *,
    fallback_summary: str,
    fallback_source: str,
) -> dict[str, Any]:
    report = raw
    summary = fallback_summary
    title = "漏洞报告"
    findings: list[dict[str, Any]] = []

    if isinstance(raw, dict):
        nested = raw.get("report")
        if isinstance(nested, dict) and (
            "findings" in nested
            or "vulnerabilities" in nested
            or "items" in nested
            or "title" in nested
        ):
            report = nested

    if isinstance(report, dict):
        title = _report_text(report.get("title") or report.get("name")) or title
        summary = _report_text(
            report.get("summary")
            or report.get("description")
            or report.get("finding")
        ) or summary
        findings = _normalize_report_findings(
            report.get("findings")
            or report.get("vulnerabilities")
            or report.get("items"),
            fallback_source,
        )
        if not findings and any(
            key in report
            for key in (
                "finding",
                "description",
                "asset",
                "endpoint",
                "request_packet",
                "response_packet",
            )
        ):
            findings = _normalize_report_findings(report, fallback_source)
    elif isinstance(report, list):
        findings = _normalize_report_findings(report, fallback_source)
    else:
        summary = _report_text(report) or summary

    if not findings:
        finding_summary = summary or fallback_summary
        findings = [
            {
                "title": _report_title_from_summary(finding_summary),
                "asset": None,
                "endpoint": None,
                "source": fallback_source,
                "type": None,
                "status": "已确认",
                "severity": "待定",
                "finding": finding_summary,
                "fix": None,
                "evidence": [],
            }
        ]

    return {
        "type": "conclude_report",
        "title": title,
        "summary": summary,
        "findings": findings,
    }


def _report_summary_from_packet(raw: Any, fallback: str) -> str:
    if isinstance(raw, dict):
        fact = raw.get("fact")
        if isinstance(fact, dict):
            desc = _report_text(fact.get("description"))
            if desc:
                return desc
        conclusion = raw.get("conclusion")
        if isinstance(conclusion, dict):
            conclusion_fact = conclusion.get("fact")
            if isinstance(conclusion_fact, dict):
                desc = _report_text(conclusion_fact.get("description"))
                if desc:
                    return desc
        desc = _report_text(raw.get("description") or raw.get("summary"))
        if desc:
            return desc
    return fallback


def build_conclude_report_packets(
    *,
    report_id: str,
    project_row: sqlite3.Row,
    intent_row: sqlite3.Row,
    source_fact_ids: list[str],
    fact_descriptions: dict[str, str],
    fact_id: str,
    worker: str,
    conclusion_description: str,
    raw_report: Any,
    created_at: str,
) -> tuple[str, str]:
    request_payload: dict[str, Any] = {
        "type": "conclude_report_request",
        "project": {
            "id": project_row["id"],
            "title": project_row["title"],
            "status": project_row["status"],
        },
        "intent": {
            "id": intent_row["id"],
            "from": source_fact_ids,
            "description": intent_row["description"],
            "creator": intent_row["creator"],
            "worker": worker,
            "created_at": intent_row["created_at"],
            "concluded_at": intent_row["concluded_at"],
        },
        "source_facts": [
            {"id": source_id, "description": fact_descriptions.get(source_id, "")}
            for source_id in source_fact_ids
        ],
        "conclusion": {
            "fact": {"id": fact_id, "description": conclusion_description}
        },
        "report": raw_report,
    }
    fallback_source = _report_source_label(
        intent_row["id"], fact_id, source_fact_ids
    )
    response_payload = normalize_report_payload(
        raw_report,
        fallback_summary=conclusion_description,
        fallback_source=fallback_source,
    )
    response_payload["report_id"] = report_id
    response_payload["project_id"] = project_row["id"]
    response_payload["intent_id"] = intent_row["id"]
    response_payload["fact_id"] = fact_id
    response_payload["worker"] = worker
    response_payload["created_at"] = created_at

    return (
        json.dumps(request_payload, ensure_ascii=False, indent=2),
        json.dumps(response_payload, ensure_ascii=False, indent=2),
    )


def report_to_model(row: sqlite3.Row) -> Report:
    source_fact_ids: list[str] = []
    raw_source_fact_ids = row["source_fact_ids"]
    if raw_source_fact_ids:
        try:
            parsed = json.loads(raw_source_fact_ids)
        except json.JSONDecodeError:
            parsed = []
        if isinstance(parsed, list):
            source_fact_ids = [str(item) for item in parsed if str(item).strip()]
    raw_response = row["response_packet"]
    parsed_response: Any = None
    try:
        parsed_response = json.loads(raw_response) if raw_response else None
    except json.JSONDecodeError:
        parsed_response = None
    fallback_summary = _report_summary_from_packet(
        parsed_response, raw_response or "结论报告"
    )
    payload = normalize_report_payload(
        parsed_response,
        fallback_summary=fallback_summary,
        fallback_source=_report_source_label(
            row["intent_id"], row["fact_id"], source_fact_ids
        ),
    )
    return Report(
        id=row["id"],
        project_id=row["project_id"],
        intent_id=row["intent_id"],
        fact_id=row["fact_id"],
        worker=row["worker"],
        source_fact_ids=source_fact_ids,
        request_packet=row["request_packet"],
        response_packet=row["response_packet"],
        created_at=row["created_at"],
        title=payload.get("title") or "漏洞报告",
        summary=payload.get("summary"),
        findings=payload.get("findings") or [],
    )


def build_reports(conn: sqlite3.Connection, project_id: str) -> list[Report]:
    rows = conn.execute(
        "SELECT * FROM reports WHERE project_id = ? ORDER BY created_at, id",
        (project_id,),
    ).fetchall()
    reports = [report_to_model(r) for r in rows]
    reported_intents = {report.intent_id for report in reports}

    project_row = get_project_or_404(conn, project_id)
    fact_rows = conn.execute(
        "SELECT id, description FROM facts WHERE project_id = ?",
        (project_id,),
    ).fetchall()
    fact_descriptions = {row["id"]: row["description"] for row in fact_rows}
    intent_rows = conn.execute(
        """
        SELECT *
        FROM intents
        WHERE project_id = ?
          AND to_fact_id IS NOT NULL
        ORDER BY concluded_at, id
        """,
        (project_id,),
    ).fetchall()
    for intent_row in intent_rows:
        if intent_row["id"] in reported_intents:
            continue
        fact_id = intent_row["to_fact_id"]
        if not fact_id:
            continue
        conclusion_description = fact_descriptions.get(fact_id, "")
        raw_report = build_fallback_report_from_conclusion(conclusion_description)
        if raw_report is None:
            continue
        source_rows = conn.execute(
            "SELECT fact_id FROM intent_sources WHERE intent_id = ? AND project_id = ? ORDER BY rowid",
            (intent_row["id"], project_id),
        ).fetchall()
        source_fact_ids = [row["fact_id"] for row in source_rows]
        request_packet, response_packet = build_conclude_report_packets(
            report_id=f"auto_{intent_row['id']}",
            project_row=project_row,
            intent_row=intent_row,
            source_fact_ids=source_fact_ids,
            fact_descriptions=fact_descriptions,
            fact_id=fact_id,
            worker=intent_row["worker"] or "system",
            conclusion_description=conclusion_description,
            raw_report=raw_report,
            created_at=intent_row["concluded_at"] or utcnow(),
        )
        payload = normalize_report_payload(
            json.loads(response_packet),
            fallback_summary=conclusion_description,
            fallback_source=_report_source_label(
                intent_row["id"], fact_id, source_fact_ids
            ),
        )
        reports.append(
            Report(
                id=f"auto_{intent_row['id']}",
                project_id=project_id,
                intent_id=intent_row["id"],
                fact_id=fact_id,
                worker=intent_row["worker"] or "system",
                source_fact_ids=source_fact_ids,
                request_packet=request_packet,
                response_packet=response_packet,
                created_at=intent_row["concluded_at"] or utcnow(),
                title=payload.get("title") or "漏洞报告",
                summary=payload.get("summary"),
                findings=payload.get("findings") or [],
            )
        )

    return sorted(reports, key=lambda report: (report.created_at, report.id))


def get_intent_timeout(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT intent_timeout FROM settings WHERE rowid = 1").fetchone()
    return row["intent_timeout"]


def get_reason_timeout(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT reason_timeout FROM settings WHERE rowid = 1").fetchone()
    return row["reason_timeout"]


def project_reason_from_row(row: sqlite3.Row) -> ProjectReason | None:
    if row["reason_worker"] is None:
        return None
    return ProjectReason(
        worker=row["reason_worker"],
        trigger=row["reason_trigger"],
        started_at=row["reason_started_at"],
        last_heartbeat_at=row["reason_last_heartbeat_at"],
    )


def project_meta_from_row(row: sqlite3.Row) -> ProjectMeta:
    return ProjectMeta(
        id=row["id"],
        title=row["title"],
        status=row["status"],
        created_at=row["created_at"],
        reason=project_reason_from_row(row),
    )


def clear_project_reason(conn: sqlite3.Connection, project_id: str) -> None:
    conn.execute(
        """
        UPDATE projects
        SET reason_worker = NULL,
            reason_trigger = NULL,
            reason_started_at = NULL,
            reason_last_heartbeat_at = NULL
        WHERE id = ?
        """,
        (project_id,),
    )


def expire_workers(conn: sqlite3.Connection, project_id: str | None = None) -> None:
    timeout = get_intent_timeout(conn)
    now = utcnow()
    query = """
        UPDATE intents
        SET worker = NULL
        WHERE to_fact_id IS NULL
          AND worker IS NOT NULL
          AND last_heartbeat_at IS NOT NULL
          AND (julianday(?) - julianday(last_heartbeat_at)) * 86400 > ?
    """
    params: tuple = (now, timeout)
    if project_id is not None:
        query = query.replace("WHERE ", "WHERE project_id = ? AND ", 1)
        params = (project_id, now, timeout)
    conn.execute(query, params)


def expire_reason_leases(conn: sqlite3.Connection, project_id: str | None = None) -> None:
    timeout = get_reason_timeout(conn)
    now = utcnow()
    query = """
        UPDATE projects
        SET reason_worker = NULL,
            reason_trigger = NULL,
            reason_started_at = NULL,
            reason_last_heartbeat_at = NULL
        WHERE reason_worker IS NOT NULL
          AND reason_last_heartbeat_at IS NOT NULL
          AND (julianday(?) - julianday(reason_last_heartbeat_at)) * 86400 > ?
    """
    params: tuple = (now, timeout)
    if project_id is not None:
        query = query.replace("WHERE ", "WHERE id = ? AND ", 1)
        params = (project_id, now, timeout)
    conn.execute(query, params)
