from fastapi import APIRouter
import json
import logging

from cairn.server.db import get_conn
from cairn.server.models import (
    ConcludeRequest,
    ConcludeResponse,
    CreateIntentRequest,
    Fact,
    HeartbeatRequest,
    Intent,
)
from cairn.server.services import (
    build_conclude_report_packets,
    check_project_active,
    get_claimable_open_intent_or_404,
    get_project_or_404,
    get_releasable_open_intent_or_404,
    intent_to_model,
    next_fact_id,
    next_intent_id,
    next_report_id,
    utcnow,
    validate_facts_exist,
    validate_intent_creator_worker,
    validate_goal_not_in_sources,
)
from cairn.reporting import build_fallback_report_from_conclusion, report_is_present

router = APIRouter(tags=["intents"])
LOG = logging.getLogger(__name__)


@router.post(
    "/projects/{project_id}/intents",
    response_model=Intent,
    status_code=201,
)
def create_intent(project_id: str, body: CreateIntentRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        validate_facts_exist(conn, project_id, body.from_)
        validate_goal_not_in_sources(body.from_)
        validate_intent_creator_worker(body.creator, body.worker)

        now = utcnow()
        iid = next_intent_id(conn, project_id)
        claimed = body.worker is not None
        conn.execute(
            "INSERT INTO intents (id, project_id, to_fact_id, description, creator, worker, last_heartbeat_at, created_at, concluded_at) VALUES (?, ?, NULL, ?, ?, ?, ?, ?, NULL)",
            (
                iid,
                project_id,
                body.description,
                body.creator,
                body.worker,
                now if claimed else None,
                now,
            ),
        )
        for fid in body.from_:
            conn.execute(
                "INSERT INTO intent_sources (intent_id, project_id, fact_id) VALUES (?, ?, ?)",
                (iid, project_id, fid),
            )

        return Intent(
            id=iid,
            **{"from": body.from_},
            to=None,
            description=body.description,
            creator=body.creator,
            worker=body.worker,
            last_heartbeat_at=now if claimed else None,
            created_at=now,
            concluded_at=None,
        )


@router.post(
    "/projects/{project_id}/intents/{intent_id}/heartbeat",
    response_model=Intent,
)
def heartbeat(project_id: str, intent_id: str, body: HeartbeatRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        get_claimable_open_intent_or_404(conn, project_id, intent_id, body.worker)

        now = utcnow()
        conn.execute(
            "UPDATE intents SET worker = ?, last_heartbeat_at = ? WHERE id = ? AND project_id = ?",
            (body.worker, now, intent_id, project_id),
        )

        updated = conn.execute(
            "SELECT * FROM intents WHERE id = ? AND project_id = ?",
            (intent_id, project_id),
        ).fetchone()
        return intent_to_model(conn, updated, project_id)


@router.post(
    "/projects/{project_id}/intents/{intent_id}/release",
    response_model=Intent,
)
def release(project_id: str, intent_id: str, body: HeartbeatRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        row = get_releasable_open_intent_or_404(conn, project_id, intent_id, body.worker)

        if row["worker"] == body.worker:
            conn.execute(
                "UPDATE intents SET worker = NULL WHERE id = ? AND project_id = ?",
                (intent_id, project_id),
            )
            row = conn.execute(
                "SELECT * FROM intents WHERE id = ? AND project_id = ?",
                (intent_id, project_id),
            ).fetchone()

        return intent_to_model(conn, row, project_id)


@router.post(
    "/projects/{project_id}/intents/{intent_id}/conclude",
    response_model=ConcludeResponse,
)
def conclude(project_id: str, intent_id: str, body: ConcludeRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        get_claimable_open_intent_or_404(conn, project_id, intent_id, body.worker)

        now = utcnow()
        fid = next_fact_id(conn, project_id)
        project_row = get_project_or_404(conn, project_id)
        source_rows = conn.execute(
            "SELECT fact_id FROM intent_sources WHERE intent_id = ? AND project_id = ? ORDER BY rowid",
            (intent_id, project_id),
        ).fetchall()
        source_fact_ids = [row["fact_id"] for row in source_rows]
        fact_rows = conn.execute(
            "SELECT id, description FROM facts WHERE project_id = ?",
            (project_id,),
        ).fetchall()
        fact_descriptions = {row["id"]: row["description"] for row in fact_rows}

        conn.execute(
            "INSERT INTO facts (id, project_id, description) VALUES (?, ?, ?)",
            (fid, project_id, body.description),
        )
        conn.execute(
            "UPDATE intents SET to_fact_id = ?, worker = ?, last_heartbeat_at = ?, concluded_at = ? WHERE id = ? AND project_id = ?",
            (fid, body.worker, now, now, intent_id, project_id),
        )

        updated = conn.execute(
            "SELECT * FROM intents WHERE id = ? AND project_id = ?",
            (intent_id, project_id),
        ).fetchone()

        raw_report = body.report
        if not report_is_present(raw_report):
            raw_report = build_fallback_report_from_conclusion(body.description)

        if report_is_present(raw_report):
            try:
                report_id = next_report_id(conn, project_id)
                request_packet, response_packet = build_conclude_report_packets(
                    report_id=report_id,
                    project_row=project_row,
                    intent_row=updated,
                    source_fact_ids=source_fact_ids,
                    fact_descriptions=fact_descriptions,
                    fact_id=fid,
                    worker=body.worker,
                    conclusion_description=body.description,
                    raw_report=raw_report,
                    created_at=now,
                )
                conn.execute(
                    """
                    INSERT INTO reports (
                        id, project_id, intent_id, fact_id, worker,
                        source_fact_ids, request_packet, response_packet, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        report_id,
                        project_id,
                        intent_id,
                        fid,
                        body.worker,
                        json.dumps(source_fact_ids, ensure_ascii=False),
                        request_packet,
                        response_packet,
                        now,
                    ),
                )
            except Exception as exc:
                LOG.warning(
                    "conclude report generation failed project=%s intent=%s worker=%s error=%s",
                    project_id,
                    intent_id,
                    body.worker,
                    exc,
                )

        return ConcludeResponse(
            fact=Fact(id=fid, description=body.description),
            intent=intent_to_model(conn, updated, project_id),
        )
