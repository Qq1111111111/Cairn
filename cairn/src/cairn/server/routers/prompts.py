from fastapi import APIRouter

from cairn.server.db import get_conn
from cairn.server.models import CreateTimelinePromptRequest, TimelinePrompt
from cairn.server.services import get_intent_or_404, get_project_or_404, utcnow

router = APIRouter(tags=["timeline-prompts"])


@router.post(
    "/projects/{project_id}/timeline-prompts",
    response_model=TimelinePrompt,
    status_code=201,
)
def create_timeline_prompt(project_id: str, body: CreateTimelinePromptRequest):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        if body.intent_id is not None:
            get_intent_or_404(conn, project_id, body.intent_id)

        now = utcnow()
        conn.execute(
            """
            INSERT INTO timeline_prompts (
                project_id,
                timeline_entry_id,
                intent_id,
                phase,
                worker,
                prompt_text,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(project_id, timeline_entry_id) DO UPDATE SET
                intent_id = excluded.intent_id,
                phase = excluded.phase,
                worker = excluded.worker,
                prompt_text = excluded.prompt_text,
                created_at = excluded.created_at
            """,
            (
                project_id,
                body.timeline_entry_id,
                body.intent_id,
                body.phase,
                body.worker,
                body.prompt_text,
                now,
            ),
        )
        return TimelinePrompt(
            timeline_entry_id=body.timeline_entry_id,
            intent_id=body.intent_id,
            phase=body.phase,
            worker=body.worker,
            prompt_text=body.prompt_text,
            created_at=now,
        )
