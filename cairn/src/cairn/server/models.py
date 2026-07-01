from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator

_CJK_RE = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]")


def _validate_non_empty_text(value: str) -> str:
    text = value.strip()
    if not text:
        raise ValueError("must not be empty")
    return text


def _validate_chinese_narrative_text(value: str) -> str:
    text = _validate_non_empty_text(value)
    if not _CJK_RE.search(text):
        raise ValueError("must contain Chinese text; technical tokens may be embedded")
    return text


class Settings(BaseModel):
    intent_timeout: int = Field(ge=5)
    reason_timeout: int = Field(ge=5)


class FactProvenance(BaseModel):
    scheme: str | None = None
    host: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    method: str | None = None
    path: str | None = None
    url: str | None = None
    interface_label: str | None = None
    repro_command: str | None = None
    evidence_files: list[str] = Field(default_factory=list)
    traffic_ids: list[str] = Field(default_factory=list)

    @field_validator(
        "scheme",
        "host",
        "method",
        "path",
        "url",
        "interface_label",
        "repro_command",
    )
    @classmethod
    def validate_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _validate_non_empty_text(value)

    @field_validator("evidence_files", "traffic_ids")
    @classmethod
    def validate_text_list(cls, value: list[str]) -> list[str]:
        return [_validate_non_empty_text(item) for item in value]


class Fact(BaseModel):
    id: str
    description: str
    provenance: FactProvenance | None = None


class Intent(BaseModel):
    id: str
    from_: list[str] = Field(alias="from")
    to: str | None = None
    description: str
    creator: str
    worker: str | None = None
    last_heartbeat_at: str | None = None
    created_at: str
    concluded_at: str | None = None

    model_config = {"populate_by_name": True}


class Hint(BaseModel):
    id: str
    content: str
    creator: str
    created_at: str


class ProjectReason(BaseModel):
    worker: str
    trigger: str
    started_at: str
    last_heartbeat_at: str


class ProjectMeta(BaseModel):
    id: str
    title: str
    category: str
    status: Literal["active", "stopped", "completed"]
    bootstrap_enabled: bool
    created_at: str
    reason: ProjectReason | None = None


class ProjectSummary(ProjectMeta):
    fact_count: int
    intent_count: int
    working_intent_count: int
    unclaimed_intent_count: int
    hint_count: int


class ProjectDetail(BaseModel):
    project: ProjectMeta
    facts: list[Fact]
    intents: list[Intent]
    hints: list[Hint]
    timeline_prompts: list["TimelinePrompt"] = Field(default_factory=list)


class TimelinePrompt(BaseModel):
    timeline_entry_id: str
    intent_id: str | None = None
    phase: str
    worker: str
    prompt_text: str
    created_at: str


class CreateHintInline(BaseModel):
    content: str
    creator: str

    @field_validator("content")
    @classmethod
    def validate_content(cls, value: str) -> str:
        return _validate_chinese_narrative_text(value)

    @field_validator("creator")
    @classmethod
    def validate_creator(cls, value: str) -> str:
        return _validate_non_empty_text(value)


class CreateProjectRequest(BaseModel):
    title: str
    category: str = "未分类"
    origin: str
    goal: str
    bootstrap_enabled: bool = True
    hints: list[CreateHintInline] | None = None

    @field_validator("title", "category", "origin", "goal")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        return _validate_non_empty_text(value)


class CreateHintRequest(BaseModel):
    content: str
    creator: str

    @field_validator("content")
    @classmethod
    def validate_content(cls, value: str) -> str:
        return _validate_chinese_narrative_text(value)

    @field_validator("creator")
    @classmethod
    def validate_creator(cls, value: str) -> str:
        return _validate_non_empty_text(value)


class CreateIntentRequest(BaseModel):
    from_: list[str] = Field(alias="from", min_length=1)
    description: str
    creator: str
    worker: str | None = None

    model_config = {"populate_by_name": True}

    @field_validator("description")
    @classmethod
    def validate_description(cls, value: str) -> str:
        return _validate_chinese_narrative_text(value)

    @field_validator("creator", "worker")
    @classmethod
    def validate_non_empty_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _validate_non_empty_text(value)

    @field_validator("from_")
    @classmethod
    def validate_fact_ids(cls, value: list[str]) -> list[str]:
        cleaned = []
        for item in value:
            text = item.strip()
            if not text:
                raise ValueError("fact ids must not be empty")
            cleaned.append(text)
        return cleaned


class HeartbeatRequest(BaseModel):
    worker: str

    @field_validator("worker")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class ReasonClaimRequest(BaseModel):
    worker: str
    trigger: str

    @field_validator("worker", "trigger")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class ConcludeRequest(BaseModel):
    worker: str
    description: str
    provenance: FactProvenance | None = None

    @field_validator("description")
    @classmethod
    def validate_description(cls, value: str) -> str:
        return _validate_chinese_narrative_text(value)

    @field_validator("worker")
    @classmethod
    def validate_worker(cls, value: str) -> str:
        return _validate_non_empty_text(value)


class CompleteRequest(BaseModel):
    from_: list[str] = Field(alias="from", min_length=1)
    description: str
    worker: str

    model_config = {"populate_by_name": True}

    @field_validator("description")
    @classmethod
    def validate_description(cls, value: str) -> str:
        return _validate_chinese_narrative_text(value)

    @field_validator("worker")
    @classmethod
    def validate_worker(cls, value: str) -> str:
        return _validate_non_empty_text(value)

    @field_validator("from_")
    @classmethod
    def validate_fact_ids(cls, value: list[str]) -> list[str]:
        cleaned = []
        for item in value:
            text = item.strip()
            if not text:
                raise ValueError("fact ids must not be empty")
            cleaned.append(text)
        return cleaned


class ConcludeResponse(BaseModel):
    fact: Fact
    intent: Intent


class LoginRequest(BaseModel):
    username: str
    password: str

    @field_validator("username", "password")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        return _validate_non_empty_text(value)


class SessionResponse(BaseModel):
    enabled: bool
    authenticated: bool
    username: str | None = None


class CreateTimelinePromptRequest(BaseModel):
    timeline_entry_id: str
    prompt_text: str
    phase: str
    worker: str
    intent_id: str | None = None

    @field_validator("timeline_entry_id", "prompt_text", "phase", "worker")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        return _validate_non_empty_text(value)

    @field_validator("intent_id")
    @classmethod
    def validate_optional_intent_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _validate_non_empty_text(value)


class UpdateProjectStatusRequest(BaseModel):
    status: Literal["active", "stopped"]


class UpdateProjectTitleRequest(BaseModel):
    title: str

    @field_validator("title")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class ReopenRequest(BaseModel):
    description: str
    creator: str

    @field_validator("description")
    @classmethod
    def validate_description(cls, value: str) -> str:
        return _validate_chinese_narrative_text(value)

    @field_validator("creator")
    @classmethod
    def validate_creator(cls, value: str) -> str:
        return _validate_non_empty_text(value)


class ReopenResponse(BaseModel):
    project: ProjectMeta
    fact: Fact
    intent: Intent


class TrafficRecordSummary(BaseModel):
    id: str
    timestamp: str
    scheme: str
    host: str
    port: int
    method: str
    path: str
    url: str
    status_code: int | None = None
    matched_field: str | None = None
    matched_excerpt: str | None = None


class TrafficRecordDetail(TrafficRecordSummary):
    request_headers: dict[str, str] = Field(default_factory=dict)
    response_headers: dict[str, str] = Field(default_factory=dict)
    raw_request: str
    raw_response: str | None = None
    pcap_file: str | None = None
    source_file: str | None = None


class ProjectFileEntry(BaseModel):
    path: str
    name: str
    kind: Literal["file", "directory"]
    size: int | None = None


ProjectDetail.model_rebuild()
