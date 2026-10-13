"""Small, serialisable contracts shared by the benchmark stages."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def new_id() -> str:
    return str(uuid4())


@dataclass
class DocumentChunk:
    id: str
    text: str
    source_id: str
    source_type: str
    trusted: bool
    metadata: dict[str, Any] = field(default_factory=dict)
    embedding: list[float] | None = None


@dataclass
class MemoryRecord:
    id: str
    text: str
    memory_type: str
    created_at: str
    session_id: str
    source_ids: list[str]
    source_types: list[str]
    trusted: bool | None = None
    embedding: list[float] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolCall:
    tool_name: str
    arguments: dict[str, Any]


@dataclass
class AgentDecision:
    answer: str
    decision: str
    reason: str
    tool_call: ToolCall | None = None


@dataclass
class MemoryCandidate:
    text: str
    memory_type: str
    source_ids: list[str]
    source_types: list[str]
    model_reported_source_ids: list[str] = field(default_factory=list)
    model_reported_source_types: list[str] = field(default_factory=list)
    confidence: float | None = None


@dataclass
class RetrievalResult:
    record_id: str
    record_type: str
    text: str
    score: float
    rank: int
    metadata: dict[str, Any]


@dataclass
class ExperimentTrace:
    experiment_id: str
    scenario_id: str
    condition: str
    model_alias: str
    model_id: str
    seed: int
    session_id: str
    query: str
    query_id: str | None
    expected_outcome: dict[str, Any] | None
    retrieved_documents: list[RetrievalResult]
    retrieved_memories: list[RetrievalResult]
    rendered_prompt: str
    prompt_messages: list[dict[str, str]]
    prompt_version: str
    prompt_sha256: str
    raw_model_output: str
    parsing_model_output: str
    model_response_metadata: dict[str, Any]
    parsed_decision: AgentDecision | None
    tool_call: ToolCall | None
    tool_result: dict[str, Any] | None
    memory_candidate: MemoryCandidate | None
    memory_write_result: dict[str, Any] | None
    memory_writer_raw_output: str | None
    memory_writer_parsing_output: str | None
    memory_writer_response_metadata: dict[str, Any] | None
    latency: dict[str, float]
    errors: list[str]
    timestamp: str = field(default_factory=utc_now)
    output_valid: bool = True
    run_kind: str = ""
    corpus_version: str = ""
    task_family: str = ""
    input_tokens: int = 0
    output_tokens: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
