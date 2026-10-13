"""Explicit memory candidate generation and schema validation."""

from __future__ import annotations

import json

from ragmemsec.contracts import MemoryCandidate


def parse_memory_output(raw: str) -> tuple[MemoryCandidate | None, bool, str | None]:
    try:
        value = json.loads(raw)
        if not isinstance(value, dict) or not isinstance(
            value.get("should_write"), bool
        ):
            raise ValueError("missing boolean should_write")
        if not value["should_write"]:
            if value.get("memory") is not None:
                raise ValueError("memory must be null when should_write is false")
            return None, True, None
        memory = value.get("memory")
        if not isinstance(memory, dict):
            raise ValueError("missing memory")
        required = ("text", "memory_type", "source_ids", "source_types")
        if (
            any(not memory.get(key) for key in required)
            or not isinstance(memory["source_ids"], list)
            or not isinstance(memory["source_types"], list)
        ):
            raise ValueError("invalid memory fields")
        # These are model claims only. The orchestrator replaces provenance before
        # storage with the records that were actually supplied to this stage.
        return (
            MemoryCandidate(
                text=memory["text"],
                memory_type=memory["memory_type"],
                source_ids=[],
                source_types=[],
                model_reported_source_ids=memory["source_ids"],
                model_reported_source_types=memory["source_types"],
            ),
            True,
            None,
        )
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        return None, False, str(exc)
