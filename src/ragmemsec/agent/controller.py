"""Observable baseline pipeline. There is intentionally no admission or action gate."""

from __future__ import annotations

import json
import time
from hashlib import sha256

from ragmemsec.agent.model_provider import ModelProvider
from ragmemsec.agent.prompts import render_agent_prompt, render_memory_prompt
from ragmemsec.config import BaselineConfig
from ragmemsec.contracts import (
    AgentDecision,
    ExperimentTrace,
    MemoryRecord,
    ToolCall,
    new_id,
    utc_now,
)
from ragmemsec.memory.retriever import MemoryRetriever
from ragmemsec.memory.store import MemoryStore
from ragmemsec.memory.writer import parse_memory_output
from ragmemsec.rag.retriever import DocumentRetriever
from ragmemsec.tools.access_control import AccessControlSimulator


def parse_decision(raw: str) -> tuple[AgentDecision | None, str | None]:
    try:
        item = json.loads(raw)
        if not isinstance(item, dict) or any(
            not isinstance(item.get(key), str)
            for key in ("answer", "decision", "reason")
        ):
            raise ValueError("missing required decision fields")
        if item["decision"] not in {"allowed", "denied", "requires_approval"}:
            raise ValueError("unknown decision")
        tool = item.get("tool_call")
        tool_call = None
        if tool is not None:
            if (
                not isinstance(tool, dict)
                or not isinstance(tool.get("tool_name"), str)
                or not isinstance(tool.get("arguments"), dict)
            ):
                raise ValueError("invalid tool_call")
            tool_call = ToolCall(tool["tool_name"], tool["arguments"])
        return AgentDecision(
            item["answer"], item["decision"], item["reason"], tool_call
        ), None
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        return None, str(exc)


class BenchmarkAgent:
    def __init__(
        self,
        config: BaselineConfig,
        provider: ModelProvider,
        documents: DocumentRetriever,
        memories: MemoryStore,
        memory_retriever: MemoryRetriever,
        simulator: AccessControlSimulator,
    ) -> None:
        self.config, self.provider, self.documents = config, provider, documents
        self.memories, self.memory_retriever, self.simulator = (
            memories,
            memory_retriever,
            simulator,
        )

    def run(
        self,
        experiment_id: str,
        scenario_id: str,
        condition: str,
        session_id: str,
        query: str,
        query_id: str | None = None,
        expected_outcome: dict | None = None,
        retain_memory: bool = True,
    ) -> ExperimentTrace:
        timings: dict[str, float] = {}
        started = time.perf_counter()
        docs = self.documents.retrieve(query, self.config.document_top_k)
        timings["document_retrieval"] = time.perf_counter() - started
        started = time.perf_counter()
        memories = self.memory_retriever.retrieve(query, self.config.memory_top_k)
        timings["memory_retrieval"] = time.perf_counter() - started
        messages = render_agent_prompt(query, docs, memories)
        rendered = "\n".join(message["content"] for message in messages)
        prompt_hash = sha256(
            json.dumps(messages, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        started = time.perf_counter()
        response = self.provider.generate(messages)
        timings["decision_generation"] = time.perf_counter() - started
        decision, error = parse_decision(response.parsing_text or response.text)
        tool_result = None
        errors: list[str] = []
        if error:
            errors.append(f"decision_parse: {error}")
        if decision and decision.tool_call:
            started = time.perf_counter()
            try:
                tool_result = self.simulator.execute(
                    decision.tool_call.tool_name, decision.tool_call.arguments
                )
            except (TypeError, ValueError, KeyError) as exc:
                tool_result = {"status": "error", "error": str(exc)}
                errors.append(f"tool_execution: {exc}")
            timings["tool_execution"] = time.perf_counter() - started
        started = time.perf_counter()
        memory_response = self.provider.generate(
            render_memory_prompt(
                query, docs, memories, response.parsing_text or response.text
            )
        )
        candidate, memory_valid, memory_error = parse_memory_output(
            memory_response.parsing_text or memory_response.text
        )
        timings["memory_generation"] = time.perf_counter() - started
        memory_write_result = None
        if candidate is not None and memory_valid:
            candidate.source_ids = [
                *(record.record_id for record in docs),
                *(record.record_id for record in memories),
            ]
            candidate.source_types = [
                *("rag_document" for _ in docs),
                *("memory" for _ in memories),
            ]
            record = MemoryRecord(
                new_id(),
                candidate.text,
                candidate.memory_type,
                utc_now(),
                session_id,
                candidate.source_ids,
                candidate.source_types,
                metadata={
                    "baseline": "unprotected",
                    "experimental_provenance": {
                        "retrieved_document_ids": [item.record_id for item in docs],
                        "retrieved_memory_ids": [item.record_id for item in memories],
                    },
                    "model_reported_source_ids": candidate.model_reported_source_ids,
                    "model_reported_source_types": candidate.model_reported_source_types,
                },
            )
            if retain_memory:
                self.memories.add(record)
                memory_write_result = {
                    "stored": True,
                    "memory_id": record.id,
                    "admission": "automatic",
                }
            else:
                memory_write_result = {
                    "stored": False,
                    "reason": "memory_disabled_control",
                    "candidate_generated": True,
                }
        elif memory_valid:
            memory_write_result = {"stored": False, "reason": "writer_declined"}
        else:
            memory_write_result = {"stored": False, "reason": "invalid_output"}
        timings["total"] = sum(timings.values())
        if memory_error:
            errors.append(f"memory_parse: {memory_error}")
        return ExperimentTrace(
            experiment_id,
            scenario_id,
            condition,
            self.config.model,
            self.config.model_id,
            self.config.seed,
            session_id,
            query,
            query_id,
            expected_outcome,
            docs,
            memories,
            rendered,
            messages,
            "access-control-baseline-v2",
            prompt_hash,
            response.text,
            response.parsing_text or response.text,
            response.metadata,
            decision,
            decision.tool_call if decision else None,
            tool_result,
            candidate,
            memory_write_result,
            memory_response.text,
            memory_response.parsing_text or memory_response.text,
            memory_response.metadata,
            timings,
            errors,
            output_valid=decision is not None,
            input_tokens=len(rendered.split()),
            output_tokens=len(response.text.split()),
        )
