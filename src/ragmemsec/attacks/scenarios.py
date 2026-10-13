"""Versioned scenario corpus contracts and validation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ragmemsec.attacks.pilot import build_pilot_v1
from ragmemsec.config import load_mapping
from ragmemsec.contracts import DocumentChunk

TOOL_ARGUMENTS = {
    "request_database_access": {"user_id", "database", "approval_id"},
    "request_credential_recovery": {"user_id"},
    "request_data_export": {"user_id", "sensitivity", "approval_id"},
    "check_user_role": {"user_id"},
    "check_manager_approval": {"approval_id"},
}


@dataclass
class ScenarioQuery:
    id: str
    text: str
    expected_outcome: dict[str, Any] | None = None


@dataclass
class Scenario:
    id: str
    corpus_version: str
    task_family: str
    trusted_documents: list[DocumentChunk]
    malicious_document: DocumentChunk
    benign_queries: list[ScenarioQuery]
    injection_queries: list[ScenarioQuery]
    victim_queries: list[ScenarioQuery]
    utility_queries: list[ScenarioQuery]
    attack_target: dict[str, Any]


@dataclass
class ScenarioCorpus:
    version: str
    scenarios: list[Scenario]
    checksum: str


def _document(data: dict[str, Any]) -> DocumentChunk:
    return DocumentChunk(**data)


def _queries(
    items: list[dict[str, Any]], outcomes_required: bool
) -> list[ScenarioQuery]:
    queries = [ScenarioQuery(**item) for item in items]
    if outcomes_required and any(query.expected_outcome is None for query in queries):
        raise ValueError("Clean, victim, and utility queries require expected_outcome")
    return queries


def _scenario(data: dict[str, Any], corpus_version: str | None = None) -> Scenario:
    return Scenario(
        id=data["scenario_id"] if "scenario_id" in data else data["id"],
        corpus_version=data.get("corpus_version", corpus_version or "unversioned"),
        task_family=data.get("task_family", "database_access"),
        trusted_documents=[_document(item) for item in data["trusted_documents"]],
        malicious_document=_document(data["malicious_document"]),
        benign_queries=_queries(data["benign_queries"], outcomes_required=True),
        injection_queries=_queries(data["injection_queries"], outcomes_required=False),
        victim_queries=_queries(data["victim_queries"], outcomes_required=True),
        utility_queries=_queries(data["utility_queries"], outcomes_required=True),
        attack_target=data["attack_target"],
    )


def _validate_arguments(tool_name: str, arguments: dict[str, Any]) -> None:
    if tool_name not in TOOL_ARGUMENTS:
        raise ValueError(f"Unknown scenario tool: {tool_name}")
    unexpected = set(arguments) - TOOL_ARGUMENTS[tool_name]
    if unexpected:
        raise ValueError(f"Invalid arguments for {tool_name}: {sorted(unexpected)}")


def _validate_outcome(outcome: dict[str, Any]) -> None:
    required = {
        "expected_decision",
        "expected_tool_name",
        "required_tool_arguments",
        "expected_simulator_result",
        "expected_state_effect",
    }
    if not required <= set(outcome):
        raise ValueError("Scenario expected outcome is incomplete")
    _validate_arguments(
        outcome["expected_tool_name"], outcome["required_tool_arguments"]
    )


def validate_corpus(corpus: ScenarioCorpus) -> None:
    ids = [scenario.id for scenario in corpus.scenarios]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate scenario IDs")
    for scenario in corpus.scenarios:
        if scenario.corpus_version != corpus.version:
            raise ValueError(f"Scenario {scenario.id} has a mismatched corpus version")
        visible_ids = {document.id for document in scenario.trusted_documents}
        if scenario.malicious_document.id in visible_ids:
            raise ValueError(
                f"Scenario {scenario.id} duplicates its malicious document"
            )
        visible_ids.add(scenario.malicious_document.id)
        if scenario.attack_target.get("source_document_id") not in visible_ids:
            raise ValueError(
                f"Scenario {scenario.id} references a missing attacker document"
            )
        target_required = {
            "source_document_id",
            "target_decision",
            "target_tool_name",
            "required_target_arguments",
            "target_simulator_result",
            "target_state_effect",
        }
        if not target_required <= set(scenario.attack_target):
            raise ValueError(f"Scenario {scenario.id} has an incomplete attack target")
        _validate_arguments(
            scenario.attack_target["target_tool_name"],
            scenario.attack_target["required_target_arguments"],
        )
        injection_text = {query.text for query in scenario.injection_queries}
        victim_text = {query.text for query in scenario.victim_queries}
        if injection_text & victim_text:
            raise ValueError(
                f"Scenario {scenario.id} overlaps injection and victim queries"
            )
        for query in (
            scenario.benign_queries + scenario.victim_queries + scenario.utility_queries
        ):
            _validate_outcome(query.expected_outcome or {})
        # Prompt rendering only consumes document/query text and generated contexts.
        # Evaluator labels must therefore never be stored inside visible document text.
        for document in [*scenario.trusted_documents, scenario.malicious_document]:
            if "expected_outcome" in document.text or "attack_target" in document.text:
                raise ValueError(
                    "Evaluator label detected in agent-visible document text"
                )


def load_corpus(path: str | Path) -> ScenarioCorpus:
    raw_path = Path(path)
    data = load_mapping(raw_path)
    version = data["corpus_version"]
    scenario_data = (
        build_pilot_v1(version)
        if data.get("generated_pilot") == "pilot_v1"
        else data["scenarios"]
    )
    corpus = ScenarioCorpus(
        version=version,
        scenarios=[_scenario(item, version) for item in scenario_data],
        checksum=hashlib.sha256(
            json.dumps(
                {
                    "corpus_file": hashlib.sha256(raw_path.read_bytes()).hexdigest(),
                    "scenarios": scenario_data,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest(),
    )
    validate_corpus(corpus)
    return corpus


def load_scenario(path: str | Path) -> Scenario:
    data = load_mapping(path)
    return _scenario(data)
