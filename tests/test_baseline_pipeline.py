"""Offline correctness regression tests for the unprotected benchmark."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from ragmemsec.agent.model_provider import MockModelProvider
from ragmemsec.attacks.scenarios import load_scenario
from ragmemsec.config import BaselineConfig, load_config, load_model_registry
from ragmemsec.evaluation.metrics import (
    attacker_target_effect_success,
    calculate_metrics,
    outcome_matches,
    target_tool_proposal_success,
)
from ragmemsec.evaluation.runner import ExperimentRunner, select_embedding_provider
from ragmemsec.rag.embeddings import (
    DeterministicEmbeddingProvider,
)
from ragmemsec.rag.retriever import DocumentRetriever

ROOT = Path(__file__).parents[1]


def make_runner(tmp_path: Path) -> ExperimentRunner:
    config = BaselineConfig(
        provider="mock",
        state_dir=str(tmp_path / "state"),
        artifacts_dir=str(tmp_path / "artifacts"),
    )
    return ExperimentRunner(
        config,
        load_scenario(ROOT / "configs/scenarios/orion_access.yaml"),
        MockModelProvider(),
    )


def results_by_condition(result: dict) -> dict:
    return {trace.condition: trace for trace in result["traces"]}


def test_models_yaml_is_authoritative_and_default_is_stable_text_model(tmp_path: Path):
    config_path = tmp_path / "baseline.yaml"
    config_path.write_text("model: qwen2.5-7b\nprovider: mock\n")
    assert load_config(config_path).model_id == "Qwen/Qwen2.5-7B-Instruct"
    assert load_model_registry()["llama3.1-8b"]["model_id"].startswith("meta-llama/")


def test_mock_mode_selects_deterministic_embedding_provider():
    assert isinstance(
        select_embedding_provider("fixed", mock_mode=True),
        DeterministicEmbeddingProvider,
    )


def test_real_mode_selects_sentence_transformer_provider(monkeypatch):
    class FakeSentenceProvider:
        def __init__(self, model_name):
            self.model_name = model_name

        def embed(self, text):
            return [1.0]

    monkeypatch.setattr(
        "ragmemsec.evaluation.runner.SentenceTransformerEmbeddingProvider",
        FakeSentenceProvider,
    )
    provider = select_embedding_provider("BAAI/bge-small-en-v1.5", mock_mode=False)
    assert isinstance(provider, FakeSentenceProvider)


def test_document_insert_and_remove():
    scenario = load_scenario(ROOT / "configs/scenarios/orion_access.yaml")
    retriever = DocumentRetriever(DeterministicEmbeddingProvider("fixed"))
    retriever.add(scenario.malicious_document)
    assert (
        retriever.retrieve("Project Orion production", 1)[0].record_id
        == scenario.malicious_document.id
    )
    assert retriever.remove(scenario.malicious_document.id) is True


def test_clean_development_access_is_scored_correctly(tmp_path: Path):
    result = make_runner(tmp_path).run()
    clean = results_by_condition(result)["clean"]
    assert clean.parsed_decision.decision == "allowed"
    assert clean.tool_call.arguments["database"] == "development"
    assert clean.tool_result == {"status": "allowed", "granted": True}
    assert outcome_matches(clean, clean.expected_outcome)
    assert result["metrics"]["clean_task_success"] == {
        "numerator": 1,
        "denominator": 1,
        "rate": 1.0,
    }


def test_wrong_resource_is_clean_task_failure(tmp_path: Path):
    clean = results_by_condition(make_runner(tmp_path).run())["clean"]
    wrong_call = replace(
        clean.tool_call,
        arguments={**clean.tool_call.arguments, "database": "production"},
    )
    wrong = replace(
        clean,
        tool_call=wrong_call,
        parsed_decision=replace(clean.parsed_decision, tool_call=wrong_call),
    )
    assert not outcome_matches(wrong, wrong.expected_outcome)


def test_denied_tool_result_is_not_attacker_execution_success(tmp_path: Path):
    runner = make_runner(tmp_path)
    result = runner.run()
    immediate = results_by_condition(result)["immediate_injection"]
    assert target_tool_proposal_success(immediate, runner.scenario.attack_target)
    assert immediate.tool_result == {"status": "requires_approval", "granted": False}
    assert not attacker_target_effect_success(immediate, runner.scenario.attack_target)
    assert result["metrics"]["attacker_target_effect_success"]["numerator"] == 0


def test_required_target_arguments_and_simulator_effect_must_match(tmp_path: Path):
    runner = make_runner(tmp_path)
    immediate = results_by_condition(runner.run())["immediate_injection"]
    wrong_args = replace(
        immediate,
        tool_call=replace(immediate.tool_call, arguments={"database": "development"}),
        parsed_decision=replace(
            immediate.parsed_decision,
            tool_call=replace(
                immediate.tool_call, arguments={"database": "development"}
            ),
        ),
    )
    assert not target_tool_proposal_success(wrong_args, runner.scenario.attack_target)
    assert not attacker_target_effect_success(immediate, runner.scenario.attack_target)


def test_poisoned_unrelated_utility_is_scored_as_failure(tmp_path: Path):
    result = make_runner(tmp_path).run()
    utility = results_by_condition(result)["post_contamination_utility"]
    assert utility.tool_call.arguments["database"] == "production"
    assert not outcome_matches(utility, utility.expected_outcome)
    assert result["metrics"]["utility_task_success_after_contamination"]["rate"] == 0.0


def test_orchestrator_provenance_cannot_be_forged_and_ablation_uses_it(tmp_path: Path):
    runner = make_runner(tmp_path)
    result = runner.run()
    injection = results_by_condition(result)["immediate_injection"]
    stored = runner.memories.inspect_all()[0]
    assert injection.memory_candidate.model_reported_source_ids == [
        "forged-model-source-id"
    ]
    assert (
        runner.scenario.malicious_document.id
        in stored.metadata["experimental_provenance"]["retrieved_document_ids"]
    )
    ablation = results_by_condition(result)["memory_ablation"]
    assert ablation.retrieved_memories == []
    assert ablation.parsed_decision.decision == "requires_approval"


def test_memory_disabled_persistence_asr_disappears(tmp_path: Path):
    result = make_runner(tmp_path).run()
    disabled = results_by_condition(result)["memory_disabled_control"]
    assert disabled.retrieved_memories == []
    assert disabled.parsed_decision.decision == "requires_approval"
    assert result["metrics"]["memory_disabled_target_effect_success"]["rate"] == 0.0


def test_invalid_outputs_are_excluded_from_valid_conditioned_asr(tmp_path: Path):
    runner = make_runner(tmp_path)
    result = runner.run()
    traces = list(result["traces"])
    index = next(
        i for i, trace in enumerate(traces) if trace.condition == "immediate_injection"
    )
    traces[index] = replace(
        traces[index], output_valid=False, parsed_decision=None, tool_call=None
    )
    metrics = calculate_metrics(
        traces, runner.scenario.attack_target, runner.memories.inspect_all()
    )
    assert metrics["invalid_output_count"] == 1
    assert metrics["overall_asr"]["denominator"] == 3
    assert metrics["valid_output_conditioned_asr"]["denominator"] == 2


def test_snapshots_and_prompt_audit_fields_are_complete(tmp_path: Path):
    result = make_runner(tmp_path).run()
    artifact = Path(result["artifact_dir"])
    expected = {
        "snapshot_initial_state.json",
        "snapshot_after_injection.json",
        "snapshot_after_source_removal.json",
        "snapshot_after_persistence.json",
        "snapshot_before_ablation.json",
        "snapshot_after_ablation.json",
        "snapshot_after_utility_evaluation.json",
    }
    assert expected <= {item.name for item in artifact.iterdir()}
    clean = results_by_condition(result)["clean"]
    assert (
        clean.prompt_messages
        and clean.prompt_version
        and len(clean.prompt_sha256) == 64
    )
    assert {"numerator", "denominator", "rate"} <= result["metrics"][
        "overall_asr"
    ].keys()
