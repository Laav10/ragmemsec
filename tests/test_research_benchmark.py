"""Research-benchmark corpus, reporting, and isolation regression tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ragmemsec.agent.model_provider import MockModelProvider
from ragmemsec.attacks.scenarios import ScenarioCorpus, load_corpus
from ragmemsec.config import BaselineConfig
from ragmemsec.evaluation.reporting import (
    aggregate_real_benchmark_runs,
    bootstrap_scenario_ci,
    qualify_model,
)
from ragmemsec.evaluation.runner import (
    BenchmarkSuiteRunner,
    ExperimentRunner,
    run_model_matrix,
)

ROOT = Path(__file__).parents[1]


def corpus():
    return load_corpus(ROOT / "configs/scenarios/pilot_v1.yaml")


def config(tmp_path: Path) -> BaselineConfig:
    return BaselineConfig(
        provider="mock",
        state_dir=str(tmp_path / "state"),
        artifacts_dir=str(tmp_path / "artifacts"),
    )


def test_pilot_corpus_has_twelve_valid_separated_scenarios():
    pilot = corpus()
    assert len(pilot.scenarios) == 12
    assert {scenario.task_family for scenario in pilot.scenarios} == {
        "database_access",
        "credential_recovery",
        "data_export",
    }
    for scenario in pilot.scenarios:
        assert len(scenario.injection_queries) >= 2
        assert len(scenario.victim_queries) >= 3
        assert len(scenario.utility_queries) >= 3
        assert not {query.text for query in scenario.injection_queries} & {
            query.text for query in scenario.victim_queries
        }


def test_mock_artifact_is_explicitly_test_only(tmp_path: Path):
    pilot = corpus()
    result = ExperimentRunner(
        config(tmp_path),
        pilot.scenarios[0],
        MockModelProvider(),
        corpus_checksum=pilot.checksum,
    ).run()
    environment = json.loads(
        (Path(result["artifact_dir"]) / "environment.json").read_text()
    )
    assert result["run_kind"] == "mock_test"
    assert environment["run_kind"] == "mock_test"
    assert environment["embedding_provider"] == "DeterministicEmbeddingProvider"
    assert environment["resolved_embedding_model"] == "deterministic-hash-test-only"


def test_mock_results_cannot_enter_real_aggregate():
    with pytest.raises(ValueError, match="Refusing"):
        aggregate_real_benchmark_runs(
            [
                {
                    "run_kind": "real_benchmark",
                    "task_family": "database_access",
                    "metrics": {"overall_asr": {"rate": 0.2}},
                },
                {
                    "run_kind": "mock_test",
                    "task_family": "data_export",
                    "metrics": {"overall_asr": {"rate": 0.1}},
                },
            ]
        )


def test_qualification_pass_and_fail():
    passed = qualify_model(
        [
            {
                "clean_task_success": {"rate": 0.8},
                "structured_output_validity": {"rate": 0.95},
            }
        ]
    )
    failed = qualify_model(
        [
            {
                "clean_task_success": {"rate": 0.6},
                "structured_output_validity": {"rate": 1.0},
            }
        ]
    )
    assert passed["qualified"] is True
    assert failed["qualified"] is False


def test_causal_pairs_bootstrap_and_scenario_order_are_reproducible(tmp_path: Path):
    pilot = corpus()
    subset = ScenarioCorpus(pilot.version, pilot.scenarios[:1], pilot.checksum)
    first = BenchmarkSuiteRunner(
        config(tmp_path / "one"), subset, lambda _: MockModelProvider()
    ).run()
    second = BenchmarkSuiteRunner(
        config(tmp_path / "two"), subset, lambda _: MockModelProvider()
    ).run()
    assert first["scenario_order"] == second["scenario_order"]
    assert len(first["causal_comparisons"]) == 6
    assert bootstrap_scenario_ci([0.0, 1.0], 17) == bootstrap_scenario_ci(
        [0.0, 1.0], 17
    )


def test_scenario_state_isolation_and_per_condition_reporting(tmp_path: Path):
    pilot = corpus()
    subset = ScenarioCorpus(pilot.version, pilot.scenarios[:2], pilot.checksum)
    report = BenchmarkSuiteRunner(
        config(tmp_path), subset, lambda _: MockModelProvider()
    ).run()
    for summary in report["summaries"]:
        assert {
            "clean",
            "immediate_injection",
            "persistence",
            "memory_ablation",
            "memory_disabled_control",
            "post_contamination_utility",
        } <= {trace.condition for trace in summary["traces"]}
        initial = json.loads(
            (Path(summary["artifact_dir"]) / "snapshot_initial_state.json").read_text()
        )
        assert initial["memories"] == []
    assert len(report["summaries"]) == 2


def test_matrix_runs_models_serially_and_keeps_model_state_isolated(tmp_path: Path):
    pilot = corpus()
    subset = ScenarioCorpus(pilot.version, pilot.scenarios[:1], pilot.checksum)
    created = []

    def factory(resolved):
        created.append(resolved.model)
        return MockModelProvider()

    results = run_model_matrix(
        config(tmp_path), subset, ["qwen2.5-7b", "llama3.1-8b"], factory
    )
    assert created == ["qwen2.5-7b", "llama3.1-8b"]
    assert [result["model_alias"] for result in results] == created
    assert all(result["run_kind"] == "mock_test" for result in results)
    config_checksums = [
        json.loads(
            (
                Path(result["summaries"][0]["artifact_dir"]) / "environment.json"
            ).read_text()
        )["config_checksum"]
        for result in results
    ]
    assert len(set(config_checksums)) == 2


def test_robustness_profile_uses_fixed_seeds_and_sampling(tmp_path: Path):
    pilot = corpus()
    subset = ScenarioCorpus(pilot.version, pilot.scenarios[:1], pilot.checksum)
    settings = []

    def factory(resolved):
        settings.append((resolved.seed, resolved.temperature, resolved.do_sample))
        return MockModelProvider()

    resolved = config(tmp_path)
    resolved.profile = "robustness_subset"
    report = run_model_matrix(resolved, subset, ["qwen2.5-7b"], factory)
    assert [item["seed"] for item in report] == [101, 202, 303]
    assert settings == [(101, 0.2, True), (202, 0.2, True), (303, 0.2, True)]
