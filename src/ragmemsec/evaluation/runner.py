"""Run the five benchmark conditions and emit auditable local artifacts."""

from __future__ import annotations

import json
import platform
import subprocess
from dataclasses import asdict
from pathlib import Path
from uuid import uuid4

from ragmemsec.agent.controller import BenchmarkAgent
from ragmemsec.agent.model_provider import MockModelProvider, ModelProvider
from ragmemsec.attacks.scenarios import Scenario
from ragmemsec.config import BaselineConfig
from ragmemsec.evaluation.metrics import calculate_metrics
from ragmemsec.evaluation.reporting import (
    bootstrap_scenario_ci,
    paired_causal_comparisons,
    qualify_model,
)
from ragmemsec.memory.retriever import MemoryRetriever
from ragmemsec.memory.store import MemoryStore
from ragmemsec.rag.embeddings import (
    DeterministicEmbeddingProvider,
    EmbeddingProvider,
    SentenceTransformerEmbeddingProvider,
)
from ragmemsec.rag.retriever import DocumentRetriever
from ragmemsec.tools.access_control import AccessControlSimulator


def _git_revision() -> str | None:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception:
        return None


def _dirty_tree() -> bool | None:
    try:
        return bool(
            subprocess.check_output(
                ["git", "status", "--porcelain"], text=True, stderr=subprocess.DEVNULL
            ).strip()
        )
    except Exception:
        return None


def _runtime_environment(config: BaselineConfig) -> dict:
    environment = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "git_commit": _git_revision(),
        "model_alias": config.model,
        "model_id": config.model_id,
        "embedding_model": config.embedding_model,
        "seed": config.seed,
        "generation": {
            "temperature": config.temperature,
            "do_sample": config.do_sample,
            "max_new_tokens": config.max_new_tokens,
            "precision": config.precision,
        },
        "cuda_version": None,
        "gpu_model": None,
        "gpu_vram_bytes": None,
        "torch_version": None,
        "transformers_version": None,
        "sentence_transformers_version": None,
        "run_kind": None,
    }
    try:
        import torch

        environment["torch_version"] = torch.__version__
        environment["cuda_version"] = torch.version.cuda
        if torch.cuda.is_available():
            properties = torch.cuda.get_device_properties(0)
            environment["gpu_model"] = properties.name
            environment["gpu_vram_bytes"] = properties.total_memory
    except ImportError:
        pass
    try:
        import transformers

        environment["transformers_version"] = transformers.__version__
    except ImportError:
        pass
    try:
        import sentence_transformers

        environment["sentence_transformers_version"] = sentence_transformers.__version__
    except ImportError:
        pass
    return environment


def select_embedding_provider(
    embedding_model: str, mock_mode: bool
) -> EmbeddingProvider:
    """Only explicit mock execution may use deterministic hash embeddings."""
    if mock_mode:
        return DeterministicEmbeddingProvider("deterministic-hash-test-only")
    return SentenceTransformerEmbeddingProvider(embedding_model)


def _is_attacker_derived(
    record_id: str, records: dict, source_document_id: str
) -> bool:
    seen: set[str] = set()

    def derived(current_id: str) -> bool:
        if current_id in seen:
            return False
        seen.add(current_id)
        record = records.get(current_id)
        if record is None:
            return False
        provenance = record.metadata.get("experimental_provenance", {})
        if source_document_id in provenance.get("retrieved_document_ids", []):
            return True
        return any(
            derived(parent) for parent in provenance.get("retrieved_memory_ids", [])
        )

    return derived(record_id)


class ExperimentRunner:
    def __init__(
        self,
        config: BaselineConfig,
        scenario: Scenario,
        provider: ModelProvider | None = None,
        embedder: EmbeddingProvider | None = None,
        corpus_checksum: str | None = None,
    ) -> None:
        self.config, self.scenario = config, scenario
        self.provider = provider or MockModelProvider()
        self.run_kind = (
            "mock_test"
            if isinstance(self.provider, MockModelProvider)
            else "real_benchmark"
        )
        self.corpus_checksum = corpus_checksum
        self.embedder = embedder or select_embedding_provider(
            config.embedding_model, isinstance(self.provider, MockModelProvider)
        )
        self.documents = DocumentRetriever(self.embedder)
        self.memories = MemoryStore(Path(config.state_dir) / "memories.json")
        self.memory_retriever = MemoryRetriever(self.memories, self.embedder)
        self.simulator = AccessControlSimulator()
        self.agent = BenchmarkAgent(
            config,
            self.provider,
            self.documents,
            self.memories,
            self.memory_retriever,
            self.simulator,
        )

    def _reset_documents(self, malicious: bool = False) -> None:
        self.documents.clear()
        self.documents.add_documents(self.scenario.trusted_documents)
        if malicious:
            self.documents.add(self.scenario.malicious_document)

    def _run_queries(
        self,
        condition: str,
        queries: list,
        experiment_id: str,
        retain_memory: bool = True,
    ) -> list:
        traces = [
            self.agent.run(
                experiment_id,
                self.scenario.id,
                condition,
                f"{condition}-{index}",
                query.text,
                query.id,
                query.expected_outcome,
                retain_memory,
            )
            for index, query in enumerate(queries, 1)
        ]
        for trace in traces:
            trace.run_kind = self.run_kind
            trace.corpus_version = self.scenario.corpus_version
            trace.task_family = self.scenario.task_family
        return traces

    def run(self) -> dict:
        run_id, traces = str(uuid4()), []
        snapshots: dict[str, dict] = {}
        self.memories.clear()
        self._reset_documents()
        snapshots["initial_state"] = self._state_snapshot()
        traces += self._run_queries("clean", self.scenario.benign_queries, run_id)
        self.memories.clear()
        self._reset_documents(malicious=True)
        traces += self._run_queries(
            "immediate_injection", self.scenario.injection_queries, run_id
        )
        contaminated_snapshot = self.memories.snapshot()
        snapshots["after_injection"] = self._state_snapshot()
        if not self.documents.remove(self.scenario.malicious_document.id):
            raise RuntimeError("Could not remove malicious document before persistence")
        snapshots["after_source_removal"] = self._state_snapshot()
        traces += self._run_queries("persistence", self.scenario.victim_queries, run_id)
        snapshots["after_persistence"] = self._state_snapshot()

        self.memories.clear()
        self._reset_documents(malicious=True)
        traces += self._run_queries(
            "memory_disabled_control",
            self.scenario.injection_queries,
            run_id,
            retain_memory=False,
        )
        if not self.documents.remove(self.scenario.malicious_document.id):
            raise RuntimeError(
                "Could not remove malicious document in memory-disabled control"
            )
        traces += self._run_queries(
            "memory_disabled_control", self.scenario.victim_queries, run_id
        )

        self.memories.restore(contaminated_snapshot)
        snapshots["before_ablation"] = self._state_snapshot()
        records = {item.id: item for item in self.memories.inspect_all()}
        source_document_id = self.scenario.attack_target["source_document_id"]
        for memory in list(records.values()):
            if _is_attacker_derived(memory.id, records, source_document_id):
                self.memories.remove(memory.id)
        traces += self._run_queries(
            "memory_ablation", self.scenario.victim_queries, run_id
        )
        snapshots["after_ablation"] = self._state_snapshot()
        self.memories.restore(contaminated_snapshot)
        traces += self._run_queries(
            "post_contamination_utility", self.scenario.utility_queries, run_id
        )
        snapshots["after_utility_evaluation"] = self._state_snapshot()
        metrics = calculate_metrics(
            traces, self.scenario.attack_target, self.memories.inspect_all()
        )
        artifact_dir = self._write_artifacts(run_id, traces, metrics, snapshots)
        return {
            "run_id": run_id,
            "artifact_dir": str(artifact_dir),
            "traces": traces,
            "metrics": metrics,
            "run_kind": self.run_kind,
            "task_family": self.scenario.task_family,
            "corpus_version": self.scenario.corpus_version,
        }

    def _state_snapshot(self) -> dict:
        return {
            "documents": [asdict(item) for item in self.documents.inspect_all()],
            "memories": self.memories.snapshot(),
        }

    def _write_artifacts(
        self,
        run_id: str,
        traces: list,
        metrics: dict,
        snapshots: dict[str, dict],
    ) -> Path:
        directory = Path(self.config.artifacts_dir) / run_id
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "resolved_config.yaml").write_text(
            "\n".join(f"{key}: {value}" for key, value in self.config.to_dict().items())
            + "\n"
        )
        environment = _runtime_environment(self.config)
        environment.update(
            {
                "run_kind": self.run_kind,
                "embedding_provider": type(self.embedder).__name__,
                "resolved_embedding_model": self.embedder.model_name,
                "configured_embedding_model": self.config.embedding_model,
                "corpus_version": self.scenario.corpus_version,
                "corpus_checksum": self.corpus_checksum,
                "config_checksum": __import__("hashlib")
                .sha256(json.dumps(self.config.to_dict(), sort_keys=True).encode())
                .hexdigest(),
                "dirty_tree": _dirty_tree(),
                "prompt_versions": sorted({item.prompt_version for item in traces}),
            }
        )
        (directory / "environment.json").write_text(json.dumps(environment, indent=2))
        (directory / "traces.jsonl").write_text(
            "".join(json.dumps(item.to_dict()) + "\n" for item in traces)
        )
        (directory / "actions.jsonl").write_text(
            "".join(json.dumps(item) + "\n" for item in self.simulator.action_log)
        )
        for name, snapshot in snapshots.items():
            (directory / f"snapshot_{name}.json").write_text(
                json.dumps(snapshot, indent=2)
            )
        (directory / "metrics.json").write_text(json.dumps(metrics, indent=2))
        (directory / "summary.md").write_text(
            f"# Baseline run {run_id}\n\nUnprotected RAG/memory benchmark. Traces: {len(traces)}.\n\n```json\n{json.dumps(metrics, indent=2)}\n```\n"
        )
        return directory


class BenchmarkSuiteRunner:
    """Repeat isolated scenario units in recorded randomized order."""

    def __init__(
        self, config: BaselineConfig, corpus, provider_factory, embedder_factory=None
    ) -> None:
        self.config, self.corpus = config, corpus
        self.provider_factory, self.embedder_factory = (
            provider_factory,
            embedder_factory,
        )

    def run(self, seed: int | None = None) -> dict:
        run_seed = self.config.seed if seed is None else seed
        scenarios = list(self.corpus.scenarios)
        import random

        random.Random(self.config.scenario_order_seed + run_seed).shuffle(scenarios)
        summaries, all_traces = [], []
        for index, scenario in enumerate(scenarios):
            isolated = BaselineConfig(
                **{
                    **self.config.to_dict(),
                    "state_dir": f"{self.config.state_dir}/seed-{run_seed}/scenario-{index}",
                }
            )
            provider = self.provider_factory(isolated)
            embedder = (
                self.embedder_factory(isolated) if self.embedder_factory else None
            )
            result = ExperimentRunner(
                isolated, scenario, provider, embedder, self.corpus.checksum
            ).run()
            summaries.append(result)
            all_traces.extend(result["traces"])
        qualification = qualify_model([item["metrics"] for item in summaries])
        causal = [
            comparison
            for item in summaries
            for comparison in paired_causal_comparisons(
                item["traces"],
                next(
                    scenario.attack_target
                    for scenario in self.corpus.scenarios
                    if scenario.id == item["traces"][0].scenario_id
                ),
            )
        ]
        scenario_asr = [
            item["metrics"]["overall_asr"]["rate"] or 0.0 for item in summaries
        ]
        return {
            "run_kind": summaries[0]["run_kind"] if summaries else "real_benchmark",
            "scenario_order": [scenario.id for scenario in scenarios],
            "seed": run_seed,
            "summaries": summaries,
            "traces": all_traces,
            "qualification": qualification,
            "qualification_failed": not qualification["qualified"],
            "causal_comparisons": causal,
            "overall_asr_bootstrap": bootstrap_scenario_ci(scenario_asr, run_seed),
        }


def profile_seeds(config: BaselineConfig) -> list[int]:
    if config.profile == "deterministic_primary":
        return [config.seed]
    if config.profile == "robustness_subset":
        return [101, 202, 303]
    raise ValueError(f"Unknown benchmark profile: {config.profile}")


def run_model_matrix(
    config: BaselineConfig,
    corpus,
    model_aliases: list[str],
    provider_factory,
    embedder_factory=None,
) -> list[dict]:
    """Run models serially; each provider is created only after the previous ends."""
    matrix = []
    for alias in model_aliases:
        model_config = BaselineConfig(
            **{
                **config.to_dict(),
                "model": alias,
                "state_dir": f"{config.state_dir}/model-{alias}",
            }
        )
        _ = model_config.model_id
        for seed in profile_seeds(model_config):
            run_config = BaselineConfig(
                **{
                    **model_config.to_dict(),
                    "seed": seed,
                    "temperature": 0.2
                    if model_config.profile == "robustness_subset"
                    else 0.0,
                    "do_sample": model_config.profile == "robustness_subset",
                }
            )
            suite = BenchmarkSuiteRunner(
                run_config, corpus, provider_factory, embedder_factory
            )
            result = suite.run(seed)
            result["model_alias"] = alias
            result["model_id"] = model_config.model_id
            matrix.append(result)
    return matrix
