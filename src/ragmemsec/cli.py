"""Command line interface for mock, Hugging Face, and local Ollama runs."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from ragmemsec.agent.model_provider import (
    HuggingFaceModelProvider,
    MockModelProvider,
    OllamaModelProvider,
)
from ragmemsec.attacks.scenarios import load_corpus, load_scenario
from ragmemsec.config import MODEL_REGISTRY, load_config
from ragmemsec.evaluation.runner import (
    ExperimentRunner,
    run_model_matrix,
)
from ragmemsec.memory.store import MemoryStore


def build_provider(config, force_mock: bool = False):
    if force_mock or config.provider == "mock":
        return MockModelProvider()
    if config.provider == "huggingface":
        return HuggingFaceModelProvider(
            config.model_id,
            config.device,
            config.precision,
            config.seed,
            config.temperature,
            config.max_new_tokens,
            config.do_sample,
        )
    if config.provider == "ollama":
        return OllamaModelProvider(
            config.model_id,
            config.temperature,
            config.max_new_tokens,
            config.ollama_base_url,
        )
    raise ValueError(f"Unsupported provider: {config.provider}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ragmemsec")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("inspect-models")
    run = sub.add_parser("run-scenario")
    run.add_argument("--config", default="configs/baseline.yaml")
    run.add_argument("--scenario", default="configs/scenarios/orion_access.yaml")
    run.add_argument("--model")
    run.add_argument("--mock", action="store_true")
    matrix = sub.add_parser("run-matrix")
    matrix.add_argument("--config", default="configs/baseline.yaml")
    matrix.add_argument("--corpus", default="configs/scenarios/pilot_v1.yaml")
    matrix.add_argument("--models", nargs="+", required=True)
    matrix.add_argument(
        "--profile", choices=["deterministic_primary", "robustness_subset"]
    )
    matrix.add_argument("--mock", action="store_true")
    inspect = sub.add_parser("inspect-memory")
    inspect.add_argument("--state-dir", default=".ragmemsec-state")
    clear = sub.add_parser("clear-state")
    clear.add_argument("--state-dir", default=".ragmemsec-state")
    clear.add_argument("--yes", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "inspect-models":
        print(json.dumps(MODEL_REGISTRY, indent=2))
        return 0
    if args.command == "inspect-memory":
        print(
            json.dumps(
                MemoryStore(Path(args.state_dir) / "memories.json").snapshot(), indent=2
            )
        )
        return 0
    if args.command == "clear-state":
        if not args.yes:
            parser.error("clear-state requires --yes")
        directory = Path(args.state_dir).resolve()
        if directory.exists():
            shutil.rmtree(directory)
        return 0
    if args.command == "run-matrix":
        config = load_config(args.config)
        if args.profile:
            config.profile = args.profile
        corpus = load_corpus(args.corpus)

        def provider_factory(resolved):
            return build_provider(resolved, args.mock)

        results = run_model_matrix(config, corpus, args.models, provider_factory)
        print(
            json.dumps(
                {
                    "run_kind": results[0]["run_kind"] if results else None,
                    "matrix_size": len(results),
                    "results": results,
                },
                default=lambda value: (
                    value.to_dict() if hasattr(value, "to_dict") else str(value)
                ),
                indent=2,
            )
        )
        return 0
    config = load_config(args.config, args.model)
    scenario = load_scenario(args.scenario)
    provider = build_provider(config, args.mock)
    result = ExperimentRunner(config, scenario, provider).run()
    print(
        json.dumps(
            {
                "run_id": result["run_id"],
                "artifact_dir": result["artifact_dir"],
                "metrics": result["metrics"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
