"""Configuration loading.  The tiny YAML reader keeps mock tests dependency-free."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from importlib import resources
from pathlib import Path
from typing import Any


@dataclass
class BaselineConfig:
    model: str = "qwen2.5-7b"
    provider: str = "huggingface"
    seed: int = 42
    temperature: float = 0.0
    do_sample: bool = False
    max_new_tokens: int = 512
    device: str = "cuda"
    precision: str = "bf16"
    embedding_model: str = "BAAI/bge-small-en-v1.5"
    document_top_k: int = 3
    memory_top_k: int = 3
    state_dir: str = ".ragmemsec-state"
    artifacts_dir: str = "artifacts/runs"
    profile: str = "deterministic_primary"
    scenario_order_seed: int = 42
    ollama_base_url: str | None = None

    @property
    def model_id(self) -> str:
        try:
            return load_model_registry()[self.model]["model_id"]
        except KeyError as exc:
            raise ValueError(f"Unknown model alias: {self.model}") from exc

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _scalar(value: str) -> Any:
    value = value.strip()
    if value.lower() in {"true", "false"}:
        return value.lower() == "true"
    if value.lower() in {"null", "none"}:
        return None
    try:
        return int(value)
    except ValueError:
        try:
            return float(value)
        except ValueError:
            return value.strip("\"'")


def load_mapping(path: str | Path) -> dict[str, Any]:
    text = Path(path).read_text(encoding="utf-8")
    try:
        value = json.loads(text)
        if isinstance(value, dict):
            return value
    except json.JSONDecodeError:
        pass
    result: dict[str, Any] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            raise ValueError(f"Unsupported YAML line in {path}: {line}")
        key, value = line.split(":", 1)
        result[key.strip()] = _scalar(value.split("#", 1)[0])
    return result


def load_model_registry() -> dict[str, dict[str, str]]:
    """Load the one authoritative, packaged model-alias registry."""
    resource = resources.files("ragmemsec").joinpath("data/models.yaml")
    try:
        data = json.loads(resource.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("Could not load the packaged model registry.") from exc
    if not all(
        isinstance(value, dict) and "model_id" in value for value in data.values()
    ):
        raise ValueError(
            "The packaged model registry must map aliases to objects with model_id"
        )
    return data


# Compatibility export for callers; the data itself remains file-authoritative.
MODEL_REGISTRY = load_model_registry()


def load_config(path: str | Path, model_override: str | None = None) -> BaselineConfig:
    values = load_mapping(path)
    if model_override:
        values["model"] = model_override
    allowed = set(BaselineConfig.__dataclass_fields__)
    config = BaselineConfig(**{k: v for k, v in values.items() if k in allowed})
    _ = config.model_id
    return config
