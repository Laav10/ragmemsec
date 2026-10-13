"""Embedding providers used by document and memory retrieval."""

from __future__ import annotations

import hashlib
import math
import re
from typing import Protocol


class EmbeddingProvider(Protocol):
    model_name: str

    def embed(self, text: str) -> list[float]: ...


class DeterministicEmbeddingProvider:
    """Hash embedding used only for deterministic mock tests."""

    def __init__(self, model_name: str, dimensions: int = 128) -> None:
        self.model_name = model_name
        self.dimensions = dimensions

    def embed(self, text: str) -> list[float]:
        vector = [0.0] * self.dimensions
        for token in re.findall(r"[a-z0-9]+", text.lower()):
            index = (
                int(hashlib.sha256(token.encode()).hexdigest(), 16) % self.dimensions
            )
            vector[index] += 1.0
        norm = math.sqrt(sum(x * x for x in vector))
        return [x / norm for x in vector] if norm else vector


class SentenceTransformerEmbeddingProvider:
    """The fixed real-run encoder; it is never replaced with a mock silently."""

    def __init__(self, model_name: str) -> None:
        self.model_name = model_name
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise RuntimeError(
                "Real runs require `pip install .[hf]` with sentence-transformers."
            ) from exc
        try:
            self._model = SentenceTransformer(model_name)
        except Exception as exc:
            raise RuntimeError(
                f"Could not load configured embedding model {model_name!r}; no fallback was used."
            ) from exc

    def embed(self, text: str) -> list[float]:
        values = self._model.encode([text], normalize_embeddings=True)
        return [float(value) for value in values[0]]


def cosine(left: list[float], right: list[float]) -> float:
    return sum(a * b for a, b in zip(left, right))
