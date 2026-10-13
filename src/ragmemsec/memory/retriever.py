"""Cosine retrieval over persistent memory records."""

from __future__ import annotations

from ragmemsec.contracts import MemoryRecord, RetrievalResult
from ragmemsec.memory.store import MemoryStore
from ragmemsec.rag.embeddings import EmbeddingProvider, cosine


class MemoryRetriever:
    def __init__(self, store: MemoryStore, embedder: EmbeddingProvider) -> None:
        self.store, self.embedder = store, embedder

    def retrieve(self, query: str, top_k: int) -> list[RetrievalResult]:
        query_embedding = self.embedder.embed(query)
        scored: list[tuple[float, MemoryRecord]] = []
        for item in self.store.inspect_all():
            if item.embedding is None:
                item.embedding = self.embedder.embed(item.text)
            scored.append((cosine(query_embedding, item.embedding), item))
        scored.sort(key=lambda value: (-value[0], value[1].id))
        return [
            RetrievalResult(
                item.id,
                "memory",
                item.text,
                score,
                rank,
                {
                    **item.metadata,
                    "source_ids": item.source_ids,
                    "source_types": item.source_types,
                    "trusted": item.trusted,
                },
            )
            for rank, (score, item) in enumerate(scored[:top_k], 1)
        ]
