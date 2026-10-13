"""Independent in-process document store and cosine retriever."""

from __future__ import annotations

from ragmemsec.contracts import DocumentChunk, RetrievalResult
from ragmemsec.rag.embeddings import EmbeddingProvider, cosine


class DocumentRetriever:
    def __init__(self, embedder: EmbeddingProvider) -> None:
        self.embedder = embedder
        self.records: dict[str, DocumentChunk] = {}

    def add(self, record: DocumentChunk) -> None:
        record.embedding = self.embedder.embed(record.text)
        self.records[record.id] = record

    def add_documents(self, records: list[DocumentChunk]) -> None:
        for record in records:
            self.add(record)

    def remove(self, record_id: str) -> bool:
        return self.records.pop(record_id, None) is not None

    def clear(self) -> None:
        self.records.clear()

    def inspect_all(self) -> list[DocumentChunk]:
        return list(self.records.values())

    def retrieve(self, query: str, top_k: int) -> list[RetrievalResult]:
        query_embedding = self.embedder.embed(query)
        scored = sorted(
            (
                (cosine(query_embedding, item.embedding or []), item)
                for item in self.records.values()
            ),
            key=lambda value: (-value[0], value[1].id),
        )[:top_k]
        return [
            RetrievalResult(
                item.id,
                "document",
                item.text,
                score,
                rank,
                {
                    **item.metadata,
                    "source_id": item.source_id,
                    "source_type": item.source_type,
                    "trusted": item.trusted,
                },
            )
            for rank, (score, item) in enumerate(scored, 1)
        ]
