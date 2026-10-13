"""JSON-persisted memory store, deliberately separate from RAG documents."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from ragmemsec.contracts import MemoryRecord


class MemoryStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.records: dict[str, MemoryRecord] = {}
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            self.records = {
                item["id"]: MemoryRecord(**item)
                for item in json.loads(self.path.read_text())
            }

    def _save(self) -> None:
        self.path.write_text(
            json.dumps([asdict(item) for item in self.records.values()], indent=2),
            encoding="utf-8",
        )

    def add(self, record: MemoryRecord) -> None:
        self.records[record.id] = record
        self._save()

    def remove(self, record_id: str) -> bool:
        removed = self.records.pop(record_id, None) is not None
        if removed:
            self._save()
        return removed

    def clear(self) -> None:
        self.records.clear()
        self._save()

    def inspect_all(self) -> list[MemoryRecord]:
        return list(self.records.values())

    def snapshot(self) -> list[dict]:
        return [asdict(item) for item in self.records.values()]

    def restore(self, snapshot: list[dict]) -> None:
        self.records = {item["id"]: MemoryRecord(**item) for item in snapshot}
        self._save()
