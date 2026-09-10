from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
from typing import Mapping, Any


DEFAULT_EXCLUDED_DIRS = frozenset({".git", ".venv", "venv", "node_modules", "dist", "build", "coverage"})
MAX_ALLOWED_FILE_SIZE = 50 * 1024 * 1024
MAX_ALLOWED_FILES = 100_000


@dataclass(frozen=True)
class ScanPolicy:
    fail_on: str = "high"
    max_file_size: int = 2 * 1024 * 1024
    max_files: int = 10_000
    excluded_dirs: frozenset[str] = DEFAULT_EXCLUDED_DIRS

    def __post_init__(self) -> None:
        if self.fail_on not in {"low", "medium", "high", "critical", "none"}:
            raise ValueError("fail_on must be low, medium, high, critical, or none")
        if isinstance(self.max_file_size, bool) or not isinstance(self.max_file_size, int) or not 0 < self.max_file_size <= MAX_ALLOWED_FILE_SIZE:
            raise ValueError(f"max_file_size must be an integer between 1 and {MAX_ALLOWED_FILE_SIZE}")
        if isinstance(self.max_files, bool) or not isinstance(self.max_files, int) or not 0 < self.max_files <= MAX_ALLOWED_FILES:
            raise ValueError(f"max_files must be an integer between 1 and {MAX_ALLOWED_FILES}")
        if not all(isinstance(item, str) and item for item in self.excluded_dirs):
            raise ValueError("excluded_dirs must contain non-empty strings")

    def should_fail(self, findings: list[object]) -> bool:
        if self.fail_on == "none":
            return False
        order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        threshold = order[self.fail_on]
        return any(order.get(getattr(f, "severity", "low"), 1) >= threshold for f in findings)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any] | None) -> "ScanPolicy":
        if data is None:
            return cls()
        if not isinstance(data, Mapping):
            raise ValueError("policy must be an object")
        excluded = data.get("excluded_dirs", list(DEFAULT_EXCLUDED_DIRS))
        if not isinstance(excluded, list) or not all(isinstance(item, str) and item for item in excluded):
            raise ValueError("excluded_dirs must be a list of non-empty strings")
        fail_on = data.get("fail_on", "high")
        max_file_size = data.get("max_file_size", 2 * 1024 * 1024)
        max_files = data.get("max_files", 10_000)
        if not isinstance(fail_on, str):
            raise ValueError("fail_on must be a string")
        if isinstance(max_file_size, bool) or not isinstance(max_file_size, int):
            raise ValueError("max_file_size must be an integer")
        if isinstance(max_files, bool) or not isinstance(max_files, int):
            raise ValueError("max_files must be an integer")
        return cls(
            fail_on=fail_on,
            max_file_size=max_file_size,
            max_files=max_files,
            excluded_dirs=frozenset(excluded),
        )


def load_policy(path: str | Path | None) -> ScanPolicy:
    if path is None:
        return ScanPolicy()
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return ScanPolicy.from_mapping(data)
