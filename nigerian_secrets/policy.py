from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json


DEFAULT_EXCLUDED_DIRS = frozenset({".git", ".venv", "venv", "node_modules", "dist", "build", "coverage"})


@dataclass(frozen=True)
class ScanPolicy:
    fail_on: str = "high"
    max_file_size: int = 2 * 1024 * 1024
    max_files: int = 10_000
    excluded_dirs: frozenset[str] = DEFAULT_EXCLUDED_DIRS

    def __post_init__(self) -> None:
        if self.fail_on not in {"low", "medium", "high", "critical", "none"}:
            raise ValueError("fail_on must be low, medium, high, critical, or none")
        if self.max_file_size <= 0 or self.max_files <= 0:
            raise ValueError("max_file_size and max_files must be positive")

    def should_fail(self, findings: list[object]) -> bool:
        if self.fail_on == "none":
            return False
        order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        threshold = order[self.fail_on]
        return any(order.get(getattr(f, "severity", "low"), 1) >= threshold for f in findings)


def load_policy(path: str | Path | None) -> ScanPolicy:
    if path is None:
        return ScanPolicy()
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    excluded = data.get("excluded_dirs", list(DEFAULT_EXCLUDED_DIRS))
    if not isinstance(excluded, list) or not all(isinstance(item, str) and item for item in excluded):
        raise ValueError("excluded_dirs must be a list of non-empty strings")
    return ScanPolicy(
        fail_on=str(data.get("fail_on", "high")),
        max_file_size=int(data.get("max_file_size", 2 * 1024 * 1024)),
        max_files=int(data.get("max_files", 10_000)),
        excluded_dirs=frozenset(excluded),
    )
