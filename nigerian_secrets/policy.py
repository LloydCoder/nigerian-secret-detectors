from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json


@dataclass(frozen=True)
class ScanPolicy:
    fail_on: str = "high"
    max_file_size: int = 2 * 1024 * 1024
    excluded_dirs: frozenset[str] = frozenset({".git", ".venv", "venv", "node_modules", "dist", "build", "coverage"})

    def should_fail(self, findings: list[object]) -> bool:
        order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        threshold = order.get(self.fail_on, 3)
        return any(order.get(getattr(f, "severity", "low"), 1) >= threshold for f in findings)


def load_policy(path: str | Path | None) -> ScanPolicy:
    if path is None:
        return ScanPolicy()
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return ScanPolicy(
        fail_on=str(data.get("fail_on", "high")),
        max_file_size=int(data.get("max_file_size", 2 * 1024 * 1024)),
        excluded_dirs=frozenset(data.get("excluded_dirs", ScanPolicy().excluded_dirs)),
    )
