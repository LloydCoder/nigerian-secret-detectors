from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any


@dataclass(frozen=True)
class Finding:
    detector_id: str
    provider: str
    category: str
    severity: str
    confidence: float
    path: str
    line: int
    column: int
    match: str
    redacted_match: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
