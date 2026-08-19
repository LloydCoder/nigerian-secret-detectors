from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .rules import RULES, Rule


@dataclass(frozen=True)
class DetectorMetadata:
    id: str
    provider: str
    category: str
    severity: str
    description: str


class DetectorRegistry:
    """Validated, deterministic registry for native detection rules."""

    def __init__(self, rules: Iterable[Rule]):
        self._rules = tuple(rules)
        self._validate()

    def _validate(self) -> None:
        ids = [rule.id for rule in self._rules]
        if len(ids) != len(set(ids)):
            raise ValueError("detector IDs must be unique")
        allowed_severities = {"low", "medium", "high", "critical"}
        for rule in self._rules:
            if not rule.id or not rule.provider or not rule.category:
                raise ValueError("detectors require id, provider, and category")
            if rule.severity not in allowed_severities:
                raise ValueError(f"unsupported severity: {rule.severity}")

    @property
    def rules(self) -> tuple[Rule, ...]:
        return self._rules

    def get(self, detector_id: str) -> Rule:
        for rule in self._rules:
            if rule.id == detector_id:
                return rule
        raise KeyError(detector_id)

    def providers(self) -> tuple[str, ...]:
        return tuple(sorted({rule.provider for rule in self._rules}))

    def metadata(self) -> tuple[DetectorMetadata, ...]:
        return tuple(
            DetectorMetadata(
                id=rule.id,
                provider=rule.provider,
                category=rule.category,
                severity=rule.severity,
                description=rule.message,
            )
            for rule in self._rules
        )


REGISTRY = DetectorRegistry(RULES)
