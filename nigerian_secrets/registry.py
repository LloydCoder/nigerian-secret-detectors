from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .providers import PROVIDERS, Provider
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
        known_providers = {provider.id for provider in PROVIDERS} | {"crypto", "nigerian-fintech"}
        for rule in self._rules:
            if not rule.id or not rule.provider or not rule.category:
                raise ValueError("detectors require id, provider, and category")
            if rule.severity not in allowed_severities:
                raise ValueError(f"unsupported severity: {rule.severity}")
            if rule.provider not in known_providers:
                raise ValueError(f"unknown provider: {rule.provider}")
        covered = {rule.provider for rule in self._rules}
        missing = sorted(provider.id for provider in PROVIDERS if provider.id not in covered)
        if missing:
            raise ValueError(f"provider corpus has no detector coverage: {', '.join(missing)}")

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

    def provider_metadata(self) -> tuple[Provider, ...]:
        return PROVIDERS

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
