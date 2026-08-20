from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class VerificationRequest:
    provider: str
    secret: str


@dataclass(frozen=True)
class VerificationResult:
    provider: str
    status: str
    message: str


class VerificationAdapter(Protocol):
    provider: str

    def verify(self, request: VerificationRequest) -> VerificationResult:
        """Verify a credential using a provider-approved mechanism."""


class VerificationDisabled(RuntimeError):
    pass


class DisabledAdapter:
    provider = "*"

    def verify(self, request: VerificationRequest) -> VerificationResult:
        raise VerificationDisabled(
            "Live verification is disabled by default; no credential was transmitted."
        )


class VerificationRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, VerificationAdapter] = {}

    def register(self, adapter: VerificationAdapter) -> None:
        if not adapter.provider:
            raise ValueError("verification adapter provider cannot be empty")
        if adapter.provider in self._adapters:
            raise ValueError(f"duplicate verification adapter: {adapter.provider}")
        self._adapters[adapter.provider] = adapter

    def get(self, provider: str) -> VerificationAdapter | None:
        return self._adapters.get(provider)

    def providers(self) -> tuple[str, ...]:
        return tuple(sorted(self._adapters))


VERIFIERS = VerificationRegistry()


def verify(request: VerificationRequest, *, enabled: bool = False) -> VerificationResult:
    if not enabled:
        raise VerificationDisabled(
            "Live verification is opt-in. Use an explicitly configured adapter and enable verification."
        )
    adapter = VERIFIERS.get(request.provider)
    if adapter is None:
        raise VerificationDisabled(f"No verification adapter is registered for {request.provider}")
    return adapter.verify(request)
