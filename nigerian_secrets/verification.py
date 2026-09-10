from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, ClassVar

VERIFICATION_STATUSES = frozenset({"valid", "invalid", "unknown", "unsupported", "rate_limited", "error"})


@dataclass(frozen=True)
class VerificationRequest:
    provider: str
    secret: str

    def __post_init__(self) -> None:
        if not self.provider or not self.secret:
            raise ValueError("provider and secret are required")


@dataclass(frozen=True)
class VerificationResult:
    provider: str
    status: str
    message: str

    def __post_init__(self) -> None:
        if self.status not in VERIFICATION_STATUSES:
            raise ValueError(f"unsupported verification status: {self.status}")
        if not self.provider:
            raise ValueError("verification provider cannot be empty")


class VerificationAdapter(Protocol):
    provider: ClassVar[str]

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
        return VerificationResult(request.provider, "unsupported", "No verification adapter is registered.")
    result = adapter.verify(request)
    if result.provider != request.provider:
        raise VerificationDisabled("verification adapter returned a mismatched provider")
    return result
