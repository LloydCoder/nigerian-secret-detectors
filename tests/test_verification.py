import pytest

from nigerian_secrets.verification import VERIFIERS, VerificationDisabled, VerificationRegistry, VerificationRequest, VerificationResult, verify


def test_verification_is_disabled_by_default():
    with pytest.raises(VerificationDisabled):
        verify(VerificationRequest("paystack", "synthetic"))


def test_unknown_provider_is_rejected_when_enabled():
    with pytest.raises(VerificationDisabled):
        verify(VerificationRequest("unknown", "synthetic"), enabled=True)


def test_registry_rejects_duplicates():
    registry = VerificationRegistry()

    class Adapter:
        provider = "paystack"

        def verify(self, request):
            return VerificationResult("paystack", "verified", "synthetic")

    registry.register(Adapter())
    with pytest.raises(ValueError):
        registry.register(Adapter())


def test_global_registry_is_empty_by_default():
    assert VERIFIERS.providers() == ()
