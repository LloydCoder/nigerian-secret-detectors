import pytest

from nigerian_secrets.verification import VERIFIERS, VerificationDisabled, VerificationRegistry, VerificationRequest, VerificationResult, verify


def test_verification_is_disabled_by_default():
    with pytest.raises(VerificationDisabled):
        verify(VerificationRequest("paystack", "synthetic"))


def test_unknown_provider_is_explicitly_unsupported_when_enabled():
    result = verify(VerificationRequest("unknown", "synthetic"), enabled=True)
    assert result.status == "unsupported"
    assert result.status != "invalid"


def test_registry_rejects_duplicates_and_invalid_statuses():
    registry = VerificationRegistry()

    class Adapter:
        provider = "paystack"

        def verify(self, request):
            return VerificationResult("paystack", "unknown", "synthetic")

    registry.register(Adapter())
    with pytest.raises(ValueError):
        registry.register(Adapter())
    with pytest.raises(ValueError):
        VerificationResult("paystack", "verified", "synthetic")


def test_global_registry_is_empty_by_default():
    assert VERIFIERS.providers() == ()
