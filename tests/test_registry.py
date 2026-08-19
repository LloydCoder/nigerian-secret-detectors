from nigerian_secrets.registry import REGISTRY


def test_registry_has_unique_detector_ids():
    ids = [rule.id for rule in REGISTRY.rules]
    assert len(ids) == len(set(ids))


def test_registry_exposes_provider_metadata():
    assert "paystack" in REGISTRY.providers()
    assert "flutterwave" in REGISTRY.providers()
    assert REGISTRY.get("paystack-secret-key").severity == "critical"


def test_registry_metadata_is_stable():
    metadata = REGISTRY.metadata()
    assert metadata
    assert all(item.id and item.provider and item.category for item in metadata)
