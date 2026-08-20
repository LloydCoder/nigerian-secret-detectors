from nigerian_secrets.api import Handler
from nigerian_secrets.policy import ScanPolicy


def test_default_policy_fails_on_high() -> None:
    finding = type("Finding", (), {"severity": "high"})()
    assert ScanPolicy().should_fail([finding])


def test_policy_does_not_fail_on_lower_severity() -> None:
    finding = type("Finding", (), {"severity": "medium"})()
    assert not ScanPolicy(fail_on="high").should_fail([finding])


def test_api_handler_exists() -> None:
    assert Handler.server_version.startswith("NigerianSecretsAPI/")
