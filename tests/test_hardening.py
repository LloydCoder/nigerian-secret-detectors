import json
from pathlib import Path

import pytest

from nigerian_secrets.fingerprint import fingerprint
from nigerian_secrets.policy import MAX_ALLOWED_FILE_SIZE, MAX_ALLOWED_FILES, ScanPolicy
from nigerian_secrets.registry import REGISTRY
from nigerian_secrets.sarif import SARIF_SCHEMA, to_sarif
from nigerian_secrets.scanner import scan
from nigerian_secrets.verification import VerificationRequest, VerificationResult, verify


SYNTHETIC = "sk_test_abcdefghijklmnopqrstuvwxyz123456"


def test_redaction_never_keeps_secret_prefix_or_suffix(tmp_path: Path):
    (tmp_path / "secret.env").write_text(f'PAYSTACK_SECRET="{SYNTHETIC}"\n', encoding="utf-8")
    finding = next(item for item in scan(tmp_path) if item.detector_id == "paystack-secret-key")
    assert SYNTHETIC not in repr(finding.to_dict())
    assert "sk_test" not in finding.redacted_match
    assert "123456" not in finding.redacted_match


def test_binary_files_are_skipped(tmp_path: Path):
    (tmp_path / "binary.bin").write_bytes(b"prefix\x00sk_live_" + b"A" * 40)
    assert scan(tmp_path) == []


def test_findings_are_deterministically_sorted(tmp_path: Path):
    (tmp_path / "b.env").write_text(f'PAYSTACK_SECRET="{SYNTHETIC}"\n', encoding="utf-8")
    (tmp_path / "a.env").write_text(f'PAYSTACK_SECRET="{SYNTHETIC}"\n', encoding="utf-8")
    first = scan(tmp_path)
    second = scan(tmp_path)
    assert first == second
    assert [item.path for item in first] == sorted(item.path for item in first)


def test_policy_semantics_are_shared():
    policy = ScanPolicy.from_mapping({"max_files": 42, "max_file_size": 4096, "fail_on": "medium", "excluded_dirs": [".git"]})
    assert policy.fail_on == "medium"
    assert policy.max_files == 42
    assert policy.should_fail([type("F", (), {"severity": "high"})()])
    with pytest.raises(ValueError):
        ScanPolicy(max_file_size=MAX_ALLOWED_FILE_SIZE + 1)
    with pytest.raises(ValueError):
        ScanPolicy(max_files=MAX_ALLOWED_FILES + 1)


def test_detector_metadata_exposes_detection_type():
    metadata = {item.id: item for item in REGISTRY.metadata()}
    assert metadata["paystack-secret-key"].detection_type == "provider-specific"
    assert metadata["squad-credential-context"].detection_type == "provider-context"


def test_fingerprint_is_keyed_and_stable():
    assert fingerprint(SYNTHETIC, "test-key") == fingerprint(SYNTHETIC, "test-key")
    assert fingerprint(SYNTHETIC, "test-key") != fingerprint(SYNTHETIC, "other-key")


def test_verification_unknown_is_not_invalid():
    result = verify(VerificationRequest("unsupported-provider", SYNTHETIC), enabled=True)
    assert result.status == "unsupported"
    assert result.status != "invalid"


def test_verification_statuses_are_normalized():
    for status in ("valid", "invalid", "unknown", "unsupported", "rate_limited", "error"):
        assert VerificationResult("provider", status, "safe").status == status
    with pytest.raises(ValueError):
        VerificationResult("provider", "maybe", "safe")


def test_sarif_is_versioned_and_redacted(tmp_path: Path):
    (tmp_path / "secret.env").write_text(f'PAYSTACK_SECRET="{SYNTHETIC}"\n', encoding="utf-8")
    payload = to_sarif(scan(tmp_path))
    assert payload["version"] == "2.1.0"
    assert payload["$schema"] == SARIF_SCHEMA
    rendered = json.dumps(payload)
    assert SYNTHETIC not in rendered
