from pathlib import Path

from nigerian_secrets.scanner import scan


PAYSTACK_SAMPLE = "sk_test_abcdefghijklmnopqrstuvwxyz123456"


def test_paystack_secret_is_detected_and_redacted(tmp_path: Path):
    sample = tmp_path / "config.py"
    sample.write_text(f'PAYSTACK_SECRET = "{PAYSTACK_SAMPLE}"\n')

    findings = scan(tmp_path)

    finding = next(item for item in findings if item.detector_id == "paystack-secret-key")
    assert finding.redacted_match != PAYSTACK_SAMPLE
    assert PAYSTACK_SAMPLE not in finding.to_dict().__repr__()


def test_flutterwave_secret_is_detected(tmp_path: Path):
    sample = tmp_path / "env.txt"
    sample.write_text('FLUTTERWAVE_KEY="FLWSECK-abcdefghijklmnopqrstuvwxyz1234567890"\n')

    findings = scan(tmp_path)

    assert any(item.detector_id == "flutterwave-secret-key" for item in findings)


def test_provider_context_reduces_false_positives(tmp_path: Path):
    sample = tmp_path / "text.txt"
    sample.write_text('value="not-a-secret-value-with-enough-length-to-look-real"\n')

    findings = scan(tmp_path)

    assert findings == []


def test_private_key_is_detected(tmp_path: Path):
    sample = tmp_path / "key.pem"
    sample.write_text("-----BEGIN PRIVATE KEY-----\nexample\n-----END PRIVATE KEY-----\n")

    findings = scan(tmp_path)

    assert any(item.detector_id == "generic-private-key" for item in findings)
