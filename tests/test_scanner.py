from pathlib import Path

from nigerian_secrets.scanner import scan


def test_paystack_secret_is_detected(tmp_path: Path):
    sample = tmp_path / "config.py"
    sample.write_text('PAYSTACK_SECRET = "sk_test_abcdefghijklmnopqrstuvwxyz123456"\n')

    findings = scan(tmp_path)

    assert any(item.detector_id == "paystack-secret-key" for item in findings)
    assert all("sk_test_" not in item.redacted_match[4:] for item in findings)


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
