import subprocess
from pathlib import Path

from nigerian_secrets.git import scan_history

SYNTHETIC = "sk_test_abcdefghijklmnopqrstuvwxyz123456"


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)


def test_git_history_detects_and_correlates_secret_without_raw_value(tmp_path: Path):
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "test@example.invalid")
    _git(tmp_path, "config", "user.name", "test")
    secret_file = tmp_path / "config.env"
    secret_file.write_text(f'PAYSTACK_SECRET="{SYNTHETIC}"\n', encoding="utf-8")
    _git(tmp_path, "add", "config.env")
    _git(tmp_path, "commit", "-m", "add synthetic credential")
    secret_file.unlink()
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-m", "remove synthetic credential")
    findings = scan_history(tmp_path, fingerprint_key="history-key-0123456789abcdef", max_commits=10)
    assert findings
    assert any(item.path == "config.env" and item.change in {"A", "D"} for item in findings)
    assert all(item.fingerprint for item in findings)
    assert all(SYNTHETIC not in str(item.to_dict()) for item in findings)
