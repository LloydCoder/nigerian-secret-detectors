from pathlib import Path

import pytest

from nigerian_secrets.api import _policy_from_payload, _safe_target
from nigerian_secrets.policy import ScanPolicy
from nigerian_secrets.scanner import scan


def test_policy_payload_is_inline_only():
    policy = _policy_from_payload({"max_files": 42, "max_file_size": 4096, "fail_on": "critical"})
    assert policy == ScanPolicy(max_files=42, max_file_size=4096, fail_on="critical")
    with pytest.raises(ValueError):
        _policy_from_payload("/etc/passwd")


def test_path_traversal_is_rejected(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("nigerian_secrets.api.SCAN_ROOT", tmp_path.resolve())
    with pytest.raises(ValueError):
        _safe_target("../outside")
    with pytest.raises(ValueError):
        _safe_target(str(tmp_path / "file.txt"))


def test_scanner_file_limit_is_enforced(tmp_path: Path):
    for index in range(5):
        (tmp_path / f"{index}.txt").write_text("ordinary documentation", encoding="utf-8")
    assert scan(tmp_path, max_files=2) == []
