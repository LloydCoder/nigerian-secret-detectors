from pathlib import Path

from nigerian_secrets.cli import main


def test_cli_exclude_dir_avoids_intentional_fixture(tmp_path: Path, capsys):
    excluded = tmp_path / "fixtures"
    excluded.mkdir()
    (excluded / "sample.env").write_text('PAYSTACK_SECRET="sk_test_qW3eR7tY9uI2oP4aS6dF8gH0jK1lZ5xC"\n', encoding="utf-8")

    assert main([str(tmp_path), "--exclude-dir", "fixtures", "--format", "json", "--fail-on", "high"]) == 0
    assert capsys.readouterr().out.strip() == "[]"
