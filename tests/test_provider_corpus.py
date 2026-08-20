from pathlib import Path

from nigerian_secrets.providers import PROVIDERS
from nigerian_secrets.registry import REGISTRY
from nigerian_secrets.scanner import scan

FIXTURE_VALUE = "qW3eR7tY9uI2oP4aS6dF8gH0jK1lZ5xC"


def _write_case(path: Path, provider: str, value: str = FIXTURE_VALUE) -> None:
    path.write_text(
        f'# provider context: {provider}\nAPI_KEY = "{value}"\n',
        encoding="utf-8",
    )


def test_provider_corpus_has_at_least_thirty_entries():
    assert len(PROVIDERS) >= 30
    assert len({provider.id for provider in PROVIDERS}) == len(PROVIDERS)


def test_every_provider_has_detector_coverage():
    covered = set(REGISTRY.providers())
    assert {provider.id for provider in PROVIDERS} <= covered


def test_synthetic_positive_fixture_for_every_provider(tmp_path: Path):
    for provider in PROVIDERS:
        case = tmp_path / f"{provider.id}.env"
        _write_case(case, provider.aliases[0])
        findings = scan(case)
        assert any(item.provider == provider.id for item in findings), provider.id


def test_provider_names_alone_are_not_findings(tmp_path: Path):
    for provider in PROVIDERS:
        case = tmp_path / f"{provider.id}.txt"
        case.write_text(
            f"This project integrates with {provider.name}.\n",
            encoding="utf-8",
        )
        assert scan(case) == []


def test_corpus_is_deterministic(tmp_path: Path):
    for provider in PROVIDERS:
        _write_case(tmp_path / f"{provider.id}.env", provider.aliases[0])

    first = [item.to_dict() for item in scan(tmp_path)]
    second = [item.to_dict() for item in scan(tmp_path)]
    assert first == second
