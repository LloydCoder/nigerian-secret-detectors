from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, asdict
from pathlib import Path
from time import perf_counter

from .providers import PROVIDERS, PROVIDER_BY_ID
from .scanner import scan

CORPUS = Path(__file__).resolve().parent.parent / "benchmarks" / "corpus.jsonl"
TRUFFLEHOG_IMAGE = "ghcr.io/trufflesecurity/trufflehog:3.96.0@sha256:b8acd9f7306d832b1f16e06003dac2283a737817954554111683ab7a56e9e539"
LANGUAGES = ("python", "javascript", "typescript", "go", "php", "java", "ruby", "rust", "csharp", "json", "yaml", "toml", "xml", "env", "docker", "shell", "gha", "terraform", "kubernetes", "text")
NEGATIVE_FIXTURES = ("uuid", "sha256", "timestamp", "public-key", "checksum", "random-high-entropy", "documentation", "jwt-like", "base64", "database-id")


@dataclass(frozen=True)
class Case:
    id: str
    expected: bool
    provider: str
    suite: str
    fixture: str
    language: str
    adversarial: bool = False

    @property
    def text(self) -> str:
        seed = hashlib.sha256(self.id.encode()).hexdigest()
        value = "".join(chr(97 + int(seed[i : i + 2], 16) % 26) for i in range(0, 48, 2))
        provider = PROVIDER_BY_ID.get(self.provider)
        alias = provider.aliases[0] if provider else "paystack"
        if self.fixture == "provider":
            if self.provider == "paystack":
                assignment = f'API_SECRET = "sk_live_{value}"'
            elif self.provider == "flutterwave":
                assignment = f'API_SECRET = "FLWSECK-{value}"'
            elif self.provider == "monnify":
                assignment = f'API_SECRET = "MK_LIVE_{value}"'
            elif self.provider == "korapay":
                assignment = f'API_SECRET = "sk_live_{value}"'
            elif self.provider == "interswitch":
                assignment = f'macKey = "{seed[:64]}"'
            else:
                assignment = f'API_KEY = "{value + value}"'
            return f"# {alias} integration\n{assignment}"
        if self.fixture == "private-key":
            return "-----BEGIN RSA PRIVATE KEY-----\nSYNTHETIC-BENCHMARK\n-----END RSA PRIVATE KEY-----"
        if self.fixture == "jwt":
            return f"{alias} access_token = 'eyJ{value[:24]}.{value[4:20]}.{value[8:28]}'"
        if self.fixture == "paystack":
            return f"paystack API_SECRET = 'sk_test_{value}'"
        negatives = {
            "uuid": "uuid = '550e8400-e29b-41d4-a716-446655440000'",
            "sha256": "sha256 = '" + "a" * 64 + "'",
            "timestamp": "timestamp = '2026-09-10T09:00:00Z'",
            "public-key": "public_key = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ'",
            "checksum": "checksum = '" + "deadbeef" * 8 + "'",
            "random-high-entropy": f"random = '{value * 2}'",
            "documentation": "documentation = 'sk_live_example'",
            "jwt-like": f"jwt_shape = 'eyJ{value[:24]}.{value[4:20]}'",
            "base64": f"base64 = '{value * 2}'",
            "database-id": "database_id = '12345678901234567890123456789012'",
        }
        return negatives[self.fixture]


@dataclass(frozen=True)
class Metrics:
    tool: str
    cases: int
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int
    precision: float
    recall: float
    f1: float
    elapsed_seconds: float = 0.0
    files_per_second: float = 0.0
    mb_per_second: float = 0.0


def _expand_seed_cases(seeds: list[Case]) -> list[Case]:
    cases: list[Case] = []
    for provider_index, provider in enumerate(PROVIDERS):
        for variant in range(10):
            cases.append(Case(f"pos-{provider.id}-{variant:02d}", True, provider.id, "regression", "provider", LANGUAGES[(provider_index * 3 + variant) % len(LANGUAGES)]))
    for variant in range(60):
        cases.append(Case(f"pos-generic-{variant:03d}", True, "generic", "regression", "private-key" if variant < 20 else "jwt" if variant < 40 else "paystack", "text"))
    for variant in range(300):
        cases.append(Case(f"neg-{variant:03d}", False, "none", "regression", NEGATIVE_FIXTURES[variant % len(NEGATIVE_FIXTURES)], "text"))
    if not seeds:
        raise ValueError("benchmark seed catalog is empty")
    return cases


def load_cases(path: Path = CORPUS) -> list[Case]:
    seeds = [Case(**json.loads(line)) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    cases = _expand_seed_cases(seeds)
    if len(cases) < 500:
        raise ValueError(f"benchmark corpus must contain at least 500 cases; found {len(cases)}")
    if len({case.id for case in cases}) != len(cases):
        raise ValueError("benchmark case IDs must be unique")
    return cases


def _native_scan(cases: list[Case]) -> tuple[set[str], float, int]:
    detected: set[str] = set()
    total_bytes = 0
    started = perf_counter()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for case in cases:
            payload = case.text
            total_bytes += len(payload.encode("utf-8"))
            (root / f"{case.id}.txt").write_text(payload, encoding="utf-8")
        for finding in scan(root):
            detected.add(Path(finding.path).stem)
    return detected, perf_counter() - started, total_bytes


def native_detected_ids(cases: list[Case]) -> set[str]:
    """Compatibility helper returning only detected case IDs."""
    return _native_scan(cases)[0]


def _score(cases: list[Case], detected_ids: set[str], tool: str, elapsed: float = 0.0, total_bytes: int = 0) -> Metrics:
    tp = fp = tn = fn = 0
    for case in cases:
        detected = case.id in detected_ids
        if case.expected and detected: tp += 1
        elif case.expected and not detected: fn += 1
        elif not case.expected and detected: fp += 1
        else: tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return Metrics(tool, len(cases), tp, fp, tn, fn, round(precision, 4), round(recall, 4), round(f1, 4), round(elapsed, 4), round(len(cases) / elapsed, 2) if elapsed else 0.0, round((total_bytes / (1024 * 1024)) / elapsed, 2) if elapsed else 0.0)


def _native_metrics(cases: list[Case]) -> Metrics:
    detected, elapsed, total_bytes = _native_scan(cases)
    return _score(cases, detected, "native", elapsed, total_bytes)


def _external_metrics(tool: str, cases: list[Case]) -> Metrics:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for case in cases:
            (root / f"{case.id}.txt").write_text(case.text, encoding="utf-8")
        total_bytes = sum(len(c.text.encode("utf-8")) for c in cases)
        if tool == "gitleaks":
            binary = shutil.which(tool)
            if not binary: raise RuntimeError(f"{tool} is not installed")
            report = root / "gitleaks.json"
            command = [binary, "dir", str(root), "--no-banner", "--exit-code", "0", "--report-format", "json", "--report-path", str(report), "--redact"]
            started = perf_counter(); subprocess.run(command, capture_output=True, text=True, timeout=120, check=False); elapsed = perf_counter() - started
            detected = set()
            if report.exists():
                for finding in json.loads(report.read_text(encoding="utf-8") or "[]"):
                    file_name = Path(str(finding.get("File", ""))).name
                    if file_name.endswith(".txt"): detected.add(Path(file_name).stem)
            return _score(cases, detected, tool, elapsed, total_bytes)
        if tool == "trufflehog-docker":
            command = ["docker", "run", "--rm", "-v", f"{root}:/repo:ro", TRUFFLEHOG_IMAGE, "filesystem", "/repo", "--no-update", "--no-color", "--json"]
            started = perf_counter(); result = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False); elapsed = perf_counter() - started
            detected = {case.id for case in cases if f"{case.id}.txt" in result.stdout}
            return _score(cases, detected, tool, elapsed, total_bytes)
        raise ValueError(f"unsupported tool: {tool}")


def run(tool: str, cases: list[Case]) -> Metrics:
    return _native_metrics(cases) if tool == "native" else _external_metrics(tool, cases)


def main() -> int:
    parser = argparse.ArgumentParser(description="Deterministic secret-detection benchmark")
    parser.add_argument("--tool", choices=("native", "gitleaks", "trufflehog-docker"), default="native")
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    metrics = run(args.tool, load_cases(args.corpus))
    print(json.dumps(asdict(metrics), indent=2) if args.json else f"{metrics.tool}: precision={metrics.precision:.4f} recall={metrics.recall:.4f} f1={metrics.f1:.4f} cases={metrics.cases} files/s={metrics.files_per_second:.2f} MB/s={metrics.mb_per_second:.2f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
