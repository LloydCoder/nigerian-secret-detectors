from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, asdict
from pathlib import Path

from .scanner import scan

CORPUS = Path(__file__).resolve().parent.parent / "benchmarks" / "corpus.jsonl"
TRUFFLEHOG_IMAGE = "ghcr.io/trufflesecurity/trufflehog:3.96.0@sha256:b8acd9f7306d832b1f16e06003dac2283a737817954554111683ab7a56e9e539"


@dataclass(frozen=True)
class Case:
    id: str
    text: str
    expected: bool


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


def load_cases(path: Path = CORPUS) -> list[Case]:
    return [Case(**json.loads(line)) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _native_detect(case: Case) -> bool:
    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory) / "fixture.txt"
        target.write_text(case.text, encoding="utf-8")
        return bool(scan(target))


def _external_detect(tool: str, case: Case) -> bool:
    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory) / "fixture.txt"
        target.write_text(case.text, encoding="utf-8")
        if tool == "gitleaks":
            binary = shutil.which(tool)
            if not binary:
                raise RuntimeError(f"{tool} is not installed")
            command = [binary, "dir", directory, "--no-banner", "--exit-code", "1", "--redact"]
        elif tool == "trufflehog-docker":
            command = [
                "docker", "run", "--rm", "-v", f"{directory}:/repo:ro", TRUFFLEHOG_IMAGE,
                "filesystem", "/repo", "--no-update", "--no-color", "--json",
            ]
        else:
            raise ValueError(f"unsupported tool: {tool}")
        result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
        if tool == "gitleaks":
            return result.returncode == 1
        return any('"DetectorName"' in line or '"DetectorType"' in line for line in result.stdout.splitlines())


def run(tool: str, cases: list[Case]) -> Metrics:
    detector = _native_detect if tool == "native" else lambda case: _external_detect(tool, case)
    tp = fp = tn = fn = 0
    for case in cases:
        detected = detector(case)
        if case.expected and detected:
            tp += 1
        elif case.expected and not detected:
            fn += 1
        elif not case.expected and detected:
            fp += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return Metrics(tool, len(cases), tp, fp, tn, fn, round(precision, 4), round(recall, 4), round(f1, 4))


def main() -> int:
    parser = argparse.ArgumentParser(description="Deterministic secret-detection benchmark")
    parser.add_argument("--tool", choices=("native", "gitleaks", "trufflehog-docker"), default="native")
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    metrics = run(args.tool, load_cases(args.corpus))
    if args.json:
        print(json.dumps(asdict(metrics), indent=2))
    else:
        print(f"{metrics.tool}: precision={metrics.precision:.4f} recall={metrics.recall:.4f} f1={metrics.f1:.4f} cases={metrics.cases}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
