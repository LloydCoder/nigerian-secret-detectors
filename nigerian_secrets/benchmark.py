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


def _score(cases: list[Case], detected_ids: set[str], tool: str) -> Metrics:
    tp = fp = tn = fn = 0
    for case in cases:
        detected = case.id in detected_ids
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


def _native_metrics(cases: list[Case]) -> Metrics:
    detected: set[str] = set()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for case in cases:
            (root / f"{case.id}.txt").write_text(case.text, encoding="utf-8")
        for finding in scan(root):
            detected.add(Path(finding.path).stem)
    return _score(cases, detected, "native")


def _external_metrics(tool: str, cases: list[Case]) -> Metrics:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for case in cases:
            (root / f"{case.id}.txt").write_text(case.text, encoding="utf-8")
        if tool == "gitleaks":
            binary = shutil.which(tool)
            if not binary:
                raise RuntimeError(f"{tool} is not installed")
            report = root / "gitleaks.json"
            command = [binary, "dir", str(root), "--no-banner", "--exit-code", "0", "--report-format", "json", "--report-path", str(report), "--redact"]
            subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
            detected = set()
            if report.exists():
                for finding in json.loads(report.read_text(encoding="utf-8") or "[]"):
                    file_name = Path(str(finding.get("File", ""))).name
                    if file_name.endswith(".txt"):
                        detected.add(Path(file_name).stem)
            return _score(cases, detected, tool)
        if tool == "trufflehog-docker":
            command = [
                "docker", "run", "--rm", "-v", f"{root}:/repo:ro", TRUFFLEHOG_IMAGE,
                "filesystem", "/repo", "--no-update", "--no-color", "--json",
            ]
            result = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
            detected = {case.id for case in cases if f"{case.id}.txt" in result.stdout}
            return _score(cases, detected, tool)
        raise ValueError(f"unsupported tool: {tool}")


def run(tool: str, cases: list[Case]) -> Metrics:
    if tool == "native":
        return _native_metrics(cases)
    return _external_metrics(tool, cases)


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
