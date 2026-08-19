from __future__ import annotations

from pathlib import Path
import math
import re
from typing import Iterable

from .models import Finding
from .rules import RULES, Rule

DEFAULT_EXCLUDED_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build", "coverage"}
DEFAULT_MAX_FILE_SIZE = 2 * 1024 * 1024


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _redact(value: str) -> str:
    if len(value) <= 10:
        return "*" * len(value)
    return f"{value[:4]}…{value[-4:]}"


def _iter_files(target: Path, excluded_dirs: set[str], max_file_size: int) -> Iterable[Path]:
    if target.is_file():
        if target.stat().st_size <= max_file_size:
            yield target
        return
    for path in target.rglob("*"):
        if not path.is_file() or path.stat().st_size > max_file_size:
            continue
        if any(part in excluded_dirs for part in path.parts):
            continue
        yield path


def _context_score(rule: Rule, window: str, match: str) -> float:
    if not rule.keywords:
        return 1.0
    normalized = window.lower()
    hits = sum(1 for keyword in rule.keywords if keyword.lower() in normalized)
    score = min(0.99, 0.55 + (0.12 * hits))
    if any(keyword.lower() in match.lower() for keyword in rule.keywords):
        score = min(0.99, score + 0.18)
    return score if hits else 0.0


def scan_file(path: Path, root: Path | None = None) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    findings: list[Finding] = []
    display_path = str(path.relative_to(root)) if root and path.is_relative_to(root) else str(path)
    for line_no, line in enumerate(text.splitlines(), 1):
        for rule in RULES:
            for match_obj in rule.pattern.finditer(line):
                match = match_obj.group(0)
                window = line[max(0, match_obj.start() - 180): min(len(line), match_obj.end() + 180)]
                confidence = _context_score(rule, window, match)
                if confidence == 0.0:
                    continue
                if rule.id.endswith("-context") and _entropy(match) < 2.8:
                    continue
                findings.append(
                    Finding(
                        detector_id=rule.id,
                        provider=rule.provider,
                        category=rule.category,
                        severity=rule.severity,
                        confidence=round(confidence, 2),
                        path=display_path,
                        line=line_no,
                        column=match_obj.start() + 1,
                        match=match,
                        redacted_match=_redact(match),
                        message=rule.message,
                    )
                )
    return findings


def scan(target: str | Path, *, excluded_dirs: set[str] | None = None, max_file_size: int = DEFAULT_MAX_FILE_SIZE) -> list[Finding]:
    path = Path(target).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(path)
    excluded = excluded_dirs or DEFAULT_EXCLUDED_DIRS
    root = path if path.is_dir() else path.parent
    findings: list[Finding] = []
    seen: set[tuple[str, int, int, str]] = set()
    for file_path in _iter_files(path, excluded, max_file_size):
        for finding in scan_file(file_path, root):
            key = (finding.path, finding.line, finding.column, finding.detector_id)
            if key not in seen:
                findings.append(finding)
                seen.add(key)
    return findings
