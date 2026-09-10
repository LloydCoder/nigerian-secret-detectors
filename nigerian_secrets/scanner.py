from __future__ import annotations

from pathlib import Path
import math
from typing import Iterable

from .fingerprint import fingerprint
from .models import Finding
from .rules import Rule
from .registry import REGISTRY

DEFAULT_EXCLUDED_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build", "coverage"}
DEFAULT_MAX_FILE_SIZE = 2 * 1024 * 1024
DEFAULT_MAX_FILES = 10_000


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _redact(value: str) -> str:
    return f"<redacted:{len(value)}>"


def _iter_files(target: Path, excluded_dirs: set[str], max_file_size: int, max_files: int) -> Iterable[Path]:
    if target.is_file():
        try:
            if not target.is_symlink() and target.stat().st_size <= max_file_size:
                yield target
        except OSError:
            return
        return
    count = 0
    try:
        candidates = sorted(target.rglob("*"), key=lambda item: item.as_posix())
    except OSError:
        return
    for path in candidates:
        if count >= max_files:
            return
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > max_file_size:
                continue
            if any(part in excluded_dirs for part in path.parts):
                continue
        except OSError:
            continue
        count += 1
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


def scan_text(text: str, *, display_path: str = "<memory>", fingerprint_key: bytes | str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    for line_index, line in enumerate(lines):
        line_no = line_index + 1
        context_start = max(0, line_index - 1)
        context_end = min(len(lines), line_index + 2)
        context_lines = lines[context_start:context_end]
        context = "\n".join(context_lines)
        for rule in REGISTRY.rules:
            for match_obj in rule.pattern.finditer(line):
                match = match_obj.group(0)
                confidence = _context_score(rule, context, match)
                if confidence == 0.0:
                    continue
                if rule.detection_type == "provider-context" and _entropy(match) < 2.0:
                    continue
                secret_value = match_obj.group(1) if match_obj.lastindex else match
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
                        redacted_match=_redact(match),
                        message=rule.message,
                        fingerprint=fingerprint(secret_value, fingerprint_key) if fingerprint_key else None,
                    )
                )
    return findings


def scan_file(path: Path, root: Path | None = None, *, fingerprint_key: bytes | str | None = None) -> list[Finding]:
    try:
        raw = path.read_bytes()
        if b"\x00" in raw:
            return []
        text = raw.decode("utf-8", errors="ignore")
    except OSError:
        return []
    display_path = str(path.relative_to(root)) if root and path.is_relative_to(root) else str(path)
    return scan_text(text, display_path=display_path, fingerprint_key=fingerprint_key)


def scan(target: str | Path, *, excluded_dirs: set[str] | None = None, max_file_size: int = DEFAULT_MAX_FILE_SIZE, max_files: int = DEFAULT_MAX_FILES, fingerprint_key: bytes | str | None = None) -> list[Finding]:
    if max_file_size <= 0 or max_files <= 0:
        raise ValueError("max_file_size and max_files must be positive")
    path = Path(target).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(path)
    excluded = set(excluded_dirs) if excluded_dirs is not None else set(DEFAULT_EXCLUDED_DIRS)
    root = path if path.is_dir() else path.parent
    findings: list[Finding] = []
    seen: set[tuple[str, int, int, str]] = set()
    for file_path in _iter_files(path, excluded, max_file_size, max_files):
        for finding in scan_file(file_path, root, fingerprint_key=fingerprint_key):
            key = (finding.path, finding.line, finding.column, finding.detector_id)
            if key not in seen:
                findings.append(finding)
                seen.add(key)
    return sorted(findings, key=lambda item: (item.path, item.line, item.column, item.detector_id))
