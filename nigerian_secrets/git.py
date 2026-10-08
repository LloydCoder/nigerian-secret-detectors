from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import subprocess

from .scanner import scan_text

DEFAULT_MAX_COMMITS = 200
DEFAULT_MAX_FILES_PER_COMMIT = 200


@dataclass(frozen=True)
class GitFinding:
    commit: str
    parent: str | None
    change: str
    path: str
    detector_id: str
    provider: str
    severity: str
    confidence: float
    line: int
    column: int
    redacted_match: str
    fingerprint: str

    def to_dict(self) -> dict:
        return asdict(self)


def _run(repo: Path, args: list[str], timeout: int = 20) -> str:
    try:
        result = subprocess.run(["git", *args], cwd=repo, stdin=subprocess.DEVNULL, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("git command failed or timed out") from exc
    if result.returncode != 0:
        raise RuntimeError("git command failed")
    return result.stdout


def _commits(repo: Path, max_commits: int) -> list[str]:
    if max_commits <= 0:
        raise ValueError("max_commits must be positive")
    return [line.strip() for line in _run(repo, ["rev-list", "--all", "--max-count", str(max_commits)]).splitlines() if line.strip()]


def _parent(repo: Path, commit: str) -> str | None:
    parts = _run(repo, ["rev-list", "--parents", "-n", "1", commit]).split()
    return parts[1] if len(parts) > 1 else None


def _changed_paths(repo: Path, commit: str, max_files: int) -> list[tuple[str, str, str | None]]:
    output = _run(repo, ["diff-tree", "--root", "--no-commit-id", "--name-status", "-r", "-M", commit])
    changes: list[tuple[str, str, str | None]] = []
    for line in output.splitlines():
        parts = line.split("\t")
        if not parts:
            continue
        status = parts[0]
        if status.startswith("R") and len(parts) >= 3:
            changes.append(("R", parts[2], parts[1]))
        elif status in {"A", "M", "C", "D"} and len(parts) >= 2:
            changes.append((status, parts[1], None))
        if len(changes) >= max_files:
            break
    return changes


def _blob_text(repo: Path, revision: str, path: str) -> str | None:
    try:
        raw = subprocess.run(["git", "show", f"{revision}:{path}"], cwd=repo, stdin=subprocess.DEVNULL, capture_output=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if raw.returncode != 0 or b"\x00" in raw.stdout:
        return None
    return raw.stdout.decode("utf-8", errors="ignore")


def scan_history(repository: str | Path, *, fingerprint_key: bytes | str, max_commits: int = DEFAULT_MAX_COMMITS, max_files_per_commit: int = DEFAULT_MAX_FILES_PER_COMMIT) -> list[GitFinding]:
    repo = Path(repository).expanduser().resolve()
    if not (repo / ".git").exists():
        raise ValueError("repository must contain a .git directory")
    if not fingerprint_key:
        raise ValueError("fingerprint_key is required for history correlation")
    findings: list[GitFinding] = []
    for commit in _commits(repo, max_commits):
        parent = _parent(repo, commit)
        for change, path, old_path in _changed_paths(repo, commit, max_files_per_commit):
            revision = parent if change == "D" and parent else commit
            source_path = old_path if change == "D" and old_path else path
            text = _blob_text(repo, revision, source_path)
            if text is None:
                continue
            for finding in scan_text(text, display_path=path, fingerprint_key=fingerprint_key):
                if finding.fingerprint is None:
                    continue
                findings.append(GitFinding(commit, parent, change, path, finding.detector_id, finding.provider, finding.severity, finding.confidence, finding.line, finding.column, finding.redacted_match, finding.fingerprint))
    return sorted(findings, key=lambda item: (item.fingerprint, item.commit, item.path, item.line, item.column, item.detector_id))
