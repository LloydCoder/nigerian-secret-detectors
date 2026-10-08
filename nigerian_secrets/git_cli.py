from __future__ import annotations

import argparse
import json
import os
import sys

from .git import scan_history


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan reachable Git history for Nigerian fintech and crypto secrets.")
    parser.add_argument("repository")
    parser.add_argument("--max-commits", type=int, default=200)
    parser.add_argument("--max-files-per-commit", type=int, default=200)
    parser.add_argument("--fingerprint-key-env", default="NIGERIAN_FINGERPRINT_KEY")
    args = parser.parse_args(argv)
    key = os.environ.get(args.fingerprint_key_env)
    if not key:
        print("error: fingerprint key environment variable is not set", file=sys.stderr)
        return 2
    try:
        findings = scan_history(args.repository, fingerprint_key=key, max_commits=args.max_commits, max_files_per_commit=args.max_files_per_commit)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"error: git history scan failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps([finding.to_dict() for finding in findings], indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
