from __future__ import annotations

import argparse
import json
import sys

from .policy import ScanPolicy, load_policy
from .sarif import to_sarif
from .scanner import scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nigerian-scan",
        description="Scan source trees for Nigerian fintech and crypto secrets.",
    )
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    parser.add_argument("--fail-on", choices=("none", "low", "medium", "high", "critical"), default=None)
    parser.add_argument("--policy", help="Path to a JSON ScanPolicy")
    parser.add_argument(
        "--exclude-dir",
        action="append",
        default=[],
        metavar="NAME",
        help="Directory name to exclude; may be repeated.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        policy = load_policy(args.policy)
        if args.fail_on is not None or args.exclude_dir:
            policy = ScanPolicy(
                fail_on=args.fail_on or policy.fail_on,
                max_file_size=policy.max_file_size,
                max_files=policy.max_files,
                excluded_dirs=policy.excluded_dirs | frozenset(args.exclude_dir),
            )
        findings = scan(
            args.target,
            excluded_dirs=set(policy.excluded_dirs),
            max_file_size=policy.max_file_size,
            max_files=policy.max_files,
        )
    except FileNotFoundError as exc:
        print(f"error: target does not exist: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: invalid scan configuration: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps([item.to_dict() for item in findings], indent=2))
    elif args.format == "sarif":
        print(json.dumps(to_sarif(findings), indent=2))
    else:
        if not findings:
            print("No Nigerian fintech or crypto secrets detected.")
        for item in findings:
            print(f"{item.severity.upper():8} {item.provider:16} {item.path}:{item.line}:{item.column} {item.detector_id} [{item.confidence:.2f}] {item.redacted_match}")
        print(f"\nFindings: {len(findings)}")
    return 1 if policy.should_fail(findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
