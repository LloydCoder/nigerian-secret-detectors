from __future__ import annotations

import argparse
import json
import sys

from .scanner import DEFAULT_EXCLUDED_DIRS, scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nigerian-scan",
        description="Scan source trees for Nigerian fintech and crypto secrets.",
    )
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    parser.add_argument("--fail-on", choices=("none", "high", "critical"), default="high")
    parser.add_argument(
        "--exclude-dir",
        action="append",
        default=[],
        metavar="NAME",
        help="Directory name to exclude; may be repeated.",
    )
    return parser


def _exit_code(findings, fail_on: str) -> int:
    if fail_on == "none":
        return 0
    levels = {"high": {"high", "critical"}, "critical": {"critical"}}
    return 1 if any(item.severity in levels[fail_on] for item in findings) else 0


def _sarif(findings):
    rules = {}
    results = []
    for finding in findings:
        rules.setdefault(finding.detector_id, {
            "id": finding.detector_id,
            "name": finding.detector_id,
            "shortDescription": {"text": finding.message},
            "properties": {"provider": finding.provider, "severity": finding.severity},
        })
        results.append({
            "ruleId": finding.detector_id,
            "level": "error" if finding.severity in {"critical", "high"} else "warning",
            "message": {"text": f"{finding.message} Match: {finding.redacted_match}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.path}, "region": {"startLine": finding.line, "startColumn": finding.column}}}],
            "properties": {"confidence": finding.confidence, "provider": finding.provider},
        })
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "nigerian-secret-detectors", "rules": list(rules.values())}}, "results": results}]}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        excluded = DEFAULT_EXCLUDED_DIRS | set(args.exclude_dir)
        findings = scan(args.target, excluded_dirs=excluded)
    except FileNotFoundError as exc:
        print(f"error: target does not exist: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps([item.to_dict() for item in findings], indent=2))
    elif args.format == "sarif":
        print(json.dumps(_sarif(findings), indent=2))
    else:
        if not findings:
            print("No Nigerian fintech or crypto secrets detected.")
        for item in findings:
            print(f"{item.severity.upper():8} {item.provider:16} {item.path}:{item.line}:{item.column} {item.detector_id} [{item.confidence:.2f}] {item.redacted_match}")
        print(f"\nFindings: {len(findings)}")
    return _exit_code(findings, args.fail_on)


if __name__ == "__main__":
    raise SystemExit(main())
