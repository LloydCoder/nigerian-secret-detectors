from __future__ import annotations

from typing import Iterable

from .models import Finding

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"


def to_sarif(findings: Iterable[Finding]) -> dict:
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for finding in findings:
        rules.setdefault(
            finding.detector_id,
            {
                "id": finding.detector_id,
                "name": finding.detector_id,
                "shortDescription": {"text": finding.message},
                "properties": {"provider": finding.provider, "severity": finding.severity},
            },
        )
        results.append(
            {
                "ruleId": finding.detector_id,
                "level": "error" if finding.severity in {"critical", "high"} else "warning",
                "message": {"text": finding.message},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.path}, "region": {"startLine": finding.line, "startColumn": finding.column}}}],
                "properties": {"confidence": finding.confidence, "provider": finding.provider, "redactedMatch": finding.redacted_match},
            }
        )
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{"tool": {"driver": {"name": "nigerian-secret-detectors", "version": "0.5.0", "rules": list(rules.values())}}, "results": results}],
    }
