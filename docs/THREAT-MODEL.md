# Threat model

## Assets

Source code and detector rules; transiently processed secret material; verification credentials; findings and historical metadata; Git history; release artifacts, SBOMs, checksums, and provenance; API authentication material.

## Threat actors

Malicious contributors and pull requests, compromised dependencies/actions, attacker-controlled source files, malicious API clients, and insiders with repository or verification access.

## Attack surfaces and mitigations

| Surface | Threats | Mitigations |
| --- | --- | --- |
| Scanner input | traversal, symlinks, encoding abuse, oversized files | root confinement, symlink exclusion, file-size/count ceilings, bounded traversal |
| Detector regexes | pathological CPU | static precompiled patterns, bounded input, regression/performance testing |
| Findings | secret leakage | full-match redaction, optional HMAC fingerprints, no raw-match field |
| Git history | historical exposure, resource exhaustion | bounded commits/files, transient blob reads, HMAC correlation |
| API | auth bypass, traversal, oversized requests, plaintext transport | API key for remote binding, TLS requirement, body limits, path confinement |
| Verification | accidental credential transmission | disabled by default, explicit adapter registry, normalized states |
| CI | compromised action, excessive token permissions, fixture leakage | least-privilege permissions, immutable SHAs, generated runtime fixtures, checksum verification |
| Container | privilege escalation | non-root user, non-login shell, read-only/capability-drop CI smoke test |
| Release | artifact substitution | SBOM, checksums, build provenance |

Residual risks include host/kernel compromise, dependency zero-days, provider adapter implementation flaws, and deployment misconfiguration. The project does not claim to eliminate these classes of risk.
