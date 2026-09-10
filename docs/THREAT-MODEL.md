# Threat model

## Assets

- source code and detector rules
- discovered secret material while transiently scanning
- verification credentials supplied by operators
- scan findings and historical metadata
- Git history
- release artifacts, SBOMs, checksums, and provenance
- API authentication material

## Threat actors

- malicious repository contributor
- malicious pull request
- compromised dependency or GitHub Action
- attacker-controlled source file
- malicious API client
- insider with repository or verification access

## Attack surfaces and mitigations

| Surface | Principal threats | Current mitigations |
| --- | --- | --- |
| Scanner input | traversal, symlink escape, binary/encoding abuse, oversized files | root-relative API targets, symlink exclusion, size/count limits, bounded traversal, safe decode |
| Detector regexes | catastrophic backtracking, excessive CPU | static precompiled regexes and bounded input sizes; regression/performance benchmarks |
| Findings | secret leakage through reports | full-match redaction, optional HMAC fingerprints, no raw-match field |
| Git history | historical secret exposure, resource exhaustion | bounded commits/files, transient blob reads, HMAC correlation |
| API | auth bypass, traversal, oversized requests, plaintext transport | API key for remote binding, TLS requirement, request limits, path confinement, constant-time key comparison |
| Verification | accidental credential transmission | disabled by default, explicit adapter registry, normalized result states |
| CI | compromised action, excessive token permissions, fixture leakage | explicit workflow permissions, immutable action SHAs, generated runtime fixtures, checksum verification |
| Dependencies | vulnerable package | minimal runtime dependency surface and dependency auditing in CI |
| Container | privilege escalation, writable filesystem | non-root UID, non-login shell, CI smoke test with `--read-only --cap-drop=ALL` |
| Release | artifact substitution | checksums, SBOM, build provenance, tag-triggered release workflow |

## Residual risks

The project does not claim to eliminate all regex, parser, dependency, kernel, Git, or host-level risks. Remote deployments should use a private network or trusted reverse proxy, and provider verification adapters must be reviewed individually before enabling them.
