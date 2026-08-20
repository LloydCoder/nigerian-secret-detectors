# Nigerian Secret Detectors 🇳🇬

Provider-aware secret detection for Nigerian fintech, payment infrastructure, and crypto projects.

The project combines a **native detection engine** with external scanners such as Gitleaks, Semgrep, Nuclei, TruffleHog, and Slither. The native engine provides deterministic findings, provider context, confidence scoring, JSON/SARIF output, a validated detector registry, safe verification boundaries, and developer/CI integrations without requiring external binaries.

## Current phase — Phase 6: Precision/Recall Benchmark

### Completed foundations

- 30 Nigerian financial/fintech provider metadata entries
- Provider aliases and category metadata
- Context-aware credential rules
- Registry validation and deterministic detector lookup
- Synthetic positive and negative corpus regression tests
- **Phase 4:** opt-in verification adapter registry; live verification is disabled by default and unknown providers are rejected
- **Phase 5:** GitHub Actions security scan with SARIF upload, pre-commit integration, Docker image, explicit directory exclusions, and CI-safe failure policy

No live credentials are included. Benchmark values are synthetic fixtures.

## Quick start

```bash
python -m pip install -e .
nigerian-scan /path/to/project
```

Machine-readable output:

```bash
nigerian-scan /path/to/project --format json
nigerian-scan /path/to/project --format sarif
```

CI-friendly failure policy:

```bash
nigerian-scan . --fail-on high
nigerian-scan . --fail-on critical
```

Explicit exclusions are supported:

```bash
nigerian-scan . --exclude-dir tests --exclude-dir fixtures
```

Docker:

```bash
docker build -t nigerian-secret-detectors .
docker run --rm -v "$PWD:/workspace:ro" nigerian-secret-detectors /workspace
```

## Verification safety

Credential verification is deliberately **opt-in**. The core scanner never transmits discovered material. Verification requires an explicitly registered provider adapter and an explicit `enabled=True` call. No provider adapters are registered by default.

This separation prevents a scan from unexpectedly making outbound credential-validation requests and provides a clean boundary for future provider-specific implementations.

## Security design

The scanner never prints an entire detected secret. Findings expose only a redacted preview and location metadata. Provider-context rules require contextual evidence before producing a finding, reducing false positives without attempting live credential verification.

The GitHub security workflow uploads SARIF for code-scanning visibility and excludes only the repository's intentional synthetic test corpus from the self-scan gate.

## Roadmap

1. Native detection engine — **complete**
2. Detector registry and signed rule metadata — **complete foundation**
3. Comprehensive provider corpus and fixture benchmark — **complete**
4. Verification adapters with strict opt-in controls — **complete foundation**
5. GitHub Actions, pre-commit, Docker, and SARIF hardening — **complete**
6. Precision/recall benchmark against Gitleaks and TruffleHog — **next**
7. Release automation, provenance, SBOM, and supply-chain hardening
8. Enterprise policy packs and multi-tenant scanning API
