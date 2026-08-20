# Nigerian Secret Detectors 🇳🇬

Provider-aware secret detection for Nigerian fintech, payment infrastructure, and crypto projects.

The project combines a **native detection engine** with external scanners such as Gitleaks, Semgrep, Nuclei, TruffleHog, and Slither. The native engine provides deterministic findings, provider context, confidence scoring, JSON/SARIF output, and a validated detector registry without requiring external binaries.

## Current phase — Phase 3: Provider Corpus & Benchmark

- 30 Nigerian financial/fintech provider metadata entries
- Provider aliases and category metadata
- Context-aware credential rules for providers without an established provider-specific token grammar
- Dedicated provider-specific rules retained for known formats
- Registry validation requires detector coverage for every corpus provider
- Synthetic positive fixture coverage across the full provider corpus
- Negative fixtures proving provider names alone do not create findings
- Deterministic corpus regression checks
- Native engine version `0.3.0`

The corpus intentionally distinguishes **provider context** from **provider-specific credential formats**. A provider name is not treated as a secret, and generic context rules are only activated around credential-shaped assignments. Provider-specific grammars should be added only when their format is independently established.

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

The legacy command remains supported:

```bash
python runner.py /path/to/project
```

## Security design

The scanner never prints an entire detected secret. Findings expose only a redacted preview and location metadata. Provider-context rules require contextual evidence before producing a finding, reducing false positives without attempting live credential verification.

## Roadmap

1. Native detection engine — **complete**
2. Detector registry and signed rule metadata — **complete foundation**
3. Comprehensive provider corpus and fixture benchmark — **in progress**
4. Verification adapters with strict opt-in controls
5. GitHub Actions, pre-commit, Docker, and SARIF hardening
6. Precision/recall benchmark against Gitleaks and TruffleHog
7. Release automation, provenance, SBOM, and supply-chain hardening
8. Enterprise policy packs and multi-tenant scanning API
