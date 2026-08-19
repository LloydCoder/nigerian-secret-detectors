# Nigerian Secret Detectors 🇳🇬

Provider-aware secret detection for Nigerian fintech, payment infrastructure, and crypto projects.

This project combines a **native detection engine** with existing scanners such as Gitleaks, Semgrep, Nuclei, TruffleHog, and Slither. The native engine is designed to provide deterministic findings, provider context, confidence scoring, JSON output, and SARIF output without requiring external binaries.

## Phase 1 — Native Detection Engine

- Provider-aware rules for Paystack, Flutterwave, Monnify, KoraPay, SeerBit, Interswitch, Remita, OPay, and PalmPay
- Generic cryptographic private-key detection
- Nigerian-fintech JWT context detection
- Normalized findings with severity and confidence
- Secret redaction in terminal/JSON/SARIF output
- Recursive filesystem scanning with common dependency/build exclusions
- Python packaging via `pyproject.toml`
- Regression tests for positive and negative cases

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

The scanner never prints an entire detected secret. Findings expose a redacted preview and location metadata. Provider-context rules require contextual evidence before producing a finding, which is intended to reduce false positives.

## Roadmap

1. Native detection engine — **in progress / Phase 1**
2. Detector registry and signed rule metadata
3. Comprehensive provider corpus and fixture benchmark
4. Verification adapters with strict opt-in controls
5. GitHub Actions, pre-commit, Docker, and SARIF hardening
6. Precision/recall benchmark against Gitleaks and TruffleHog
7. Release automation, provenance, SBOM, and supply-chain hardening
8. Enterprise policy packs and multi-tenant scanning API
