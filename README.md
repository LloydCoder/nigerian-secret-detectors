# Nigerian Secret Detectors 🇳🇬

Provider-aware secret detection for Nigerian fintech, payment infrastructure, and crypto projects.

The project combines a **native detection engine** with external scanners such as Gitleaks, Semgrep, Nuclei, TruffleHog, and Slither. The native engine provides deterministic findings, provider context, confidence scoring, JSON/SARIF output, and a validated detector registry without requiring external binaries.

## Current phase — Phase 2: Detector Registry

- Native provider-aware rules for Paystack, Flutterwave, Monnify, KoraPay, SeerBit, Interswitch, Remita, OPay, and PalmPay
- Generic cryptographic private-key detection
- Nigerian-fintech JWT context detection
- Normalized findings with severity and confidence
- Secret redaction in terminal/JSON/SARIF output
- Recursive filesystem scanning with common dependency/build exclusions
- Deterministic `DetectorRegistry` with duplicate-ID and metadata validation
- Provider and detector metadata APIs
- Modern Python packaging with explicit package discovery
- Regression tests for detection and registry integrity

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
2. Detector registry and signed rule metadata — **in progress**
3. Comprehensive provider corpus and fixture benchmark
4. Verification adapters with strict opt-in controls
5. GitHub Actions, pre-commit, Docker, and SARIF hardening
6. Precision/recall benchmark against Gitleaks and TruffleHog
7. Release automation, provenance, SBOM, and supply-chain hardening
8. Enterprise policy packs and multi-tenant scanning API
