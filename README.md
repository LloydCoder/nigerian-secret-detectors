# Nigerian Secret Detectors 🇳🇬

Provider-aware secret detection for Nigerian fintech, payment infrastructure, banking, open-banking, and crypto projects.

The project combines a native detection engine with established scanner integrations and provides deterministic findings, provider context, explicit detector classifications, confidence scoring, JSON/SARIF output, a validated detector registry, safe verification boundaries, Git-history scanning, HMAC-based secret correlation, developer/CI integrations, release security, policy controls, and a hardened local scanning API.

## Current build status

- Native detection engine: **production-quality component**
- Detector registry and provider metadata: **implemented**
- Provider corpus: **30 providers**
- Provider-specific detector classes: **5 providers currently have explicit provider-specific rules**
- Provider-context detector classes: **25 providers currently rely on contextual detection**
- Benchmark corpus: **660 deterministic generated cases (360 positives, 300 negatives)**
- Git-history scanning: **implemented with bounded history/file limits and HMAC correlation**
- Live verification: **opt-in architecture; no provider adapters are enabled by default**
- Local API: **implemented; remote binding requires API key plus TLS certificate/key**
- SARIF: **2.1.0 output with schema reference and regression tests**
- Supply-chain controls: **SBOM, checksums, provenance, checksum-pinned external scanner binary, immutable GitHub Action pins**
- Container: **non-root, no-login user, read-only/capability-drop smoke-tested in CI**

The benchmark is a controlled synthetic regression/coverage corpus. It is not a real-world recall estimate and contains no live credentials. Synthetic credential material is generated only at benchmark runtime so repository secret-scanning systems do not receive credential-shaped fixtures.

## Quick start

```bash
python -m pip install .
nigerian-scan /path/to/project
```

Machine-readable output:

```bash
nigerian-scan . --format json
nigerian-scan . --format sarif
```

Policy:

```bash
nigerian-scan . --policy scan-policy.json --fail-on high
```

The policy system supports `none`, `low`, `medium`, `high`, and `critical` gates plus file-size, file-count, and excluded-directory controls. CLI and API policy semantics use the same `ScanPolicy` implementation.

## Git history scanning

Historical scanning is deliberately bounded and does not persist raw secret material. It scans changed blobs across reachable history, including deleted-file content when the deleted blob is available from the parent commit.

```bash
export NIGERIAN_FINGERPRINT_KEY='store-this-outside-the-repository'
nigerian-git-scan /path/to/repository --max-commits 200
```

Results contain detector/provider metadata, commit/path/line information, redacted matches, and an HMAC-SHA-256 fingerprint. The fingerprint key is required and raw secret values are not included in reports.

## Local API

The API is intentionally local-only by default and binds to `127.0.0.1:8787`.

```bash
nigerian-secrets-api
```

Endpoints:

- `GET /healthz` — health check
- `GET /v1/providers` — provider catalog
- `GET /v1/detectors` — detector catalog
- `POST /v1/scan` — scan a path relative to `NIGERIAN_SCAN_ROOT`

Remote binding requires all of:

- `NIGERIAN_API_KEY`
- `NIGERIAN_TLS_CERTFILE`
- `NIGERIAN_TLS_KEYFILE`

TLS is terminated by the application for direct remote binding; a private network or trusted reverse proxy is also appropriate. Plaintext remote API exposure is not supported.

## Verification

Detection and verification are separate security boundaries. Verification is disabled by default. A provider must have an explicitly registered adapter before a credential can be transmitted. Verification results use the states `valid`, `invalid`, `unknown`, `unsupported`, `rate_limited`, and `error`; `unknown` is never converted to `invalid`.

No provider verification adapter is enabled in the current distribution. This is intentional: arbitrary detected secrets must not be transmitted to third-party APIs merely to increase a benchmark score.

## Integrations

The repository interoperates with:

- Gitleaks
- TruffleHog
- Semgrep
- Nuclei
- Slither

These integrations complement rather than replace the native engine. The native engine is independently usable and owns the Nigerian/African financial-infrastructure specialization.

## SARIF

SARIF output targets version 2.1.0 and includes stable rule IDs, provider/severity metadata, locations, confidence, and redacted match metadata. The generated output includes the OASIS SARIF schema URI and is validated by CI structure tests.

## Release and supply-chain security

Tagged releases build Python distributions, generate an SPDX 2.3 SBOM with SHA-256 file hashes, publish artifact checksums, and generate GitHub build-provenance attestations. GitHub Actions are pinned to immutable commit SHAs. The Gitleaks benchmark binary is verified against its published checksum and the TruffleHog benchmark image is pinned by digest.

See `SECURITY.md` and `docs/RELEASE.md` for the security and release model.

## Benchmark methodology

The checked-in `benchmarks/corpus.jsonl` is a small, reviewable seed catalog. The benchmark expands that seed deterministically into **660 cases**: 360 positive cases and 300 difficult negative cases across 30 providers, generic cryptographic/JWT classes, and multiple source-language labels. Credential-shaped values are generated only in the temporary benchmark workspace.

Metrics report precision, recall, F1, elapsed time, files/second, and MB/second. The benchmark is intended for regression, coverage, and performance tracking; it is not a production prevalence or real-world recall study.

See `docs/BENCHMARK.md`.

## Docker

Build:

```bash
docker build -t nigerian-secret-detectors .
```

Recommended hardened invocation for a read-only scan:

```bash
docker run --rm --read-only --cap-drop=ALL nigerian-secret-detectors /scan-target --format json --fail-on none
```

The image runs as UID 10001 with a non-login shell. Container vulnerability scanning and image provenance should be performed by the deployment environment.

## License

Apache License 2.0. See `LICENSE` and package metadata for the authoritative declaration.

## Security claims

This project makes no claim of 100% detection, zero false positives, complete provider coverage, or universal production readiness. Provider-specific versus provider-contextual detection is explicitly represented in detector metadata. Benchmark numbers are synthetic and versioned by the repository state.
