# Nigerian Secret Detectors 🇳🇬

Provider-aware secret detection for Nigerian fintech, payment infrastructure, and crypto projects.

The project combines a native detection engine with external scanner integrations and provides deterministic findings, provider context, confidence scoring, JSON/SARIF output, a validated detector registry, safe verification boundaries, developer/CI integrations, release security, policy controls, and a local scanning API.

## Build status

- Phase 1 — Native detection engine: **complete**
- Phase 2 — Detector registry: **complete**
- Phase 3 — Provider corpus and benchmark fixtures: **complete**
- Phase 4 — Safe verification boundaries: **complete foundation**
- Phase 5 — Developer and CI integrations: **complete**
- Phase 6 — Precision/recall benchmark: **planned next**
- Phase 7 — Supply-chain and release hardening: **implemented**
- Phase 8 — Policy/API platform layer: **implemented foundation**

No live credentials are included. Benchmark values are synthetic fixtures.

## Quick start

```bash
python -m pip install -e .
nigerian-scan /path/to/project
```

Machine-readable output:

```bash
nigerian-scan . --format json
nigerian-scan . --format sarif
```

CI failure policy:

```bash
nigerian-scan . --fail-on high
nigerian-scan . --fail-on critical
```

## Policy packs

A JSON policy can define the severity gate, file-size limit, and excluded directories:

```json
{"fail_on":"high","max_file_size":2097152,"excluded_dirs":[".git","node_modules"]}
```

The policy model is deliberately data-only so it can be reviewed, versioned, and promoted through CI without executing arbitrary configuration code.

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

The API caps request bodies at 64 KiB, never returns raw secret material, and prevents path traversal outside `NIGERIAN_SCAN_ROOT`. It is a local integration surface, not an internet-facing multi-tenant service.

## Release and supply-chain security

Tagged releases build Python distributions, generate an SPDX 2.3 SBOM with SHA-256 file hashes, publish artifact checksums, and use GitHub artifact provenance attestations. See `SECURITY.md` for the security model and reporting guidance.

## Roadmap

1. Native detection engine — **complete**
2. Detector registry — **complete**
3. Provider corpus and fixture benchmark — **complete**
4. Verification safety — **complete foundation**
5. CI/developer integrations — **complete**
6. Precision/recall benchmark against Gitleaks and TruffleHog — **next**
7. Supply-chain hardening — **implemented**
8. Enterprise policy/API platform — **implemented foundation**
