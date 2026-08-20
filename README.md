# Nigerian Secret Detectors 🇳🇬

Provider-aware secret detection for Nigerian fintech, payment infrastructure, and crypto projects.

The project combines a native detection engine with external scanner integrations and provides deterministic findings, provider context, confidence scoring, JSON/SARIF output, a validated detector registry, safe verification boundaries, developer/CI integrations, release security, policy controls, and a hardened local scanning API.

## Enterprise build status

- Phase 1 — Native detection engine: **complete**
- Phase 2 — Detector registry and rule metadata: **complete**
- Phase 3 — Provider corpus and fixture benchmark: **complete**
- Phase 4 — Safe verification boundaries: **complete foundation**
- Phase 5 — Developer and CI integrations: **complete**
- Phase 6 — Precision/recall benchmark: **complete**
- Phase 7 — Supply-chain and release hardening: **complete**
- Phase 8 — Policy/API platform layer: **complete foundation**

The benchmark suite is deterministic, contains synthetic positive and negative fixtures, and compares the native engine with Gitleaks and TruffleHog in CI. Benchmark artifacts are retained for review. No live credentials are included.

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

A JSON policy can define the severity gate, file-size limit, file-count limit, and excluded directories:

```json
{"fail_on":"high","max_file_size":2097152,"max_files":10000,"excluded_dirs":[".git","node_modules"]}
```

Policies are data-only and validated before use. The platform does not execute arbitrary configuration code or load policy paths supplied by API clients.

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

Security controls include a 64 KiB request limit, JSON content-type enforcement, method allowlisting, bounded request timeouts, rate limiting, optional API-key authentication for remote binding, path-traversal protection, symlink exclusion, file-size/file-count limits, and redacted findings. Raw secret material is never returned.

## Release and supply-chain security

Tagged releases build Python distributions, generate an SPDX 2.3 SBOM with SHA-256 file hashes, publish artifact checksums, and generate GitHub build-provenance attestations. GitHub Actions dependencies are kept on current supported major releases, dependency updates are automated, and sensitive repository paths are protected by `CODEOWNERS`.

See `SECURITY.md` for security reporting and secret-handling guidance.

## Benchmark methodology

The benchmark corpus contains 19 synthetic positive cases and 13 negative cases covering provider-specific credentials, JWT-shaped tokens, cryptographic keys, provider context, and false-positive controls. Native detection is gated in unit tests; Gitleaks and TruffleHog are executed as independent comparison runs. Results are stored as CI artifacts and are not presented as real-world recall estimates—the corpus is a controlled regression benchmark.

## Roadmap

All eight planned build phases are now implemented. Future work is incremental: expand the provider corpus, add additional safe verification adapters, increase benchmark diversity, and evolve the local platform boundary into a separately authenticated multi-tenant service when an actual hosted control plane is required.
