# Release security

A release must be traceable to an exact source revision.

Release gates:

1. Supported Python CI passes.
2. Benchmark regression passes.
3. Security scanning and dependency audit pass.
4. Package build and metadata validation pass.
5. `LICENSE` and package metadata agree on Apache-2.0.
6. SBOM generation succeeds.
7. SHA-256 checksums are generated for release artifacts and SBOM.
8. Build-provenance attestation succeeds.

Tagged releases publish the Python distribution, SBOM, and checksum manifest. GitHub Actions are pinned to immutable commit SHAs.

Current package version: `0.5.0`.
