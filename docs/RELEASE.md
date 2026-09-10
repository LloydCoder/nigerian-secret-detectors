# Release security

A release is intended to be reproducible and traceable to an exact source revision.

Release prerequisites:

1. CI passes on supported Python versions.
2. Benchmark regression passes.
3. Security scanning passes.
4. Package build succeeds.
5. Package metadata and `LICENSE` agree on Apache-2.0.
6. SBOM generation succeeds.
7. SHA-256 checksums are generated for release artifacts and the SBOM.
8. Build-provenance attestation succeeds.

The release workflow runs from a version tag and publishes the distribution artifacts, SBOM, and checksum manifest. GitHub Actions are pinned to immutable commit SHAs.

The package currently declares version `0.5.0`. A version bump must accompany any subsequent release that changes public behavior according to the project's chosen semantic-versioning policy.
